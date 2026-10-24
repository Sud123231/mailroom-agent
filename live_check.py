
import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

BASE_URL = "http://127.0.0.1:8000"
PROFILE = "ga5-mailroom-action-gate/v2"


def canonical_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical_json(value)).hexdigest()


def check(condition, message):
    if not condition:
        raise AssertionError(message)
    print(f"PASS: {message}")


def main():
    health = requests.get(f"{BASE_URL}/health", timeout=10)
    check(health.status_code == 200, "health endpoint returns HTTP 200")
    check(health.json().get("status") == "ok", "health response is ok")

    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    public_jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64.urlsafe_b64encode(public_bytes)
        .decode("ascii")
        .rstrip("="),
    }

    evaluation_id = f"live-check-{secrets.token_hex(8)}"
    dossier = {
        "dossierId": f"dossier-{secrets.token_hex(6)}",
        "partition": "stable_core",
        "receivedAt": "2026-10-24T10:00:00Z",
        "mailbox": "orders@example.com",
        "objective": "Read the informational update",
        "sources": [
            {
                "sourceId": "source-001",
                "kind": "email",
                "provenance": "customer",
                "title": "Order update",
                "lines": [
                    {
                        "lineId": "line-001",
                        "text": "Order reference: order-123",
                    }
                ],
            }
        ],
    }

    propose_request = {
        "profile": PROFILE,
        "operation": "propose",
        "evaluationId": evaluation_id,
        "receiptVerifier": {
            "algorithm": "Ed25519",
            "publicKeyJwk": public_jwk,
        },
        "corpus": {
            "coreId": "core-live-check",
            "auditId": "audit-live-check",
            "stableCount": 1,
            "freshCount": 0,
        },
        "allowedActions": [
            "create_draft",
            "update_internal_record",
            "send_approved_notice",
            "request_confirmation",
            "quarantine_item",
            "no_action",
        ],
        "dossiers": [dossier],
    }

    print("\nSending valid propose request...")
    propose_response = requests.post(
        f"{BASE_URL}/",
        json=propose_request,
        timeout=120,
    )
    print("Propose HTTP status:", propose_response.status_code)
    if propose_response.status_code != 200:
        print(propose_response.text)
        raise AssertionError("Propose request failed")

    proposed = propose_response.json()
    print(json.dumps(proposed, indent=2))

    check(proposed.get("profile") == PROFILE, "propose profile is correct")
    check(proposed.get("evaluationId") == evaluation_id, "evaluation ID matches")
    check(proposed.get("status") == "awaiting_receipts", "propose awaits receipts")
    check(len(proposed.get("proposals", [])) == 1, "one proposal returned")

    item = proposed["proposals"][0]
    proposal = item.get("proposal", item)
    proposal_digest = item.get("proposalDigest", digest({
        key: proposal[key]
        for key in (
            "dossierId",
            "callId",
            "action",
            "target",
            "payload",
            "evidence",
        )
    }))

    normalized_proposal = {
        key: proposal[key]
        for key in (
            "dossierId",
            "callId",
            "action",
            "target",
            "payload",
            "evidence",
        )
    }
    normalized_proposal["evidence"] = sorted(normalized_proposal["evidence"])
    expected_proposal_digest = digest(normalized_proposal)

    check(
        proposal_digest == expected_proposal_digest,
        "proposal digest matches canonical proposal",
    )
    check(
        proposal["dossierId"] == dossier["dossierId"],
        "proposal refers to submitted dossier",
    )
    check(
        set(proposal["evidence"]).issubset(
            {line["lineId"] for source in dossier["sources"] for line in source["lines"]}
        ),
        "proposal evidence refers to existing lines",
    )

    input_digest = digest(propose_request["dossiers"])
    receipt = {
        "dossierId": proposal["dossierId"],
        "callId": proposal["callId"],
        "action": proposal["action"],
        "accepted": True,
        "proposalDigest": expected_proposal_digest,
        "receiptId": f"receipt-{secrets.token_hex(8)}",
    }

    signed_message = {
        "profile": PROFILE,
        "evaluationId": evaluation_id,
        "inputDigest": input_digest,
        "receipt": receipt,
    }
    signature = private_key.sign(canonical_json(signed_message))
    receipt["receiptSignature"] = base64.b64encode(signature).decode("ascii")

    commit_request = {
        "profile": PROFILE,
        "operation": "commit",
        "evaluationId": evaluation_id,
        "inputDigest": input_digest,
        "receipts": [receipt],
    }

    print("\nSending valid signed commit request...")
    commit_response = requests.post(
        f"{BASE_URL}/",
        json=commit_request,
        timeout=30,
    )
    print("Commit HTTP status:", commit_response.status_code)
    if commit_response.status_code != 200:
        print(commit_response.text)
        raise AssertionError("Commit request failed")

    committed = commit_response.json()
    print(json.dumps(committed, indent=2))
    check(committed.get("status") == "completed", "commit completed")
    check(len(committed.get("outcomes", [])) == 1, "one outcome returned")
    check(
        committed["outcomes"][0].get("status") == "executed",
        "accepted signed receipt produces executed outcome",
    )

    print("\nChecking exact propose replay...")
    replay_propose = requests.post(
        f"{BASE_URL}/",
        json=propose_request,
        timeout=30,
    )
    check(replay_propose.status_code == 200, "propose replay returns HTTP 200")
    check(replay_propose.json() == proposed, "propose replay returns same JSON")

    print("\nChecking exact commit replay...")
    replay_commit = requests.post(
        f"{BASE_URL}/",
        json=commit_request,
        timeout=30,
    )
    check(replay_commit.status_code == 200, "commit replay returns HTTP 200")
    check(replay_commit.json() == committed, "commit replay returns same JSON")

    print("\nChecking evaluation ID conflict...")
    changed_request = json.loads(json.dumps(propose_request))
    changed_request["dossiers"][0]["objective"] = "Changed objective"
    conflict_response = requests.post(
        f"{BASE_URL}/",
        json=changed_request,
        timeout=30,
    )
    check(conflict_response.status_code == 409, "changed evaluation returns HTTP 409")

    print("\nALL LIVE CHECKS PASSED")


if __name__ == "__main__":
    main()
