from concurrent.futures import ThreadPoolExecutor
from threading import Event, Lock
import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

import app.service as service
from app.canonical import canonical_json
from app.database import create_database, session_scope as database_session_scope
from app.schemas import PROFILE
from app.security import receipt_signed_message
from app.service import (
    RequestValidationError,
    ServiceConflictError,
    process_commit,
    process_propose,
)


class FakeAgent:
    def __init__(self):
        self.calls = 0

    def validated_proposal(self, dossier, allowed_actions, call_id):
        self.calls += 1

        return {
            "dossierId": dossier["dossierId"],
            "callId": call_id,
            "action": "no_action",
            "target": None,
            "payload": {
                "reasonCode": "INFORMATIONAL",
                "referenceId": "order-123",
            },
            "evidence": ["line-001"],
        }


@pytest.fixture
def setup_service(tmp_path, monkeypatch):
    database_path = tmp_path / "lifecycle.db"
    engine, factory = create_database(f"sqlite:///{database_path}")

    from contextlib import contextmanager

    @contextmanager
    def temporary_session_scope():
        with database_session_scope(factory) as session:
            yield session

    monkeypatch.setattr(
        service,
        "session_scope",
        temporary_session_scope,
    )

    private_key = Ed25519PrivateKey.generate()
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    public_key_jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64.urlsafe_b64encode(public_key_bytes)
        .decode("ascii")
        .rstrip("="),
    }

    request = {
        "profile": PROFILE,
        "operation": "propose",
        "evaluationId": "evaluation-lifecycle-001",
        "receiptVerifier": {
            "algorithm": "Ed25519",
            "publicKeyJwk": public_key_jwk,
        },
        "corpus": {
            "coreId": "core-test",
            "auditId": "audit-test",
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
        "dossiers": [
            {
                "dossierId": "dossier-lifecycle-001",
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
        ],
    }

    agent = FakeAgent()

    yield {
        "engine": engine,
        "factory": factory,
        "private_key": private_key,
        "public_key_jwk": public_key_jwk,
        "request": request,
        "agent": agent,
    }

    engine.dispose()


def make_signed_commit(setup, proposal, accepted=True):
    input_digest = service.compute_input_digest(setup["request"])

    receipt = {
        "dossierId": proposal["dossierId"],
        "callId": proposal["callId"],
        "action": proposal["action"],
        "accepted": accepted,
        "proposalDigest": service.proposal_digest(proposal),
        "receiptId": "receipt-lifecycle-001",
    }

    message = receipt_signed_message(
        evaluation_id=setup["request"]["evaluationId"],
        input_digest=input_digest,
        receipt=receipt,
    )

    receipt["receiptSignature"] = base64.b64encode(
        setup["private_key"].sign(message)
    ).decode("ascii")

    return {
        "profile": PROFILE,
        "operation": "commit",
        "evaluationId": setup["request"]["evaluationId"],
        "inputDigest": input_digest,
        "receipts": [receipt],
    }


def test_successful_propose_and_commit(setup_service):
    setup = setup_service

    proposed = process_propose(setup["request"], setup["agent"])

    assert proposed["status"] == "awaiting_receipts"
    assert len(proposed["proposals"]) == 1

    commit_request = make_signed_commit(
        setup,
        proposed["proposals"][0],
        accepted=True,
    )

    result = process_commit(commit_request)

    assert result["status"] == "completed"
    assert result["outcomes"][0]["status"] == "executed"


def test_rejected_receipt_produces_rejected_outcome(setup_service):
    setup = setup_service
    proposed = process_propose(setup["request"], setup["agent"])

    commit_request = make_signed_commit(
        setup,
        proposed["proposals"][0],
        accepted=False,
    )

    result = process_commit(commit_request)

    assert result["outcomes"][0]["status"] == "rejected"


def test_invalid_signature_is_rejected_atomically(setup_service):
    setup = setup_service
    proposed = process_propose(setup["request"], setup["agent"])

    commit_request = make_signed_commit(
        setup,
        proposed["proposals"][0],
    )
    commit_request["receipts"][0]["receiptSignature"] = base64.b64encode(
        b"x" * 64
    ).decode("ascii")

    with pytest.raises(RequestValidationError):
        process_commit(commit_request)

    with database_session_scope(setup["factory"]) as session:
        from app.database import Evaluation, StoredReceipt

        evaluation = session.get(
            Evaluation,
            setup["request"]["evaluationId"],
        )

        receipts = session.query(StoredReceipt).all()

        assert evaluation.status == "awaiting_receipts"
        assert evaluation.commit_response_json is None
        assert receipts == []


def test_wrong_proposal_digest_is_rejected(setup_service):
    setup = setup_service
    proposed = process_propose(setup["request"], setup["agent"])

    commit_request = make_signed_commit(
        setup,
        proposed["proposals"][0],
    )

    commit_request["receipts"][0]["proposalDigest"] = "f" * 64

    with pytest.raises(ServiceConflictError):
        process_commit(commit_request)


def test_exact_propose_replay_does_not_call_agent_again(setup_service):
    setup = setup_service

    first = process_propose(setup["request"], setup["agent"])
    second = process_propose(setup["request"], setup["agent"])

    assert first == second
    assert setup["agent"].calls == 1


def test_exact_commit_replay_returns_stored_result(setup_service):
    setup = setup_service
    proposed = process_propose(setup["request"], setup["agent"])

    commit_request = make_signed_commit(
        setup,
        proposed["proposals"][0],
    )

    first = process_commit(commit_request)
    second = process_commit(commit_request)

    assert first == second


def test_changed_request_with_same_evaluation_id_conflicts(setup_service):
    setup = setup_service
    process_propose(setup["request"], setup["agent"])

    changed_request = json.loads(json.dumps(setup["request"]))
    changed_request["dossiers"][0]["objective"] = "Different objective"

    with pytest.raises(ServiceConflictError):
        process_propose(changed_request, setup["agent"])



from app.canonical import canonical_digest


def test_input_digest_hashes_only_dossiers(setup_service):
    request = setup_service["request"]

    assert service.compute_input_digest(request) == canonical_digest(
        request["dossiers"]
    )

    changed_envelope = json.loads(json.dumps(request))
    changed_envelope["evaluationId"] = "another-evaluation"

    assert (
        service.compute_input_digest(changed_envelope)
        == service.compute_input_digest(request)
    )

    changed_dossier = json.loads(json.dumps(request))
    changed_dossier["dossiers"][0]["objective"] = "Changed objective"

    assert (
        service.compute_input_digest(changed_dossier)
        != service.compute_input_digest(request)
    )


def test_stable_dossier_reuses_complete_proposal_across_evaluations(
    setup_service,
):
    setup = setup_service

    first_response = process_propose(
        setup["request"],
        setup["agent"],
    )

    second_request = json.loads(json.dumps(setup["request"]))
    second_request["evaluationId"] = "evaluation-lifecycle-002"
    second_request["corpus"]["auditId"] = "audit-test-002"

    second_response = process_propose(
        second_request,
        setup["agent"],
    )

    first_proposal = first_response["proposals"][0]
    second_proposal = second_response["proposals"][0]

    assert first_proposal == second_proposal
    assert setup["agent"].calls == 1
    assert first_response["inputDigest"] == second_response["inputDigest"]


def test_incompatible_cached_decision_is_not_replaced(setup_service):
    setup = setup_service

    first_response = process_propose(
        setup["request"],
        setup["agent"],
    )
    original_proposal = first_response["proposals"][0]

    changed_request = json.loads(json.dumps(setup["request"]))
    changed_request["evaluationId"] = "evaluation-lifecycle-003"
    changed_request["allowedActions"].remove("no_action")

    with pytest.raises(RequestValidationError):
        process_propose(changed_request, setup["agent"])

    assert setup["agent"].calls == 1

    from app.database import get_cached_decision

    fingerprint = service.dossier_fingerprint(
        setup["request"]["dossiers"][0]
    )

    with database_session_scope(setup["factory"]) as session:
        cached = get_cached_decision(session, fingerprint)
        assert json.loads(cached.proposal_json) == original_proposal


def test_concurrent_identical_proposals_do_not_call_agent_twice(
    setup_service,
):
    setup = setup_service
    agent_started = Event()
    release_agent = Event()
    calls_lock = Lock()

    class BlockingAgent(FakeAgent):
        def validated_proposal(self, dossier, allowed_actions, call_id):
            with calls_lock:
                self.calls += 1
                call_number = self.calls

            agent_started.set()

            if call_number == 1:
                release_agent.wait(timeout=5)
            else:
                release_agent.set()

            return {
                "dossierId": dossier["dossierId"],
                "callId": call_id,
                "action": "no_action",
                "target": None,
                "payload": {
                    "reasonCode": "INFORMATIONAL",
                    "referenceId": "order-123",
                },
                "evidence": ["line-001"],
            }

    agent = BlockingAgent()

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            first_future = executor.submit(
                process_propose,
                setup["request"],
                agent,
            )

            assert agent_started.wait(timeout=3)

            second_future = executor.submit(
                process_propose,
                setup["request"],
                agent,
            )

            try:
                with pytest.raises(ServiceConflictError):
                    second_future.result(timeout=3)
            finally:
                release_agent.set()

            first_response = first_future.result(timeout=5)

        assert first_response["status"] == "awaiting_receipts"
        assert agent.calls == 1

    finally:
        release_agent.set()

from datetime import datetime, timedelta, timezone

from app.database import Evaluation


def test_stale_processing_evaluation_can_be_recovered(setup_service):
    setup = setup_service
    request = setup["request"]
    fingerprint = service.canonical_digest(request)

    with database_session_scope(setup["factory"]) as session:
        session.add(
            Evaluation(
                evaluation_id=request["evaluationId"],
                request_fingerprint=fingerprint,
                input_digest=service.compute_input_digest(request),
                verifier_jwk_json=json.dumps(setup["public_key_jwk"]),
                propose_response_json=None,
                status="processing",
                created_at=datetime.now(timezone.utc) - timedelta(minutes=5),
            )
        )

    response = process_propose(request, setup["agent"])

    assert response["status"] == "awaiting_receipts"
    assert setup["agent"].calls == 1        