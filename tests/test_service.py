
import copy

import pytest

from app.service import (
    RequestValidationError,
    validate_propose_request,
)


def make_request():
    return {
        "profile": "ga5-mailroom-action-gate/v2",
        "operation": "propose",
        "evaluationId": "evaluation-001",
        "receiptVerifier": {
            "algorithm": "Ed25519",
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            },
        },
        "corpus": {
            "coreId": "core-001",
            "auditId": "audit-001",
            "stableCount": 1,
            "freshCount": 1,
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
                "dossierId": "dossier-001",
                "partition": "stable_core",
            },
            {
                "dossierId": "dossier-002",
                "partition": "fresh_audit",
            },
        ],
    }


def test_valid_request_passes():
    validate_propose_request(make_request())


def test_duplicate_dossier_ids_are_rejected():
    request = make_request()
    request["dossiers"][1]["dossierId"] = "dossier-001"

    with pytest.raises(RequestValidationError):
        validate_propose_request(request)


def test_incorrect_partition_count_is_rejected():
    request = make_request()
    request["corpus"]["stableCount"] = 2

    with pytest.raises(RequestValidationError):
        validate_propose_request(request)


def test_unknown_action_is_rejected():
    request = make_request()
    request["allowedActions"].append("delete_everything")

    with pytest.raises(RequestValidationError):
        validate_propose_request(request)


def test_duplicate_allowed_actions_are_rejected():
    request = make_request()
    request["allowedActions"].append("no_action")

    with pytest.raises(RequestValidationError):
        validate_propose_request(request)


def test_invalid_partition_is_rejected():
    request = make_request()
    request["dossiers"][0]["partition"] = "unknown"

    with pytest.raises(RequestValidationError):
        validate_propose_request(request)
