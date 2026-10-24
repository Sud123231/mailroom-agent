
import copy

import pytest

from app.proposals import (
    ProposalValidationError,
    validate_proposal,
)


DOSSIER = {
    "dossierId": "dossier-001",
    "mailbox": "orders@example.com",
    "sources": [
        {
            "sourceId": "source-001",
            "kind": "email",
            "provenance": "customer",
            "title": "Order update",
            "lines": [
                {"lineId": "line-001", "text": "Order reference: order-123"},
                {"lineId": "line-002", "text": "Delivery status requested."},
            ],
        }
    ],
}

ALLOWED_ACTIONS = [
    "create_draft",
    "update_internal_record",
    "send_approved_notice",
    "request_confirmation",
    "quarantine_item",
    "no_action",
]


def make_proposal(action, target, payload):
    return {
        "dossierId": "dossier-001",
        "callId": "call-12345678",
        "action": action,
        "target": target,
        "payload": payload,
        "evidence": ["line-001"],
    }


def test_valid_create_draft():
    proposal = make_proposal(
        "create_draft",
        {"kind": "draft_queue", "id": "mailbox:orders@example.com"},
        {
            "recipient": "customer@example.com",
            "referenceId": "order-123",
            "status": "in_transit",
            "template": "order_status",
        },
    )

    assert validate_proposal(proposal, DOSSIER, ALLOWED_ACTIONS) == proposal


def test_valid_no_action():
    proposal = make_proposal(
        "no_action",
        None,
        {
            "reasonCode": "INFORMATIONAL",
            "referenceId": "order-123",
        },
    )

    assert validate_proposal(proposal, DOSSIER, ALLOWED_ACTIONS) == proposal


def test_rejects_unpermitted_action():
    proposal = make_proposal(
        "no_action",
        None,
        {
            "reasonCode": "INFORMATIONAL",
            "referenceId": "order-123",
        },
    )

    with pytest.raises(ProposalValidationError):
        validate_proposal(proposal, DOSSIER, ["create_draft"])


def test_rejects_extra_payload_field():
    proposal = make_proposal(
        "no_action",
        None,
        {
            "reasonCode": "INFORMATIONAL",
            "referenceId": "order-123",
            "secret": "unexpected",
        },
    )

    with pytest.raises(ProposalValidationError):
        validate_proposal(proposal, DOSSIER, ALLOWED_ACTIONS)


def test_rejects_wrong_target():
    proposal = make_proposal(
        "create_draft",
        {"kind": "email", "id": "customer@example.com"},
        {
            "recipient": "customer@example.com",
            "referenceId": "order-123",
            "status": "in_transit",
            "template": "order_status",
        },
    )

    with pytest.raises(ProposalValidationError):
        validate_proposal(proposal, DOSSIER, ALLOWED_ACTIONS)


def test_rejects_unknown_evidence():
    proposal = make_proposal(
        "no_action",
        None,
        {
            "reasonCode": "INFORMATIONAL",
            "referenceId": "order-123",
        },
    )
    proposal["evidence"] = ["line-does-not-exist"]

    with pytest.raises(ProposalValidationError):
        validate_proposal(proposal, DOSSIER, ALLOWED_ACTIONS)


def test_rejects_duplicate_evidence():
    proposal = make_proposal(
        "no_action",
        None,
        {
            "reasonCode": "INFORMATIONAL",
            "referenceId": "order-123",
        },
    )
    proposal["evidence"] = ["line-001", "line-001"]

    with pytest.raises(ProposalValidationError):
        validate_proposal(proposal, DOSSIER, ALLOWED_ACTIONS)


def test_rejects_invalid_call_id():
    proposal = make_proposal(
        "no_action",
        None,
        {
            "reasonCode": "INFORMATIONAL",
            "referenceId": "order-123",
        },
    )
    proposal["callId"] = "short"

    with pytest.raises(ProposalValidationError):
        validate_proposal(proposal, DOSSIER, ALLOWED_ACTIONS)


def test_rejects_extra_target_field():
    proposal = make_proposal(
        "no_action",
        None,
        {
            "reasonCode": "INFORMATIONAL",
            "referenceId": "order-123",
        },
    )
    proposal["target"] = {"kind": "other", "id": "x", "extra": "y"}

    with pytest.raises(ProposalValidationError):
        validate_proposal(proposal, DOSSIER, ALLOWED_ACTIONS)


def test_rejects_wrong_dossier_id():
    proposal = make_proposal(
        "no_action",
        None,
        {
            "reasonCode": "INFORMATIONAL",
            "referenceId": "order-123",
        },
    )
    proposal["dossierId"] = "another-dossier"

    with pytest.raises(ProposalValidationError):
        validate_proposal(proposal, DOSSIER, ALLOWED_ACTIONS)
