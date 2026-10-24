
from app.canonical import (
    canonical_digest,
    canonical_json,
    dossier_fingerprint,
    proposal_digest,
)


def test_json_keys_are_sorted_recursively():
    first = {"z": 1, "a": {"y": 2, "b": 3}}
    second = {"a": {"b": 3, "y": 2}, "z": 1}

    assert canonical_json(first) == canonical_json(second)
    assert canonical_digest(first) == canonical_digest(second)


def test_compact_json_uses_utf8():
    value = {"message": "café", "number": 1}

    assert canonical_json(value) == '{"message":"café","number":1}'.encode("utf-8")


def test_proposal_digest_sorts_evidence():
    first = {
        "dossierId": "dossier-1",
        "callId": "call-12345678",
        "action": "no_action",
        "target": None,
        "payload": {
            "reasonCode": "INFORMATIONAL",
            "referenceId": "ref-1",
        },
        "evidence": ["line-2", "line-1"],
        "extraField": "ignored",
    }

    second = {
        "dossierId": "dossier-1",
        "callId": "call-12345678",
        "action": "no_action",
        "target": None,
        "payload": {
            "referenceId": "ref-1",
            "reasonCode": "INFORMATIONAL",
        },
        "evidence": ["line-1", "line-2"],
    }

    assert proposal_digest(first) == proposal_digest(second)


def test_proposal_digest_changes_when_payload_changes():
    first = {
        "dossierId": "dossier-1",
        "callId": "call-12345678",
        "action": "no_action",
        "target": None,
        "payload": {"reasonCode": "INFORMATIONAL", "referenceId": "ref-1"},
        "evidence": ["line-1"],
    }

    second = {
        **first,
        "payload": {"reasonCode": "DUPLICATE", "referenceId": "ref-1"},
    }

    assert proposal_digest(first) != proposal_digest(second)


def test_dossier_fingerprint_is_content_based():
    first = {"dossierId": "d-1", "objective": "Read mail"}
    second = {"objective": "Read mail", "dossierId": "d-1"}

    assert dossier_fingerprint(first) == dossier_fingerprint(second)



from app.canonical import deterministic_call_id


def test_call_id_is_deterministic():
    dossier = {
        "dossierId": "dossier-001",
        "objective": "Check delivery status",
    }

    assert deterministic_call_id(dossier) == deterministic_call_id(dossier)


def test_call_id_is_valid():
    dossier = {
        "dossierId": "dossier-001",
        "objective": "Check delivery status",
    }

    call_id = deterministic_call_id(dossier)

    assert 12 <= len(call_id) <= 128
    assert all(
        character.isascii()
        and (character.isalnum() or character in "._:-")
        for character in call_id
    )


def test_changed_dossier_produces_different_call_id():
    first = {
        "dossierId": "dossier-001",
        "objective": "Check delivery status",
    }
    second = {
        "dossierId": "dossier-001",
        "objective": "Cancel the order",
    }

    assert deterministic_call_id(first) != deterministic_call_id(second)
