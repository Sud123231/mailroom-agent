
import re
from typing import Any


ACTIONS = {
    "create_draft",
    "update_internal_record",
    "send_approved_notice",
    "request_confirmation",
    "quarantine_item",
    "no_action",
}

NO_ACTION_REASONS = {
    "ALREADY_COMPLETED",
    "DUPLICATE",
    "INFORMATIONAL",
}

REFERENCE_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:/-]+$")


class ProposalValidationError(ValueError):
    pass


def require_exact_keys(
    value: dict[str, Any],
    expected: set[str],
    field_name: str,
) -> None:
    actual = set(value)

    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)

        raise ProposalValidationError(
            f"{field_name}: missing keys={missing}, extra keys={extra}"
        )


def require_nonempty_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProposalValidationError(
            f"{field_name} must be a non-empty string"
        )

    return value


def validate_reference_id(value: Any, field_name: str) -> str:
    result = require_nonempty_string(value, field_name)

    if not REFERENCE_ID_PATTERN.fullmatch(result):
        raise ProposalValidationError(
            f"{field_name} contains unsupported characters"
        )

    return result


def validate_target(
    target: Any,
    expected_kind: str,
    expected_id: str | None = None,
) -> None:
    if not isinstance(target, dict):
        raise ProposalValidationError("target must be an object")

    require_exact_keys(target, {"kind", "id"}, "target")

    if target["kind"] != expected_kind:
        raise ProposalValidationError("Incorrect target kind")

    target_id = require_nonempty_string(target["id"], "target.id")

    if expected_id is not None and target_id != expected_id:
        raise ProposalValidationError("Incorrect target ID")


def validate_payload(
    payload: Any,
    expected_keys: set[str],
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ProposalValidationError("payload must be an object")

    require_exact_keys(payload, expected_keys, "payload")

    return payload


def validate_string_fields(
    payload: dict[str, Any],
    fields: set[str],
) -> None:
    for field in fields:
        require_nonempty_string(payload[field], f"payload.{field}")


def validate_proposal(
    proposal: dict[str, Any],
    dossier: dict[str, Any],
    allowed_actions: list[str],
) -> dict[str, Any]:
    if not isinstance(proposal, dict):
        raise ProposalValidationError("Proposal must be an object")

    require_exact_keys(
        proposal,
        {
            "dossierId",
            "callId",
            "action",
            "target",
            "payload",
            "evidence",
        },
        "proposal",
    )

    dossier_id = require_nonempty_string(
        dossier.get("dossierId"),
        "dossier.dossierId",
    )

    if proposal["dossierId"] != dossier_id:
        raise ProposalValidationError("Dossier ID mismatch")

    call_id = require_nonempty_string(proposal["callId"], "callId")

    if not 12 <= len(call_id) <= 128:
        raise ProposalValidationError("Invalid callId length")

    if not re.fullmatch(r"[A-Za-z0-9._:-]+", call_id):
        raise ProposalValidationError("Invalid callId characters")

    action = proposal["action"]

    if action not in ACTIONS:
        raise ProposalValidationError("Unknown action")

    if action not in allowed_actions:
        raise ProposalValidationError("Action is not allowed by the request")

    source_lines = {
        line["lineId"]
        for source in dossier.get("sources", [])
        for line in source.get("lines", [])
        if isinstance(line, dict) and isinstance(line.get("lineId"), str)
    }

    evidence = proposal["evidence"]

    if not isinstance(evidence, list) or not evidence:
        raise ProposalValidationError("Evidence must be a non-empty list")

    if any(not isinstance(line_id, str) or not line_id for line_id in evidence):
        raise ProposalValidationError("Evidence contains an invalid line ID")

    if len(evidence) != len(set(evidence)):
        raise ProposalValidationError("Evidence contains duplicate line IDs")

    if not set(evidence).issubset(source_lines):
        raise ProposalValidationError("Evidence references an unknown line ID")

    target = proposal["target"]
    payload = proposal["payload"]

    if action == "create_draft":
        expected_target_id = f"mailbox:{dossier.get('mailbox', '')}"

        validate_target(target, "draft_queue", expected_target_id)

        payload = validate_payload(
            payload,
            {"recipient", "referenceId", "status", "template"},
        )
        validate_string_fields(
            payload,
            {"recipient", "referenceId", "status", "template"},
        )
        validate_reference_id(payload["referenceId"], "payload.referenceId")

        if payload["template"] != "order_status":
            raise ProposalValidationError("Invalid draft template")

    elif action == "update_internal_record":
        validate_target(target, "case_record")

        payload = validate_payload(
            payload,
            {"field", "sourceEventId", "value"},
        )
        validate_string_fields(
            payload,
            {"field", "sourceEventId", "value"},
        )
        validate_reference_id(
            payload["sourceEventId"],
            "payload.sourceEventId",
        )

        if payload["field"] != "delivery_window":
            raise ProposalValidationError("Invalid internal field")

    elif action == "send_approved_notice":
        validate_target(target, "email")

        payload = validate_payload(
            payload,
            {"referenceId", "status", "template"},
        )
        validate_string_fields(
            payload,
            {"referenceId", "status", "template"},
        )
        validate_reference_id(payload["referenceId"], "payload.referenceId")

        if payload["template"] != "approved_delivery_notice":
            raise ProposalValidationError("Invalid notice template")

    elif action == "request_confirmation":
        validate_target(target, "approval_queue")

        payload = validate_payload(
            payload,
            {"claimedSender", "questionCode", "referenceId"},
        )
        validate_string_fields(
            payload,
            {"claimedSender", "questionCode", "referenceId"},
        )
        validate_reference_id(payload["referenceId"], "payload.referenceId")

        if payload["questionCode"] != "VERIFY_REQUEST":
            raise ProposalValidationError("Invalid confirmation question code")

    elif action == "quarantine_item":
        validate_target(target, "security_queue", "mailroom")

        payload = validate_payload(
            payload,
            {"artifactId", "reasonCode"},
        )
        validate_string_fields(
            payload,
            {"artifactId", "reasonCode"},
        )
        validate_reference_id(payload["artifactId"], "payload.artifactId")

        if payload["reasonCode"] != "INDIRECT_PROMPT_INJECTION":
            raise ProposalValidationError("Invalid quarantine reason code")

    elif action == "no_action":
        if target is not None:
            raise ProposalValidationError("no_action target must be null")

        payload = validate_payload(
            payload,
            {"reasonCode", "referenceId"},
        )
        validate_string_fields(
            payload,
            {"reasonCode", "referenceId"},
        )
        validate_reference_id(payload["referenceId"], "payload.referenceId")

        if payload["reasonCode"] not in NO_ACTION_REASONS:
            raise ProposalValidationError("Invalid no_action reason code")

    return proposal
