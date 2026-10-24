
import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> bytes:
    serialized = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return serialized.encode("utf-8")


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_digest(value: Any) -> str:
    return sha256_hex(canonical_json(value))


def proposal_digest(proposal: dict[str, Any]) -> str:
    required_fields = (
        "dossierId",
        "callId",
        "action",
        "target",
        "payload",
        "evidence",
    )

    normalized = {
        field: proposal[field]
        for field in required_fields
    }

    normalized["evidence"] = sorted(normalized["evidence"])

    return canonical_digest(normalized)


def dossier_fingerprint(dossier: dict[str, Any]) -> str:
    return canonical_digest(dossier)


def deterministic_call_id(dossier: dict[str, Any]) -> str:
    fingerprint = dossier_fingerprint(dossier)
    return f"call-{fingerprint}"
