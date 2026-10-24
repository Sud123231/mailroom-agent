
import base64
import binascii
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)

from app.canonical import canonical_json
from app.schemas import PROFILE


class ReceiptVerificationError(Exception):
    pass


def decode_base64url(value: str) -> bytes:
    if not value or not all(
        character.isalnum() or character in "-_"
        for character in value
    ):
        raise ReceiptVerificationError("Invalid base64url encoding")

    padded = value + "=" * (-len(value) % 4)

    try:
        return base64.b64decode(
            padded.encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, UnicodeEncodeError, binascii.Error) as exc:
        raise ReceiptVerificationError(
            "Invalid base64url encoding"
        ) from exc


def decode_base64(value: str) -> bytes:
    if not value:
        raise ReceiptVerificationError("Missing receipt signature")

    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, UnicodeEncodeError, binascii.Error) as exc:
        raise ReceiptVerificationError(
            "Invalid base64 signature encoding"
        ) from exc


def import_ed25519_public_key(public_key_jwk: dict[str, Any]) -> Ed25519PublicKey:
    if public_key_jwk.get("kty") != "OKP":
        raise ReceiptVerificationError("Unsupported key type")

    if public_key_jwk.get("crv") != "Ed25519":
        raise ReceiptVerificationError("Unsupported key curve")

    encoded_key = public_key_jwk.get("x")

    if not isinstance(encoded_key, str):
        raise ReceiptVerificationError("Missing public key")

    raw_key = decode_base64url(encoded_key)

    if len(raw_key) != 32:
        raise ReceiptVerificationError("Invalid Ed25519 public key length")

    try:
        return Ed25519PublicKey.from_public_bytes(raw_key)
    except ValueError as exc:
        raise ReceiptVerificationError("Invalid public key") from exc


def receipt_signed_message(
    evaluation_id: str,
    input_digest: str,
    receipt: dict[str, Any],
) -> bytes:
    receipt_fields = {
        key: value
        for key, value in receipt.items()
        if key != "receiptSignature"
    }

    message = {
        "profile": PROFILE,
        "evaluationId": evaluation_id,
        "inputDigest": input_digest,
        "receipt": receipt_fields,
    }

    return canonical_json(message)


def verify_receipt_signature(
    receipt: dict[str, Any],
    evaluation_id: str,
    input_digest: str,
    public_key_jwk: dict[str, Any],
) -> bool:
    try:
        public_key = import_ed25519_public_key(public_key_jwk)

        signature = decode_base64(
            receipt.get("receiptSignature", "")
        )

        if len(signature) != 64:
            return False

        message = receipt_signed_message(
            evaluation_id=evaluation_id,
            input_digest=input_digest,
            receipt=receipt,
        )

        public_key.verify(signature, message)
        return True

    except (ReceiptVerificationError, InvalidSignature, TypeError, ValueError):
        return False
