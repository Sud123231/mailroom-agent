
import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from app.canonical import canonical_json
from app.schemas import PROFILE
from app.security import (
    import_ed25519_public_key,
    receipt_signed_message,
    verify_receipt_signature,
)


EVALUATION_ID = "evaluation-test-001"
INPUT_DIGEST = "a" * 64


@pytest.fixture
def key_pair():
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

    return private_key, public_key_jwk


def make_receipt(private_key):
    receipt = {
        "dossierId": "dossier-001",
        "callId": "call-12345678",
        "action": "no_action",
        "accepted": True,
        "proposalDigest": "b" * 64,
        "receiptId": "receipt-001",
    }

    signed_message = canonical_json(
        {
            "profile": PROFILE,
            "evaluationId": EVALUATION_ID,
            "inputDigest": INPUT_DIGEST,
            "receipt": receipt,
        }
    )

    receipt["receiptSignature"] = base64.b64encode(
        private_key.sign(signed_message)
    ).decode("ascii")

    return receipt


def test_import_public_key(key_pair):
    _, public_key_jwk = key_pair

    public_key = import_ed25519_public_key(public_key_jwk)

    assert public_key is not None


def test_valid_signature_is_accepted(key_pair):
    private_key, public_key_jwk = key_pair
    receipt = make_receipt(private_key)

    assert verify_receipt_signature(
        receipt,
        EVALUATION_ID,
        INPUT_DIGEST,
        public_key_jwk,
    )


def test_modified_receipt_is_rejected(key_pair):
    private_key, public_key_jwk = key_pair
    receipt = make_receipt(private_key)
    receipt["accepted"] = False

    assert not verify_receipt_signature(
        receipt,
        EVALUATION_ID,
        INPUT_DIGEST,
        public_key_jwk,
    )


def test_wrong_evaluation_is_rejected(key_pair):
    private_key, public_key_jwk = key_pair
    receipt = make_receipt(private_key)

    assert not verify_receipt_signature(
        receipt,
        "different-evaluation",
        INPUT_DIGEST,
        public_key_jwk,
    )


def test_wrong_input_digest_is_rejected(key_pair):
    private_key, public_key_jwk = key_pair
    receipt = make_receipt(private_key)

    assert not verify_receipt_signature(
        receipt,
        EVALUATION_ID,
        "c" * 64,
        public_key_jwk,
    )


def test_missing_signature_is_rejected(key_pair):
    _, public_key_jwk = key_pair
    receipt = {
        "dossierId": "dossier-001",
        "callId": "call-12345678",
        "action": "no_action",
        "accepted": True,
        "proposalDigest": "b" * 64,
        "receiptId": "receipt-001",
    }

    assert not verify_receipt_signature(
        receipt,
        EVALUATION_ID,
        INPUT_DIGEST,
        public_key_jwk,
    )


def test_malformed_signature_is_rejected(key_pair):
    _, public_key_jwk = key_pair
    receipt = {
        "dossierId": "dossier-001",
        "callId": "call-12345678",
        "action": "no_action",
        "accepted": True,
        "proposalDigest": "b" * 64,
        "receiptId": "receipt-001",
        "receiptSignature": "not-valid-base64!",
    }

    assert not verify_receipt_signature(
        receipt,
        EVALUATION_ID,
        INPUT_DIGEST,
        public_key_jwk,
    )


def test_wrong_public_key_is_rejected(key_pair):
    private_key, _ = key_pair
    receipt = make_receipt(private_key)

    other_private_key = Ed25519PrivateKey.generate()
    other_public_key_bytes = other_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    other_public_key_jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64.urlsafe_b64encode(other_public_key_bytes)
        .decode("ascii")
        .rstrip("="),
    }

    assert not verify_receipt_signature(
        receipt,
        EVALUATION_ID,
        INPUT_DIGEST,
        other_public_key_jwk,
    )
