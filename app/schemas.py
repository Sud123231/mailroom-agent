
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr


PROFILE = "ga5-mailroom-action-gate/v2"

Action = Literal[
    "create_draft",
    "update_internal_record",
    "send_approved_notice",
    "request_confirmation",
    "quarantine_item",
    "no_action",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class PublicKeyJWK(StrictModel):
    kty: Literal["OKP"]
    crv: Literal["Ed25519"]
    x: StrictStr


class ReceiptVerifier(StrictModel):
    algorithm: Literal["Ed25519"]
    publicKeyJwk: PublicKeyJWK


class Corpus(StrictModel):
    coreId: StrictStr
    auditId: StrictStr
    stableCount: int = Field(ge=0)
    freshCount: int = Field(ge=0)


class SourceLine(StrictModel):
    lineId: StrictStr
    text: StrictStr


class DossierSource(StrictModel):
    sourceId: StrictStr
    kind: StrictStr
    provenance: StrictStr
    title: StrictStr
    lines: list[SourceLine]


class Dossier(StrictModel):
    dossierId: StrictStr
    partition: Literal["stable_core", "fresh_audit"]
    receivedAt: datetime
    mailbox: StrictStr
    objective: StrictStr
    sources: list[DossierSource]


class ProposeRequest(StrictModel):
    profile: Literal["ga5-mailroom-action-gate/v2"]
    operation: Literal["propose"]
    evaluationId: StrictStr
    receiptVerifier: ReceiptVerifier
    corpus: Corpus
    allowedActions: list[Action]
    dossiers: list[Dossier]


class Target(StrictModel):
    kind: StrictStr
    id: StrictStr


class Proposal(StrictModel):
    dossierId: StrictStr
    callId: Annotated[
        str,
        Field(
            strict=True,
            min_length=12,
            max_length=128,
            pattern=r"^[A-Za-z0-9._:-]+$",
        ),
    ]
    action: Action
    target: Target | None
    payload: dict[str, Any]
    evidence: list[StrictStr]


class ProposeResponse(StrictModel):
    profile: Literal["ga5-mailroom-action-gate/v2"]
    evaluationId: StrictStr
    status: Literal["awaiting_receipts"]
    inputDigest: Annotated[
        str,
        Field(strict=True, pattern=r"^[0-9a-f]{64}$"),
    ]
    proposals: list[Proposal]


class Receipt(StrictModel):
    dossierId: StrictStr
    callId: Annotated[
        str,
        Field(
            strict=True,
            min_length=12,
            max_length=128,
            pattern=r"^[A-Za-z0-9._:-]+$",
        ),
    ]
    action: Action
    accepted: StrictBool
    proposalDigest: Annotated[
        str,
        Field(strict=True, pattern=r"^[0-9a-f]{64}$"),
    ]
    receiptId: StrictStr
    receiptSignature: StrictStr


class CommitRequest(StrictModel):
    profile: Literal["ga5-mailroom-action-gate/v2"]
    operation: Literal["commit"]
    evaluationId: StrictStr
    inputDigest: Annotated[
        str,
        Field(strict=True, pattern=r"^[0-9a-f]{64}$"),
    ]
    receipts: list[Receipt]


class Outcome(StrictModel):
    dossierId: StrictStr
    callId: StrictStr
    action: Action
    proposalDigest: Annotated[
        str,
        Field(strict=True, pattern=r"^[0-9a-f]{64}$"),
    ]
    receiptId: StrictStr
    status: Literal["executed", "rejected"]


class CommitResponse(StrictModel):
    profile: Literal["ga5-mailroom-action-gate/v2"]
    evaluationId: StrictStr
    status: Literal["completed"]
    inputDigest: Annotated[
        str,
        Field(strict=True, pattern=r"^[0-9a-f]{64}$"),
    ]
    outcomes: list[Outcome]
