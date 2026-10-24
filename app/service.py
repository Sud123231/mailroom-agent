from sqlalchemy.exc import IntegrityError
import json
from typing import Any
from datetime import datetime, timedelta, timezone
from app.agent import AgentError, MailroomAgent
from app.canonical import (
    canonical_digest,
    canonical_json,
    deterministic_call_id,
    dossier_fingerprint,
    proposal_digest,
)
from app.database import (
    CachedDecision,
    Evaluation,
    EvaluationProposal,
    SessionLocal,
    StoredReceipt,
    get_cached_decision,
    get_evaluation,
    get_evaluation_proposals,
    save_cached_decision,
    session_scope,
)
from app.proposals import ProposalValidationError, validate_proposal
from app.schemas import PROFILE
from app.security import verify_receipt_signature

from typing import Any

from app.proposals import ACTIONS

PROCESSING_RESERVATION_TIMEOUT = timedelta(minutes=3)


def is_stale_processing_evaluation(evaluation) -> bool:
    if evaluation.status != "processing":
        return False

    created_at = evaluation.created_at

    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)

    return (
        datetime.now(timezone.utc) - created_at
        > PROCESSING_RESERVATION_TIMEOUT
    )

class RequestValidationError(ValueError):
    pass


def validate_propose_request(
    request: dict[str, Any],
) -> None:
    if request.get("profile") != "ga5-mailroom-action-gate/v2":
        raise RequestValidationError("Unsupported profile")

    if request.get("operation") != "propose":
        raise RequestValidationError("Expected propose operation")

    evaluation_id = request.get("evaluationId")

    if not isinstance(evaluation_id, str) or not evaluation_id.strip():
        raise RequestValidationError("Invalid evaluationId")

    verifier = request.get("receiptVerifier")

    if not isinstance(verifier, dict):
        raise RequestValidationError("Missing receiptVerifier")

    if verifier.get("algorithm") != "Ed25519":
        raise RequestValidationError("Unsupported receipt algorithm")

    corpus = request.get("corpus")

    if not isinstance(corpus, dict):
        raise RequestValidationError("Invalid corpus")

    for field in ("coreId", "auditId"):
        if not isinstance(corpus.get(field), str) or not corpus[field]:
            raise RequestValidationError(f"Invalid corpus.{field}")

    stable_count = corpus.get("stableCount")
    fresh_count = corpus.get("freshCount")

    if (
        type(stable_count) is not int
        or type(fresh_count) is not int
        or stable_count < 0
        or fresh_count < 0
    ):
        raise RequestValidationError("Invalid corpus counts")

    allowed_actions = request.get("allowedActions")

    if not isinstance(allowed_actions, list) or not allowed_actions:
        raise RequestValidationError("allowedActions must be a non-empty list")

    if any(
        not isinstance(action, str) or action not in ACTIONS
        for action in allowed_actions
    ):
        raise RequestValidationError("Unknown allowed action")

    if len(allowed_actions) != len(set(allowed_actions)):
        raise RequestValidationError("Duplicate allowed action")

    dossiers = request.get("dossiers")

    if not isinstance(dossiers, list):
        raise RequestValidationError("dossiers must be a list")

    dossier_ids = []
    stable_actual = 0
    fresh_actual = 0

    for dossier in dossiers:
        if not isinstance(dossier, dict):
            raise RequestValidationError("Each dossier must be an object")

        dossier_id = dossier.get("dossierId")

        if not isinstance(dossier_id, str) or not dossier_id.strip():
            raise RequestValidationError("Invalid dossierId")

        dossier_ids.append(dossier_id)

        partition = dossier.get("partition")

        if partition == "stable_core":
            stable_actual += 1
        elif partition == "fresh_audit":
            fresh_actual += 1
        else:
            raise RequestValidationError("Invalid dossier partition")

    if len(dossier_ids) != len(set(dossier_ids)):
        raise RequestValidationError("Duplicate dossier IDs")

    if stable_actual != stable_count:
        raise RequestValidationError("stableCount does not match dossiers")

    if fresh_actual != fresh_count:
        raise RequestValidationError("freshCount does not match dossiers")


def json_safe_dossier(dossier_model: Any) -> dict[str, Any]:
    return dossier_model.model_dump(mode="json")


def json_safe_request(request_model: Any) -> dict[str, Any]:
    return request_model.model_dump(mode="json")


class ServiceConflictError(RuntimeError):
    pass


class ServiceProcessingError(RuntimeError):
    pass



def compute_input_digest(request):
    return canonical_digest(request["dossiers"])


def process_propose(
    request: dict[str, Any],
    agent: MailroomAgent | None = None,
) -> dict[str, Any]:
    validate_propose_request(request)

    evaluation_id = request["evaluationId"]
    input_digest = compute_input_digest(request)
    request_fingerprint = canonical_digest(request)
    verifier_json = canonical_json(
        request["receiptVerifier"]["publicKeyJwk"]
    ).decode("utf-8")

    with session_scope() as session:
        existing = get_evaluation(session, evaluation_id)

        if existing is not None:
            if existing.request_fingerprint != request_fingerprint:
                raise ServiceConflictError(
                    "Evaluation ID was reused with changed content"
                )

            if existing.propose_response_json is not None:
                return json.loads(existing.propose_response_json)

            if not is_stale_processing_evaluation(existing):
                raise ServiceConflictError(
                    "Evaluation is already being processed"
                )

            session.delete(existing)
            session.flush()

    try:
        with session_scope() as session:
            session.add(
                Evaluation(
                    evaluation_id=evaluation_id,
                    request_fingerprint=request_fingerprint,
                    input_digest=input_digest,
                    verifier_jwk_json=verifier_json,
                    propose_response_json=None,
                    status="processing",
                )
            )
    except IntegrityError:
        with session_scope() as session:
            existing = get_evaluation(session, evaluation_id)

            if existing is None:
                raise ServiceProcessingError(
                    "Unable to reserve evaluation"
                )

            if existing.request_fingerprint != request_fingerprint:
                raise ServiceConflictError(
                    "Evaluation ID was reused with changed content"
                )

            if existing.propose_response_json is not None:
                return json.loads(existing.propose_response_json)

            raise ServiceConflictError(
                "Evaluation is already being processed"
            )

    try:
        if agent is None:
            agent = MailroomAgent()

        allowed_actions = request["allowedActions"]
        proposals = []

        for dossier in request["dossiers"]:
            fingerprint = dossier_fingerprint(dossier)
            call_id = deterministic_call_id(dossier)
            proposal = None

            if dossier["partition"] == "stable_core":
                with session_scope() as session:
                    cached = get_cached_decision(
                        session,
                        fingerprint,
                    )

                    if cached is not None:
                        candidate = json.loads(cached.proposal_json)

                        try:
                            proposal = validate_proposal(
                                candidate,
                                dossier,
                                allowed_actions,
                            )
                        except ProposalValidationError as exc:
                            raise RequestValidationError(
                                "Cached stable decision is incompatible "
                                "with allowedActions"
                            ) from exc

            if proposal is None:
                proposal = agent.validated_proposal(
                    dossier=dossier,
                    allowed_actions=allowed_actions,
                    call_id=call_id,
                )

            if proposal["callId"] != call_id:
                raise ServiceProcessingError(
                    "Proposal callId does not match the deterministic ID"
                )

            proposals.append(
                {
                    "proposal": proposal,
                    "proposalDigest": proposal_digest(proposal),
                    "fingerprint": fingerprint,
                    "dossier": dossier,
                }
            )

        response = {
            "profile": PROFILE,
            "evaluationId": evaluation_id,
            "status": "awaiting_receipts",
            "inputDigest": input_digest,
            "proposals": [
                item["proposal"] for item in proposals
            ],
        }

        response_json = canonical_json(response).decode("utf-8")

        with session_scope() as session:
            evaluation = get_evaluation(session, evaluation_id)

            if evaluation is None:
                raise ServiceProcessingError(
                    "Evaluation reservation was lost"
                )

            if evaluation.request_fingerprint != request_fingerprint:
                raise ServiceConflictError(
                    "Evaluation ID was reused with changed content"
                )

            if evaluation.propose_response_json is not None:
                return json.loads(evaluation.propose_response_json)

            for item in proposals:
                proposal = item["proposal"]

                session.add(
                    EvaluationProposal(
                        evaluation_id=evaluation_id,
                        dossier_id=proposal["dossierId"],
                        dossier_fingerprint=item["fingerprint"],
                        call_id=proposal["callId"],
                        proposal_json=canonical_json(
                            proposal
                        ).decode("utf-8"),
                        proposal_digest=item["proposalDigest"],
                    )
                )

                if item["dossier"]["partition"] == "stable_core":
                    save_cached_decision(
                        session,
                        item["fingerprint"],
                        item["dossier"],
                        proposal,
                    )

            evaluation.propose_response_json = response_json
            evaluation.status = "awaiting_receipts"

        return response

    except (AgentError, ProposalValidationError) as exc:
        print(f"PROPOSAL DEBUG: {type(exc).__name__}: {exc}", flush=True)
        error = ServiceProcessingError(
            "Unable to produce a valid proposal"
        )
        error.__cause__ = exc
        cause = exc.__cause__
        while cause is not None:
            print(f"ROOT CAUSE: {type(cause).__name__}: {cause}", flush=True)
            cause = cause.__cause__
        raise error

    except Exception:
        try:
            with session_scope() as session:
                evaluation = get_evaluation(session, evaluation_id)

                if (
                    evaluation is not None
                    and evaluation.request_fingerprint == request_fingerprint
                    and evaluation.propose_response_json is None
                    and evaluation.status == "processing"
                ):
                    session.delete(evaluation)
        except Exception:
            pass

        raise


def process_commit(
    request: dict[str, Any],
) -> dict[str, Any]:
    if request.get("profile") != PROFILE:
        raise RequestValidationError("Unsupported profile")

    if request.get("operation") != "commit":
        raise RequestValidationError("Expected commit operation")

    evaluation_id = request.get("evaluationId")
    input_digest = request.get("inputDigest")
    receipts = request.get("receipts")

    if not isinstance(evaluation_id, str) or not evaluation_id:
        raise RequestValidationError("Invalid evaluationId")

    if not isinstance(input_digest, str) or len(input_digest) != 64:
        raise RequestValidationError("Invalid inputDigest")

    if not isinstance(receipts, list):
        raise RequestValidationError("receipts must be a list")

    commit_fingerprint = canonical_digest(request)

    with session_scope() as session:
        evaluation = get_evaluation(session, evaluation_id)

        if evaluation is None:
            raise ServiceConflictError("Unknown evaluation")

        if evaluation.input_digest != input_digest:
            raise ServiceConflictError("inputDigest does not match evaluation")

        if evaluation.commit_response_json is not None:
            if evaluation.commit_request_fingerprint != commit_fingerprint:
                raise ServiceConflictError(
                    "Commit replay contains changed content"
                )

            return json.loads(evaluation.commit_response_json)

        stored_proposals = get_evaluation_proposals(
            session,
            evaluation_id,
        )

        verifier_jwk = json.loads(evaluation.verifier_jwk_json)

        if len(receipts) != len(stored_proposals):
            raise RequestValidationError(
                "Receipt count does not match proposal count"
            )

        proposals_by_dossier = {
            proposal.dossier_id: proposal
            for proposal in stored_proposals
        }

        seen_dossiers = set()
        seen_calls = set()
        seen_receipt_ids = set()
        verified_receipts = []

        for receipt in receipts:
            dossier_id = receipt.get("dossierId")
            call_id = receipt.get("callId")
            receipt_id = receipt.get("receiptId")

            if (
                not isinstance(dossier_id, str)
                or not isinstance(call_id, str)
                or not isinstance(receipt_id, str)
                or not receipt_id
            ):
                raise RequestValidationError("Malformed receipt identifiers")

            if (
                dossier_id in seen_dossiers
                or call_id in seen_calls
                or receipt_id in seen_receipt_ids
            ):
                raise RequestValidationError("Duplicate receipt binding")

            seen_dossiers.add(dossier_id)
            seen_calls.add(call_id)
            seen_receipt_ids.add(receipt_id)

            stored = proposals_by_dossier.get(dossier_id)

            if stored is None:
                raise ServiceConflictError("Receipt references unknown dossier")

            if call_id != stored.call_id:
                raise ServiceConflictError("Receipt callId mismatch")

            if receipt.get("action") != json.loads(
                stored.proposal_json
            )["action"]:
                raise ServiceConflictError("Receipt action mismatch")

            if receipt.get("proposalDigest") != stored.proposal_digest:
                raise ServiceConflictError("Receipt proposalDigest mismatch")

            if not verify_receipt_signature(
                receipt=receipt,
                evaluation_id=evaluation_id,
                input_digest=input_digest,
                public_key_jwk=verifier_jwk,
            ):
                raise RequestValidationError("Invalid receipt signature")

            verified_receipts.append((stored, receipt))

        if seen_dossiers != set(proposals_by_dossier):
            raise RequestValidationError("Missing proposal receipt")

        outcomes = []

        for stored, receipt in verified_receipts:
            proposal = json.loads(stored.proposal_json)

            outcome = {
                "dossierId": stored.dossier_id,
                "callId": stored.call_id,
                "action": proposal["action"],
                "proposalDigest": stored.proposal_digest,
                "receiptId": receipt["receiptId"],
                "status": (
                    "executed" if receipt["accepted"] else "rejected"
                ),
            }

            outcomes.append(outcome)

        response = {
            "profile": PROFILE,
            "evaluationId": evaluation_id,
            "status": "completed",
            "inputDigest": input_digest,
            "outcomes": outcomes,
        }

        for stored, receipt in verified_receipts:
            outcome = next(
                item for item in outcomes
                if item["dossierId"] == stored.dossier_id
            )

            session.add(
                StoredReceipt(
                    evaluation_id=evaluation_id,
                    dossier_id=stored.dossier_id,
                    call_id=stored.call_id,
                    receipt_id=receipt["receiptId"],
                    receipt_json=canonical_json(
                        receipt
                    ).decode("utf-8"),
                    outcome_json=canonical_json(
                        outcome
                    ).decode("utf-8"),
                )
            )

        evaluation.commit_request_fingerprint = commit_fingerprint
        evaluation.commit_response_json = canonical_json(
            response
        ).decode("utf-8")
        evaluation.status = "completed"

        return response
