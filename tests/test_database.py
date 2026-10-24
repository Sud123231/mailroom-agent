
import json

from sqlalchemy import select

from app.database import (
    CachedDecision,
    Evaluation,
    EvaluationProposal,
    StoredReceipt,
    create_database,
    get_cached_decision,
    save_cached_decision,
    session_scope,
)


def test_database_creates_all_tables(tmp_path):
    database_path = tmp_path / "test.db"
    engine, factory = create_database(f"sqlite:///{database_path}")

    try:
        assert set(engine.dialect.get_table_names(engine.connect())) >= {
            "evaluations",
            "cached_decisions",
            "evaluation_proposals",
            "stored_receipts",
        }
    finally:
        engine.dispose()


def test_evaluation_persists_across_sessions(tmp_path):
    database_path = tmp_path / "evaluation.db"
    engine, factory = create_database(f"sqlite:///{database_path}")

    try:
        with session_scope(factory) as session:
            session.add(
                Evaluation(
                    evaluation_id="eval-001",
                    request_fingerprint="a" * 64,
                    input_digest="b" * 64,
                    verifier_jwk_json=json.dumps({
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "x": "test",
                    }),
                    status="proposed",
                )
            )

        with session_scope(factory) as session:
            evaluation = session.get(Evaluation, "eval-001")

            assert evaluation is not None
            assert evaluation.input_digest == "b" * 64
            assert evaluation.status == "proposed"
    finally:
        engine.dispose()


def test_cached_decision_is_reused(tmp_path):
    database_path = tmp_path / "cache.db"
    engine, factory = create_database(f"sqlite:///{database_path}")

    dossier = {
        "dossierId": "dossier-001",
        "objective": "Read the mail",
    }

    proposal = {
        "dossierId": "dossier-001",
        "callId": "call-12345678",
        "action": "no_action",
        "target": None,
        "payload": {
            "reasonCode": "INFORMATIONAL",
            "referenceId": "ref-001",
        },
        "evidence": ["line-001"],
    }

    try:
        with session_scope(factory) as session:
            saved = save_cached_decision(
                session,
                "c" * 64,
                dossier,
                proposal,
            )

            assert saved.call_id == proposal["callId"]

        with session_scope(factory) as session:
            cached = get_cached_decision(session, "c" * 64)

            assert cached is not None
            assert json.loads(cached.proposal_json) == proposal

        with session_scope(factory) as session:
            cached_again = save_cached_decision(
                session,
                "c" * 64,
                dossier,
                {**proposal, "callId": "different-call-123"},
            )

            assert cached_again.call_id == proposal["callId"]
    finally:
        engine.dispose()



def test_cached_decision_is_not_overwritten(tmp_path):
    import json

    from app.database import (
        create_database,
        save_cached_decision,
        session_scope,
    )

    engine, factory = create_database(
        f"sqlite:///{tmp_path / 'cache_test.db'}"
    )

    dossier = {
        "dossierId": "dossier-cache-test",
        "partition": "stable_core",
        "objective": "Informational",
    }

    first_proposal = {
        "dossierId": "dossier-cache-test",
        "callId": "call-cache-test-001",
        "action": "no_action",
        "target": None,
        "payload": {
            "reasonCode": "INFORMATIONAL",
            "referenceId": "ref-001",
        },
        "evidence": ["line-001"],
    }

    second_proposal = {
        **first_proposal,
        "payload": {
            "reasonCode": "DUPLICATE",
            "referenceId": "ref-001",
        },
    }

    fingerprint = "a" * 64

    try:
        with session_scope(factory) as session:
            first = save_cached_decision(
                session,
                fingerprint,
                dossier,
                first_proposal,
            )
            assert json.loads(first.proposal_json) == first_proposal

        with session_scope(factory) as session:
            second = save_cached_decision(
                session,
                fingerprint,
                dossier,
                second_proposal,
            )
            assert json.loads(second.proposal_json) == first_proposal
    finally:
        engine.dispose()
