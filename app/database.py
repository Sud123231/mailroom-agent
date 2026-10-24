from sqlalchemy.exc import IntegrityError
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

from sqlalchemy import (
    DateTime,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    select,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    sessionmaker,
)

from app.canonical import canonical_json


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./mailroom.db",
)


def build_engine(database_url: str):
    options: dict[str, Any] = {}

    if database_url.startswith("sqlite"):
        options["connect_args"] = {"check_same_thread": False}

    return create_engine(
        database_url,
        pool_pre_ping=True,
        **options,
    )


class Base(DeclarativeBase):
    pass


class Evaluation(Base):
    __tablename__ = "evaluations"

    evaluation_id: Mapped[str] = mapped_column(
        String(255),
        primary_key=True,
    )
    request_fingerprint: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    input_digest: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    verifier_jwk_json: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    propose_response_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    commit_request_fingerprint: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    commit_response_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="proposed",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class CachedDecision(Base):
    __tablename__ = "cached_decisions"

    dossier_fingerprint: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )
    dossier_json: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    proposal_json: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    call_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class EvaluationProposal(Base):
    __tablename__ = "evaluation_proposals"
    __table_args__ = (
        UniqueConstraint(
            "evaluation_id",
            "dossier_id",
            name="uq_evaluation_dossier",
        ),
        UniqueConstraint(
            "evaluation_id",
            "call_id",
            name="uq_evaluation_call",
        ),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )
    evaluation_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    dossier_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    dossier_fingerprint: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    call_id: Mapped[str] = mapped_column(
    String(128),
    nullable=False,
    )

    proposal_json: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    proposal_digest: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )


class StoredReceipt(Base):
    __tablename__ = "stored_receipts"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )
    evaluation_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    dossier_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    call_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    receipt_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    receipt_json: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    outcome_json: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    __table_args__ = (
        UniqueConstraint(
            "evaluation_id",
            "receipt_id",
            name="uq_evaluation_receipt",
        ),
        UniqueConstraint(
            "evaluation_id",
            "dossier_id",
            name="uq_evaluation_receipt_dossier",
        ),
    )


def create_database(database_url: str = DATABASE_URL):
    engine = build_engine(database_url)
    Base.metadata.create_all(engine)

    factory = sessionmaker(
        bind=engine,
        expire_on_commit=False,
    )

    return engine, factory


engine, SessionLocal = create_database()


@contextmanager
def session_scope(
    factory: sessionmaker[Session] = SessionLocal,
) -> Iterator[Session]:
    session = factory()

    try:
        with session.begin():
            yield session
    finally:
        session.close()


def get_evaluation(
    session: Session,
    evaluation_id: str,
) -> Evaluation | None:
    return session.get(Evaluation, evaluation_id)


def get_cached_decision(
    session: Session,
    dossier_fingerprint: str,
) -> CachedDecision | None:
    return session.get(CachedDecision, dossier_fingerprint)



def save_cached_decision(
    session: Session,
    dossier_fingerprint: str,
    dossier: dict[str, Any],
    proposal: dict[str, Any],
) -> CachedDecision:
    existing = get_cached_decision(session, dossier_fingerprint)

    if existing is not None:
        return existing

    cached = CachedDecision(
        dossier_fingerprint=dossier_fingerprint,
        dossier_json=canonical_json(dossier).decode("utf-8"),
        proposal_json=canonical_json(proposal).decode("utf-8"),
        call_id=proposal["callId"],
    )

    try:
        with session.begin_nested():
            session.add(cached)
            session.flush()
        return cached
    except IntegrityError:
        existing = get_cached_decision(session, dossier_fingerprint)

        if existing is not None:
            return existing

        raise


def get_evaluation_proposals(
    session: Session,
    evaluation_id: str,
) -> list[EvaluationProposal]:
    statement = (
        select(EvaluationProposal)
        .where(EvaluationProposal.evaluation_id == evaluation_id)
        .order_by(EvaluationProposal.id)
    )

    return list(session.scalars(statement).all())
