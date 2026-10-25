import pytest

from app.agent import AgentError, MailroomAgent


DOSSIER = {
    "dossierId": "dossier-agent-001",
    "partition": "stable_core",
    "receivedAt": "2026-10-24T10:00:00Z",
    "mailbox": "orders@example.com",
    "objective": "Read the informational update",
    "sources": [
        {
            "sourceId": "source-001",
            "kind": "email",
            "provenance": "customer",
            "title": "Order update",
            "lines": [
                {
                    "lineId": "line-001",
                    "text": "Order reference: order-123",
                }
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


def make_agent(monkeypatch, evidence):
    agent = object.__new__(MailroomAgent)
    responses = iter(
        [
            {"action": "no_action"},
            {
                "dossierId": DOSSIER["dossierId"],
                "action": "no_action",
                "target": None,
                "payload": {
                    "reasonCode": "INFORMATIONAL",
                    "referenceId": "order-123",
                },
                "evidence": evidence,
            },
        ]
    )
    calls = []

    def generate(prompt, schema):
        calls.append((prompt, schema))
        return next(responses)

    monkeypatch.setattr(
        agent,
        "_generate_json",
        generate,
    )
    agent.model_calls = calls
    return agent


def test_validated_proposal_is_an_agent_method(monkeypatch):
    agent = make_agent(monkeypatch, ["line-001"])

    proposal = agent.validated_proposal(
        DOSSIER,
        ALLOWED_ACTIONS,
        "call-agent-0001",
    )

    assert proposal == {
        "dossierId": DOSSIER["dossierId"],
        "callId": "call-agent-0001",
        "action": "no_action",
        "target": None,
        "payload": {
            "reasonCode": "INFORMATIONAL",
            "referenceId": "order-123",
        },
        "evidence": ["line-001"],
    }
    assert len(agent.model_calls) == 2


def test_invalid_model_evidence_fails_without_logging_payload(
    monkeypatch,
    capsys,
):
    agent = make_agent(monkeypatch, ["unknown-line"])

    with pytest.raises(AgentError, match="failed schema or evidence validation"):
        agent.validated_proposal(
            DOSSIER,
            ALLOWED_ACTIONS,
            "call-agent-0001",
        )

    assert capsys.readouterr().out == ""
