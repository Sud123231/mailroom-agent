
from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_invalid_json_is_rejected():
    response = client.post(
        "/",
        content="{invalid",
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 400


def test_unknown_operation_is_rejected():
    response = client.post(
        "/",
        json={"operation": "unknown"},
    )

    assert response.status_code == 400


def test_missing_propose_fields_are_rejected():
    response = client.post(
        "/",
        json={
            "profile": "ga5-mailroom-action-gate/v2",
            "operation": "propose",
        },
    )

    assert response.status_code == 422


def test_missing_commit_fields_are_rejected():
    response = client.post(
        "/",
        json={
            "profile": "ga5-mailroom-action-gate/v2",
            "operation": "commit",
        },
    )

    assert response.status_code == 422
