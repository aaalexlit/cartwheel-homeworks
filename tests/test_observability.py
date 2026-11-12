"""Homework 2, Part D: authentication tests for the session endpoints.

Everything here runs offline. The FastAPI TestClient is used without its
context manager, so the app lifespan (which would configure Langfuse) never
runs, and every request below is rejected before the agent or a model
provider is touched.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from server import app as server_app


@pytest.fixture
def client(world: dict) -> TestClient:
    server_app._SESSIONS.clear()
    return TestClient(server_app.app)


def _open_session(client: TestClient, user_id: int, role: str) -> dict:
    response = client.post("/sessions", json={"user_id": user_id, "role": role})
    assert response.status_code == 200, response.text
    return response.json()


def test_create_session_rejects_role_that_differs_from_database(client: TestClient) -> None:
    # User 1 is a shopper in the seeded world; claiming merchant is refused.
    response = client.post("/sessions", json={"user_id": 1, "role": "merchant"})

    assert response.status_code == 403
    assert server_app._SESSIONS == {}, "a rejected request must not open a session"


def test_create_session_rejects_unknown_role_and_user(client: TestClient) -> None:
    assert client.post("/sessions", json={"user_id": 1, "role": "admin"}).status_code == 400
    assert client.post("/sessions", json={"user_id": 999_999, "role": "shopper"}).status_code == 404


def test_token_for_one_session_cannot_authorize_another(client: TestClient) -> None:
    first = _open_session(client, user_id=1, role="shopper")
    second = _open_session(client, user_id=2, role="shopper")

    response = client.post(
        f"/sessions/{second['session_id']}/messages",
        headers={"Authorization": f"Bearer {first['token']}"},
        json={"message": "Show my recent orders."},
    )

    assert response.status_code == 403
    assert "another session" in response.json()["detail"]


def test_message_without_or_with_tampered_token_is_unauthorized(client: TestClient) -> None:
    session = _open_session(client, user_id=1, role="shopper")
    url = f"/sessions/{session['session_id']}/messages"
    body = {"message": "Show my recent orders."}

    assert client.post(url, json=body).status_code == 401

    # Flip the signature so the payload no longer verifies.
    payload, signature = session["token"].rsplit(".", 1)
    tampered = f"{payload}.{'0' * len(signature)}"
    response = client.post(url, headers={"Authorization": f"Bearer {tampered}"}, json=body)
    assert response.status_code == 401


def test_token_payload_comes_from_database_identity(client: TestClient) -> None:
    session = _open_session(client, user_id=9001, role="merchant")
    payload = server_app.verify_token(session["token"])

    assert payload is not None
    assert payload["session_id"] == session["session_id"]
    assert payload["user_id"] == 9001
    assert payload["role"] == "merchant"
    assert payload["store_id"] == 1
    assert isinstance(payload["issued_at"], int)
