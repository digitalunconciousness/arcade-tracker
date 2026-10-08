"""Helpers shared by the characterization tests (imported as a plain module)."""
from __future__ import annotations

ROLES = ("readonly", "operator", "manager", "admin")
LEVEL = {"anon": 0, "readonly": 1, "operator": 2, "manager": 3, "admin": 4}
PASSWORD = "Synthetic-Passw0rd!"


def login(client, role: str):
    """Sign *client* in as the seeded user for *role*; ``anon`` leaves it signed out."""
    if role == "anon":
        return client
    resp = client.post("/login", data={"username": f"test-{role}", "password": PASSWORD})
    assert resp.status_code == 302, f"login as {role} failed"
    return client


def flashes(client) -> list[tuple[str, str]]:
    with client.session_transaction() as sess:
        return list(sess.get("_flashes", []))
