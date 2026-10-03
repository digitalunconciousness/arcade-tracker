"""The factory builds, and the schema it builds is complete.

`inventory_request_history` is asserted by name on purpose: the model existed with
no migration to create it, so a database brought up through Flask-Migrate was
missing it and every page touching the audit trail raised
`no such table: inventory_request_history`. Migration f1c2d3e4a5b6 fixed that.
"""
from __future__ import annotations

EXPECTED_BLUEPRINTS = {
    "admin", "auth", "dashboard", "games", "inventory",
    "maintenance", "reports", "skeeball",
    # _register_blueprints swallows an ImportError with a printed warning, so a broken
    # blueprint is simply absent and every one of its routes 404s. Naming it here turns
    # that silence into a failing test.
    "api_v1",
}


def test_factory_builds_and_registers_every_blueprint(app):
    assert EXPECTED_BLUEPRINTS <= set(app.blueprints), (
        f"missing: {EXPECTED_BLUEPRINTS - set(app.blueprints)}"
    )


def test_create_all_builds_every_model_table(app):
    from app.extensions import db
    import sqlalchemy as sa

    declared = set(db.metadata.tables)
    present = set(sa.inspect(db.engine).get_table_names())
    assert declared <= present, f"declared but not created: {sorted(declared - present)}"


def test_the_audit_trail_table_exists(app):
    from app.extensions import db
    import sqlalchemy as sa

    assert sa.inspect(db.engine).has_table("inventory_request_history")


def test_the_home_page_answers(client):
    response = client.get("/")
    # Unauthenticated: a redirect to the login page is the right answer, not a 500.
    assert response.status_code in (200, 302), response.status_code
