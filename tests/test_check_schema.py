"""scripts/check_schema.py -- the sequence half.

The schema comparison is exercised every time ``deploy.sh`` runs. The sequence
check cannot be: it is PostgreSQL-only and the suite runs on SQLite, so what is
tested here is the dialect guard (it must not fire spuriously) and the repair
statement it prints, which is the part a person copies and runs.
"""
from __future__ import annotations

import importlib.util
import os

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _module():
    path = os.path.join(REPO_ROOT, "scripts", "check_schema.py")
    spec = importlib.util.spec_from_file_location("check_schema", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def check_schema():
    return _module()


def test_the_sequence_check_is_a_no_op_off_postgresql(check_schema, app):
    """SQLite has no sequences; the check must stay silent rather than guess."""
    from app.extensions import db

    with app.app_context():
        assert db.engine.dialect.name == "sqlite", "the suite must not touch PostgreSQL"
        assert check_schema.check_sequences(db, {"game"}) == []


def test_the_repair_names_the_table_column_and_sequence(check_schema, capsys):
    check_schema.report_sequences([("game", "public.game_id_seq", "id", 1, 100)])
    out = capsys.readouterr().out
    assert "game.id: next value would be 1, but 100 is already in use" in out
    assert "SELECT setval('public.game_id_seq', (SELECT max(id) FROM \"game\"));" in out


def test_a_non_id_primary_key_is_named_correctly(check_schema, capsys):
    """The repair used to hard-code max(id), which is wrong for any other key."""
    check_schema.report_sequences([("widget", "public.widget_pk_seq", "widget_id", 3, 9)])
    out = capsys.readouterr().out
    assert "max(widget_id)" in out
    assert "max(id)" not in out
