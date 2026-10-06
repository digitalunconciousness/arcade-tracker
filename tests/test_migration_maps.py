"""``scripts/check_schema.py``'s three maps, against the migrations themselves.

``INTRODUCED_BY``, ``PREDECESSOR`` and ``ORDER`` are maintained by hand, with a comment
saying "keep in step with migrations/versions/" and nothing enforcing it. ``deploy.sh``
gates the deploy on that script, so a map that has drifted either points at the wrong
revision in a failure message or -- worse -- reports a missing column as unknown and
leaves whoever is deploying with no instruction.

This reads the migration files, so adding a revision without touching the maps fails here
instead of at a deploy.
"""
from __future__ import annotations

import importlib.util
import os
import re

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERSIONS = os.path.join(REPO_ROOT, "migrations", "versions")

REVISION = re.compile(r"^revision\s*=\s*['\"]([^'\"]+)['\"]", re.M)
DOWN = re.compile(r"^down_revision\s*=\s*(?:['\"]([^'\"]+)['\"]|None)", re.M)
TABLE = re.compile(r"batch_alter_table\(\s*['\"]([^'\"]+)['\"]")
COLUMN = re.compile(r"add_column\(\s*sa\.Column\(\s*['\"]([^'\"]+)['\"]")
CREATE = re.compile(r"op\.create_table\(\s*\n?\s*['\"]([^'\"]+)['\"]")


def _migrations() -> dict[str, dict]:
    """{revision: {"down", "added": {(table, column)}}} read off the files."""
    out = {}
    for name in sorted(os.listdir(VERSIONS)):
        if not name.endswith(".py"):
            continue
        text = open(os.path.join(VERSIONS, name), encoding="utf-8").read()
        rev = REVISION.search(text)
        if not rev:
            continue
        down = DOWN.search(text)
        # upgrade() only: downgrade() drops the same columns and would double-count.
        upgrade = text.split("def upgrade()", 1)[-1].split("def downgrade()", 1)[0]
        added, table = set(), None
        for line in upgrade.splitlines():
            t = TABLE.search(line)
            if t:
                table = t.group(1)
            c = COLUMN.search(line)
            if c and table:
                added.add((table, c.group(1)))
        out[rev.group(1)] = {"down": down.group(1) if down and down.group(1) else None,
                             "added": added,
                             "tables": set(CREATE.findall(upgrade))}
    return out


@pytest.fixture()
def check_schema():
    path = os.path.join(REPO_ROOT, "scripts", "check_schema.py")
    spec = importlib.util.spec_from_file_location("check_schema", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_order_is_the_real_revision_chain(check_schema):
    revs = _migrations()
    downs = {v["down"] for v in revs.values()}
    heads = [r for r in revs if r not in downs]
    assert len(heads) == 1, f"expected one head, found {sorted(heads)}"
    chain, rev = [], heads[0]
    while rev is not None:
        chain.append(rev)
        rev = revs[rev]["down"]
    assert check_schema.ORDER == list(reversed(chain))


def test_predecessor_matches_each_down_revision(check_schema):
    revs = _migrations()
    for rev, pred in check_schema.PREDECESSOR.items():
        assert rev in revs, f"PREDECESSOR names {rev}, which is not a migration"
        assert revs[rev]["down"] == pred, (
            f"{rev}: down_revision is {revs[rev]['down']!r}, PREDECESSOR says {pred!r}"
        )


def test_every_added_column_is_attributed_to_its_revision(check_schema):
    """The map is what turns "column missing" into "stamp X and upgrade"."""
    revs = _migrations()
    for rev, info in revs.items():
        for key in info["added"]:
            assert key in check_schema.INTRODUCED_BY, (
                f"{key[0]}.{key[1]} is added by {rev} and is not in INTRODUCED_BY"
            )
            assert check_schema.INTRODUCED_BY[key] == rev, (
                f"{key[0]}.{key[1]} is added by {rev}, "
                f"INTRODUCED_BY says {check_schema.INTRODUCED_BY[key]}"
            )


def test_introduced_by_names_only_real_revisions(check_schema):
    revs = _migrations()
    for key, rev in check_schema.INTRODUCED_BY.items():
        assert rev in revs, f"INTRODUCED_BY[{key}] names {rev}, which is not a migration"


def test_every_created_table_is_attributed_to_its_revision(check_schema):
    """``check_schema`` prints a stamp instruction for a missing *column* and, for a missing
    table, only "db upgrade may be enough" -- which is the one case where it has nothing
    useful to say. Phase 2 left three tables unattributed and Phase 6 adds a fourth.
    """
    revs = _migrations()
    for rev, info in revs.items():
        for table in info["tables"]:
            assert table in check_schema.TABLE_INTRODUCED_BY, (
                f"{table} is created by {rev} and is not in TABLE_INTRODUCED_BY"
            )
            assert check_schema.TABLE_INTRODUCED_BY[table] == rev, (
                f"{table} is created by {rev}, "
                f"TABLE_INTRODUCED_BY says {check_schema.TABLE_INTRODUCED_BY[table]}"
            )


def test_table_attribution_names_only_real_revisions(check_schema):
    revs = _migrations()
    for table, rev in check_schema.TABLE_INTRODUCED_BY.items():
        assert rev in revs, f"TABLE_INTRODUCED_BY[{table}] names {rev}, not a migration"
