"""Nothing that runs as part of the application may import names from `app`
that the factory package does not export.

`app/` exports `create_app` and nothing else. The monolithic `app.py` used to
re-export `db`, `Game`, `User` and friends at module level, so `from app import
db, Game` worked then and raises ImportError now. One of those survived the
refactor in skeeball/revenue_scheduler.py, inside a thread that swallowed the
error and retried every 60 seconds -- so the automatic daily revenue sync never
ran and nothing surfaced except a log line.

Scope is deliberately the code that runs when the application runs. The one-off
maintenance scripts at the repository root (init_db.py, list_users.py,
create_manager.py, reset_ranking_counters.py, register_skeeball_lanes.py,
create_*_table.py, migrate_*.py, scripts/migrate_database.py,
scripts/import_csv_backup.py, templates/dbmigrate.py) carry the same stale
imports and fail loudly the moment they are run; they are tracked separately
rather than asserted here, so this test stays about live behaviour.
"""
from __future__ import annotations

import os
import re

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Directories and files that are imported while serving a request.
LIVE_PATHS = ["app", "skeeball", "run.py", "scripts/create_admin.py"]

IMPORT_RE = re.compile(r"^\s*from app import\s+(.+?)\s*(?:#.*)?$", re.MULTILINE)
EXPORTED = {"create_app", "models"}       # `models` is imported for its side effect


def _python_files():
    for entry in LIVE_PATHS:
        path = os.path.join(REPO_ROOT, entry)
        if os.path.isfile(path):
            yield path
            continue
        for root, _dirs, files in os.walk(path):
            for name in files:
                if name.endswith(".py"):
                    yield os.path.join(root, name)


def test_live_code_imports_only_what_app_exports():
    offenders = []
    for path in _python_files():
        with open(path, encoding="utf-8") as handle:
            source = handle.read()
        for match in IMPORT_RE.finditer(source):
            names = {n.strip().split(" as ")[0] for n in match.group(1).split(",")}
            unknown = {n for n in names if n and n not in EXPORTED}
            if unknown:
                rel = os.path.relpath(path, REPO_ROOT)
                line = source[: match.start()].count("\n") + 1
                offenders.append(f"{rel}:{line} imports {sorted(unknown)} from app")
    assert not offenders, (
        "app/ exports only create_app; these will raise ImportError:\n  "
        + "\n  ".join(offenders)
    )
