"""The pinning that keeps the application able to reach its own database.

requirements.txt pinned Flask-SQLAlchemy but not SQLAlchemy, and named no
PostgreSQL driver at all -- psycopg2 had been installed on the server by hand. A
clean virtualenv therefore resolved SQLAlchemy 2.1, which changed the default
driver for "postgresql://" from psycopg2 to psycopg 3, and the application could
not connect:

    ModuleNotFoundError: No module named 'psycopg'

These assertions are cheap and they would have caught it before a cut-over.
"""
from __future__ import annotations

import os
import re

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _pins(filename: str) -> dict[str, str]:
    path = os.path.join(REPO_ROOT, filename)
    pins: dict[str, str] = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.split("#", 1)[0].strip()
            match = re.match(r"^([A-Za-z0-9_.\-]+)==([^\s;]+)$", line)
            if match:
                pins[match.group(1).lower()] = match.group(2)
    return pins


def test_sqlalchemy_is_pinned_explicitly():
    pins = _pins("requirements.txt")
    assert "sqlalchemy" in pins, (
        "SQLAlchemy must be pinned directly, not left to resolve as a transitive "
        "dependency of Flask-SQLAlchemy: 2.1 changes the default postgresql driver."
    )


def test_a_postgresql_driver_is_present():
    pins = _pins("requirements.txt")
    drivers = {"psycopg2", "psycopg2-binary", "psycopg", "pg8000"}
    assert drivers & set(pins), (
        "requirements.txt names no PostgreSQL driver, but the deployment's "
        f"DATABASE_URL is a postgresql:// URL. Pinned: {sorted(pins)}"
    )


def test_the_driver_matches_what_sqlalchemy_will_default_to():
    """A psycopg2 pin with SQLAlchemy >= 2.1 is the exact trap described above."""
    pins = _pins("requirements.txt")
    sqlalchemy_version = tuple(int(p) for p in pins["sqlalchemy"].split(".")[:2])
    uses_psycopg2 = {"psycopg2", "psycopg2-binary"} & set(pins)
    if uses_psycopg2 and sqlalchemy_version >= (2, 1):
        raise AssertionError(
            f"SQLAlchemy {pins['sqlalchemy']} defaults postgresql:// to psycopg 3, "
            "but only psycopg2 is pinned. Either pin psycopg[binary] or write the "
            "URL as postgresql+psycopg2://."
        )


def test_the_retired_skeeball_hardware_packages_are_gone():
    """Skeeball was retired on 2026-10-08. Nothing left in the server imports gpiozero or
    pyserial (gpio_init and the lane manager went to docs/history/skeeball/ with it), so
    a server install has no reason to pull them in."""
    server = set(_pins("requirements.txt"))
    for package in ("gpiozero", "pyserial", "rpi.gpio"):
        assert package not in server, f"{package} belonged to the retired skeeball lanes"
    assert not os.path.exists(os.path.join(REPO_ROOT, "requirements-pi.txt"))


def test_segno_is_present_because_the_label_route_imports_it():
    """app/routes/games.py imports segno; a server install without it 500s on labels."""
    assert "segno" in _pins("requirements.txt")
