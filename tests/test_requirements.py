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


def test_only_rpi_gpio_is_treated_as_pi_only():
    """RPi.GPIO is Pi-only. gpiozero and pyserial are NOT, however much they look it.

    A static grep for "import gpiozero" under app/ finds nothing, which is
    misleading: app/routes/skeeball.py imports gpio_init, which does
    `from gpiozero import Device` at module level and takes MockFactory from
    gpiozero for mock mode. Dropping gpiozero from the server requirements made
    every skeeball route 500 on a fresh virtualenv -- including
    /skeeball/api/health. Only RPi.GPIO is genuinely absent off a Pi, and
    gpio_init already wraps that import in try/except.
    """
    server = set(_pins("requirements.txt"))
    pi_only = set(_pins("requirements-pi.txt"))

    assert "rpi.gpio" not in server, "RPi.GPIO does not install or import off a Pi"
    assert "rpi.gpio" in pi_only

    for package in ("gpiozero", "pyserial"):
        assert package in server, (
            f"{package} is imported transitively by the skeeball routes; moving it "
            "out of requirements.txt breaks them on a hardware-free server"
        )
        assert package not in pi_only, f"{package} must not be duplicated across both files"


def test_segno_is_present_because_the_label_route_imports_it():
    """app/routes/games.py imports segno; a server install without it 500s on labels."""
    assert "segno" in _pins("requirements.txt")
