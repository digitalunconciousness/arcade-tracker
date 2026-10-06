"""Shared fixtures. Every test gets its own throwaway SQLite database.

Nothing here may touch a real database: DATABASE_URL is overridden for the whole
session before the application is imported, so a stray test cannot reach the
deployment's PostgreSQL even if .env is present.
"""
from __future__ import annotations

import os
import tempfile

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(scope="session", autouse=True)
def _isolate_environment():
    """Point the application at a scratch database and a throwaway secret."""
    tmp = tempfile.mkdtemp(prefix="arcade-tracker-tests-")
    os.environ["DATABASE_URL"] = f"sqlite:///{os.path.join(tmp, 'test.db')}"
    os.environ["SECRET_KEY"] = "test-only-not-a-real-secret"
    os.environ.setdefault("WTF_CSRF_ENABLED", "False")
    yield


@pytest.fixture()
def app(_isolate_environment):
    from app import create_app
    from app.extensions import db

    application = create_app()
    application.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    """Flask-Limiter's storage outlives the app fixture.

    ``limiter`` is a module-level singleton with ``storage_uri="memory://"``, so its counters
    are created once per pytest process and shared by every test that follows -- a test that
    exhausts a limit would quietly spend another test's budget, and the order they run in
    would decide who fails.
    """
    from app.extensions import limiter

    # ``limiter.storage`` asserts on an uninitialised limiter, and this runs before the app
    # fixture builds one -- so on the first test of a process there is nothing to reset yet.
    # Checking the attribute is less odd than catching the AssertionError behind it.
    if getattr(limiter, "_storage", None) is not None:
        limiter.reset()
    yield
