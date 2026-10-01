#!/usr/bin/env python3
"""Create the first admin account, or rotate an existing user's password.

Recovered from ``create_admin_fix.py``, which existed only on the deployment and
was never committed. It replaces the legacy ``create_admin.py`` (moved to
``docs/history/``), which was written against the monolithic ``app.py``.

    python scripts/create_admin.py                      # create the first admin
    python scripts/create_admin.py --list               # show who exists
    python scripts/create_admin.py --reset-password NAME

``--reset-password`` exists because the only way to rotate a manager or
read-only account was to log in as them. Database snapshots were committed to
this repository's history in 2025, so those password hashes are public and every
account that predates the clean-up has to be rotated from the outside.

Run it from the repository root with the application's environment loaded, so
DATABASE_URL points at the real database:

    set -a && . ./.env && set +a && ./venv/bin/python scripts/create_admin.py
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app                      # noqa: E402
from app.extensions import db                   # noqa: E402
from app.models import User                     # noqa: E402

MIN_USERNAME = 4
MIN_PASSWORD = 8          # the app's own forms ask for 8; the old script said 6


def _ask_password(prompt: str = "Password") -> str | None:
    """Prompt twice, never echoing. Returns None if the answers are unusable."""
    first = getpass.getpass(f"{prompt} (min {MIN_PASSWORD} chars): ").strip()
    if len(first) < MIN_PASSWORD:
        print(f"Password must be at least {MIN_PASSWORD} characters.", file=sys.stderr)
        return None
    if first != getpass.getpass("Confirm: ").strip():
        print("Passwords do not match.", file=sys.stderr)
        return None
    return first


def list_users() -> int:
    users = User.query.order_by(User.id).all()
    if not users:
        print("No users. Run without --list to create the first admin.")
        return 0
    print(f"{len(users)} user(s):")
    for u in users:
        flags = []
        if not u.is_active:
            flags.append("inactive")
        if u.must_change_password:
            flags.append("must change password")
        suffix = f"  [{', '.join(flags)}]" if flags else ""
        print(f"  {u.id:>3}  {u.username:<24} {u.role}{suffix}")
    return 0


def reset_password(username: str) -> int:
    user = User.query.filter_by(username=username).first()
    if user is None:
        print(f"No such user: {username!r}. Try --list.", file=sys.stderr)
        return 1
    print(f"Rotating the password for {user.username!r} ({user.role}).")
    password = _ask_password("New password")
    if password is None:
        return 1
    user.set_password(password)
    # Make them pick their own on next sign-in: this one was typed by whoever ran the script.
    user.must_change_password = True
    db.session.commit()
    print(f"Password for {user.username!r} rotated; they must change it at next sign-in.")
    return 0


def create_admin() -> int:
    existing = User.query.count()
    if existing:
        print(f"Users already exist ({existing} found); not creating another admin.")
        list_users()
        print("\nTo rotate one of these, use --reset-password NAME.")
        return 1
    print("Creating the first admin account.")
    username = input(f"Username (min {MIN_USERNAME} chars): ").strip()
    if len(username) < MIN_USERNAME:
        print(f"Username must be at least {MIN_USERNAME} characters.", file=sys.stderr)
        return 1
    password = _ask_password()
    if password is None:
        return 1
    admin = User(username=username, role="admin", is_active=True)
    admin.set_password(password)
    admin.must_change_password = False      # they just chose it themselves
    db.session.add(admin)
    db.session.commit()
    print(f"Admin {username!r} created.")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    g = p.add_mutually_exclusive_group()
    g.add_argument("--list", action="store_true", help="list the existing users and exit")
    g.add_argument("--reset-password", metavar="USERNAME", help="rotate one user's password")
    args = p.parse_args()

    app = create_app()
    with app.app_context():
        uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
        # Say which database, without the credentials in a postgres URL.
        shown = uri.split("@")[-1] if "@" in uri else uri
        print(f"database: {shown}")
        if args.list:
            return list_users()
        if args.reset_password:
            return reset_password(args.reset_password)
        return create_admin()


if __name__ == "__main__":
    sys.exit(main())
