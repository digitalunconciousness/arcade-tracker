"""User accounts: roles, one-time passwords, and the changes an admin may not make."""
from __future__ import annotations

import secrets

from app.extensions import db
from app.models import InventoryRequest, InventoryRequestHistory, StockHistory, User, WorkLog
from app.security.utils import check_password_strength

ROLES = ("readonly", "operator", "manager", "admin")
ROLE_TEXT = {
    "readonly": "Read only: sees machines, work orders and rail history",
    "operator": "Operator: reports and works on orders, records plays, uses parts",
    "manager": "Manager: also reports, revenue, part orders, coin-door labels",
    "admin": "Admin: also users, storage and backups",
}

# No 0/O, 1/l/I: a one-time password is read off a screen and typed on a phone.
_UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
_LOWER = "abcdefghijkmnpqrstuvwxyz"
_DIGIT = "23456789"


def one_time_password() -> str:
    """A random password that meets the strength rule, grouped for reading aloud.

    Replaces the fixed "Arcade123!" every reset used to set (F-19). The user must change it
    at their next sign-in, and is held on the change-password page until they do (F-41).
    """
    alphabet = _UPPER + _LOWER + _DIGIT
    while True:
        raw = "".join(secrets.choice(alphabet) for _ in range(12))
        if check_password_strength(raw)[0]:
            return f"{raw[:4]}-{raw[4:8]}-{raw[8:]}"


def history_count(user: User) -> int:
    """Rows that name this user. A user with any cannot be deleted: PostgreSQL refuses the
    delete (their foreign keys are NOT NULL), and the history would lose who did the work."""
    return sum(model.query.filter_by(**{column: user.id}).count() for model, column in (
        (WorkLog, "user_id"),
        (StockHistory, "user_id"),
        (InventoryRequest, "requested_by_id"),
        (InventoryRequestHistory, "user_id"),
    ))


def refusal(actor: User, target: User, action: str, new_role: str | None = None) -> str | None:
    """Why *actor* may not do *action* to *target*, or None.

    Nobody can lock the tracker out of its own admin pages (F-40): an admin cannot demote,
    deactivate or delete themselves. That is enough: only an active admin can act, so the
    one acting is always an admin who remains.
    """
    if action == "change_role":
        if new_role not in ROLES:
            return "Pick a role from the list."
        if new_role == target.role:
            return f"{target.username} is already {new_role}."
        if target.id == actor.id:
            return "You can't change your own role. Ask another admin."
    elif action == "toggle_active":
        if target.id == actor.id:
            return "You can't deactivate your own account."
    elif action == "delete_user":
        if target.id == actor.id:
            return "You cannot delete your own account."
        if history_count(target):
            return (f"{target.username} has work on record, so the account stays for that "
                    "history. Deactivate it instead.")
    elif action != "reset_password":
        return "Unknown action."
    return None


def validate_new_user(username: str, password: str, role: str) -> dict[str, str]:
    """Field errors for a new account (empty when it is fine). A blank password is allowed:
    the caller then makes a one-time password."""
    errors: dict[str, str] = {}
    if len(username) < 3:
        errors["username"] = "Use at least 3 characters."
    elif len(username) > 80:
        errors["username"] = "Use at most 80 characters."
    elif User.query.filter(User.username.ilike(username)).first():
        errors["username"] = "That username is taken."
    if password:
        strong, why = check_password_strength(password)
        if not strong:
            errors["password"] = why + "."
    if role not in ROLES:
        errors["role"] = "Pick a role from the list."
    return errors


def create_user(username: str, password: str, role: str) -> tuple[User, str | None]:
    """Make the account. Returns (user, one-time password if one was generated). The user
    must change the password at first sign-in either way. Caller commits."""
    generated = None if password else one_time_password()
    user = User(username=username, role=role, is_active=True, must_change_password=True)
    user.set_password(password or generated)
    db.session.add(user)
    return user, generated
