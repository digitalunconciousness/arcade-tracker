"""Security utilities for logging, request validation, and file/path safety."""

import logging
import os
from datetime import datetime, timedelta

from flask import request

# -------------------------------------------------------------
# 🔐 FAILED LOGIN TRACKING
# -------------------------------------------------------------
failed_login_attempts = {}  # {username_or_ip: [timestamp, timestamp, ...]}
LOCKOUT_THRESHOLD = 5  # Number of failed attempts before lockout
LOCKOUT_DURATION = 900  # 15 minutes in seconds


def log_security_event(event_type, user_id=None, details="", level="info"):
    """Record a security event: one ``event=<TYPE>`` line on the ``arcade.security`` logger.

    Until Step 5.5 these went to a logger with no level, which kept warnings only, so every
    info-level event (LOGIN_SUCCESS, LOGIN_FAILED, BACKUP_CREATED ...) was dropped (F-23).

    Args:
        event_type: what happened, e.g. ``'LOGIN_SUCCESS'``.
        user_id: the user involved, if any.
        details: free text; never a password or token.
        level: ``'info'``, ``'warning'`` or ``'error'``.
    """
    logging.getLogger("arcade.security").log(
        getattr(logging, level.upper(), logging.INFO),
        "%s: %s" if details else "%s", event_type, *([details] if details else []),
        extra={"fields": {
            "event": event_type,
            "user_id": user_id or "-",
            "ip": get_client_ip(),
            "agent": request.headers.get("User-Agent", "-")[:200],
        }},
    )


def get_client_ip() -> str:
    """The visitor's address. See :func:`app.security.https.client_ip` for what is trusted."""
    from app.security.https import client_ip

    return client_ip()


def record_failed_login(username, ip=None):
    """Record a failed login attempt.

    Args:
        username: Username that failed to login.
        ip: IP address of the attempt (optional).

    Returns:
        ``True`` if account is now locked, ``False`` otherwise.
    """
    if ip is None:
        ip = get_client_ip()

    key = f"{username}:{ip}"
    current_time = datetime.now()

    if key not in failed_login_attempts:
        failed_login_attempts[key] = []

    failed_login_attempts[key].append(current_time)

    # Remove attempts older than lockout duration
    cutoff_time = current_time - timedelta(seconds=LOCKOUT_DURATION)
    failed_login_attempts[key] = [
        attempt
        for attempt in failed_login_attempts[key]
        if attempt > cutoff_time
    ]

    return len(failed_login_attempts[key]) >= LOCKOUT_THRESHOLD


def is_account_locked(username, ip=None):
    """Check if an account is currently locked due to failed login attempts.

    Args:
        username: Username to check.
        ip: IP address to check (optional).

    Returns:
        ``True`` if account is locked, ``False`` otherwise.
    """
    if ip is None:
        ip = get_client_ip()

    key = f"{username}:{ip}"
    current_time = datetime.now()

    if key not in failed_login_attempts:
        return False

    cutoff_time = current_time - timedelta(seconds=LOCKOUT_DURATION)
    failed_login_attempts[key] = [
        attempt
        for attempt in failed_login_attempts[key]
        if attempt > cutoff_time
    ]

    return len(failed_login_attempts[key]) >= LOCKOUT_THRESHOLD


def clear_failed_login_attempts(username, ip=None):
    """Clear failed login attempts for a user (called after successful login).

    Args:
        username: Username to clear attempts for.
        ip: IP address to clear (optional).
    """
    if ip is None:
        ip = get_client_ip()

    key = f"{username}:{ip}"
    if key in failed_login_attempts:
        del failed_login_attempts[key]


def check_password_strength(password):
    """Check if a password meets minimum security requirements.

    Args:
        password: Password to check.

    Returns:
        A ``(bool, str)`` tuple of ``(is_valid, error_message)``.
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)

    if not (has_upper and has_lower and has_digit):
        return False, "Password must contain uppercase, lowercase, and numbers"

    return True, ""


def safe_path_join(base_path, user_path):
    """Safely join paths to prevent directory traversal attacks.

    Args:
        base_path: Base directory path.
        user_path: User-provided path component.

    Returns:
        Safe joined path, or ``None`` if the result would escape *base_path*.
    """
    base = os.path.abspath(base_path)
    target = os.path.abspath(os.path.join(base, user_path))

    try:
        is_within_base = os.path.commonpath([base, target]) == base
    except ValueError:
        is_within_base = False

    if not is_within_base:
        log_security_event(
            "PATH_TRAVERSAL_ATTEMPT",
            details=f"Attempted path: {user_path}",
        )
        return None

    return target


def validate_file_upload(file, allowed_extensions, max_size_mb=10):
    """Validate an uploaded file.

    Args:
        file: Werkzeug ``FileStorage`` object.
        allowed_extensions: Set of allowed file extensions (e.g., ``{'png', 'jpg'}``).
        max_size_mb: Maximum file size in megabytes.

    Returns:
        A ``(bool, str)`` tuple of ``(is_valid, error_message)``.
    """
    if not file or not file.filename:
        return False, "No file provided"

    if "." not in file.filename:
        return False, "File has no extension"

    ext = file.filename.rsplit(".", 1)[1].lower()
    if ext not in allowed_extensions:
        return False, (
            f"File type .{ext} not allowed. "
            f"Allowed: {', '.join(allowed_extensions)}"
        )

    file.seek(0, os.SEEK_END)
    size_mb = file.tell() / (1024 * 1024)
    file.seek(0)

    if size_mb > max_size_mb:
        return False, (
            f"File too large ({size_mb:.1f}MB). Maximum: {max_size_mb}MB"
        )

    return True, ""


def sanitize_filename(filename):
    """Sanitize a filename to prevent security issues.

    Args:
        filename: Original filename.

    Returns:
        Sanitized filename.
    """
    from werkzeug.utils import secure_filename

    return secure_filename(filename)


def is_safe_redirect_url(target):
    """Check if a redirect URL is safe (prevents open redirect vulnerabilities).

    Args:
        target: Target URL to redirect to.

    Returns:
        ``True`` if safe, ``False`` otherwise.
    """
    if not target:
        return False

    # Only allow local relative URLs and block protocol-relative URLs.
    if target.startswith("/") and not target.startswith("//"):
        return True

    return False
