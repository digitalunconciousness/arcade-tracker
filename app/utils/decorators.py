"""Custom route decorators for role-based access control."""

from functools import wraps

from flask import flash, redirect, request, url_for
from flask_login import current_user


def requires_role(role: str):
    """Restrict access to users with the specified role or higher.

    Usage::

        @app.route('/admin')
        @login_required
        @requires_role('admin')
        def admin_panel():
            ...

    The wrapped view will redirect unauthenticated users to the login
    page and flash an error for authenticated users who lack the
    required role. Unauthorized access attempts are logged as security
    events.
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for("auth.login"))
            if not current_user.has_role(role):
                from app.security.utils import log_security_event
                log_security_event(
                    "UNAUTHORIZED_ACCESS",
                    user_id=current_user.id,
                    details=(
                        f"Required role: {role}, "
                        f"User role: {current_user.role}, "
                        f"Path: {request.path}"
                    ),
                    level="warning",
                )
                flash(
                    "You do not have permission to access this page.",
                    "danger",
                )
                return redirect(url_for("dashboard.home"))
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def admin_required(f):
    """Shorthand decorator that requires the ``admin`` role."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("auth.login"))
        if not current_user.has_role("admin"):
            from app.security.utils import log_security_event
            log_security_event(
                "UNAUTHORIZED_ACCESS",
                user_id=current_user.id,
                details=(
                    f"Required role: admin, "
                    f"User role: {current_user.role}, "
                    f"Path: {request.path}"
                ),
                level="warning",
            )
            flash(
                "You do not have permission to access this page.",
                "danger",
            )
            return redirect(url_for("dashboard.home"))
        return f(*args, **kwargs)

    return decorated_function


def manager_required(f):
    """Shorthand decorator that requires the ``manager`` role or higher."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("auth.login"))
        if not current_user.has_role("manager"):
            from app.security.utils import log_security_event
            log_security_event(
                "UNAUTHORIZED_ACCESS",
                user_id=current_user.id,
                details=(
                    f"Required role: manager, "
                    f"User role: {current_user.role}, "
                    f"Path: {request.path}"
                ),
                level="warning",
            )
            flash(
                "You do not have permission to access this page.",
                "danger",
            )
            return redirect(url_for("dashboard.home"))
        return f(*args, **kwargs)

    return decorated_function
