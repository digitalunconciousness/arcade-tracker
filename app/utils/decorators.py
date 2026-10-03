"""Custom route decorators: role-based access for people, token auth for machines."""

from functools import wraps

from flask import flash, g, jsonify, redirect, request, url_for
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


def requires_device(f):
    """Authenticate a machine client by bearer token, and answer in JSON.

    Usage::

        @api_v1_bp.route("/ingest", methods=["POST"])
        @requires_device
        def ingest():
            g.device        # the authenticated Device

    **Never stack this with @login_required.** That decorator redirects an unauthenticated
    caller to the login page, because ``login_manager.login_view`` is set and there is no
    ``unauthorized_handler`` -- so a machine client would get a 302 and an HTML login form
    where it expected a 401 and JSON. This decorator is the whole check.

    The token is ``gbx_<public_id>.<secret>``. The public id is the indexed lookup key; the
    secret is verified against a hash, which is why it cannot itself be the key. Every
    failure gets the same message: telling a caller whether the device existed, was
    disabled, or had the wrong secret only helps someone guessing.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        from app.models import Device
        from app.security.utils import get_client_ip, log_security_event

        def refuse(why: str):
            log_security_event(
                "DEVICE_AUTH_FAILED",
                details=f"{why}; Path: {request.path}; IP: {get_client_ip()}",
                level="warning",
            )
            return jsonify({"error": "a valid device token is required"}), 401

        header = request.headers.get("Authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            return refuse("no bearer token")

        parts = Device.split_token(token.strip())
        if parts is None:
            return refuse("malformed token")
        public_id, secret = parts

        device = Device.query.filter_by(public_id=public_id).first()
        if device is None:
            return refuse(f"no device with public id {public_id!r}")
        if not device.enabled:
            return refuse(f"device {device.name!r} is disabled")
        if not device.check_secret(secret):
            return refuse(f"wrong secret for device {device.name!r}")

        g.device = device
        return f(*args, **kwargs)

    return decorated_function


def device_rate_key() -> str:
    """Rate-limit bucket for a device request.

    Keyed on the presented public id rather than the address, because there is no
    ProxyFix in front of this application: everything arriving through the Cloudflare
    tunnel shares one remote address, so an address-keyed limit would put every remote
    caller in one bucket.

    This is a **quota, not a security boundary.** The key comes from an unverified header,
    so somebody varying it gets fresh buckets. Brute force is caught by the
    DEVICE_AUTH_FAILED log, not by this.
    """
    from app.models import Device

    header = request.headers.get("Authorization", "")
    _, _, token = header.partition(" ")
    parts = Device.split_token(token.strip())
    if parts is None:
        return f"anon:{request.remote_addr}"
    return f"device:{parts[0]}"
