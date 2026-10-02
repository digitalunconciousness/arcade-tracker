"""Security middleware: rate limiting and logging setup.

**Nothing calls init_security().** It is kept because the security logging and the
per-endpoint rate limiting in it are wanted eventually, but do not simply wire it up:
``app.config.from_object(SecurityConfig)`` would also apply three settings that
contradict what ``app/__init__.py`` deliberately sets, and one of them takes the site
down for anyone on the LAN.

  SESSION_COOKIE_SECURE = True        the site is reachable over plain HTTP on the LAN
                                      (192.168.x:5000). A secure-only session cookie is
                                      never sent over HTTP, so nobody can log in there.
  MAX_CONTENT_LENGTH = 16 MB          the application allows 50 MB; maintenance photos
  PERMANENT_SESSION_LIFETIME = 30 min the application uses 30 days

It would also register a second Flask-Limiter against the same app, alongside the one
in app/extensions.

Adopting this module means reconciling those settings first, deciding whether loopback
and LAN should differ, and testing a login over HTTP on the LAN afterwards. It is a
piece of work, not a one-line call.

The Content-Security-Policy that used to live here has been removed: it was dead (this
after_request was never registered) and it allowed cdn.jsdelivr.net. There is now one
policy, in app/__init__.py, and it allows no external origin at all.
"""

from flask import Flask, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


def init_security(app: Flask) -> Limiter:
    """Initialise security middleware and rate limiting.

    * Applies :class:`~app.security.config.SecurityConfig` to the app.
    * Sets up rotating security log via
      :func:`~app.security.utils.setup_security_logging`.
    * Creates and returns a :class:`~flask_limiter.Limiter` instance.
    * Registers an ``after_request`` handler that adds common security
      headers to every response.

    Args:
        app: Flask application instance.

    Returns:
        The configured :class:`Limiter`.
    """
    # Apply security configuration
    from app.security.config import SecurityConfig

    app.config.from_object(SecurityConfig)

    # Setup security logging
    from app.security.utils import setup_security_logging

    log_file = app.config.get("SECURITY_LOG_FILE", "logs/security.log")
    setup_security_logging(app, log_file)

    # Initialise rate limiter
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["1000 per day", "200 per hour"],
        storage_uri="memory://",
        default_limits_exempt_when=lambda: request.path.startswith(
            "/skeeball/api/"
        ),
    )

    app.logger.info(
        "✅ Security middleware and rate limiting initialized."
    )

    return limiter
