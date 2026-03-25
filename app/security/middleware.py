"""Security middleware: rate limiting, headers, and logging setup."""

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

    # Security headers
    @app.after_request
    def add_security_headers(response):
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://cdn.jsdelivr.net;"
        )
        return response

    app.logger.info(
        "✅ Security middleware and rate limiting initialized."
    )

    return limiter
