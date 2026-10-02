"""Security configuration module."""

import os
from datetime import timedelta


class SecurityConfig:
    """Security configuration settings."""

    # Secret Key – MUST be set via environment variable in production
    SECRET_KEY = os.getenv("SECRET_KEY")
    if not SECRET_KEY:
        if os.getenv("FLASK_ENV") == "production":
            raise ValueError(
                "SECRET_KEY must be set in production environment!"
            )
        else:
            SECRET_KEY = os.urandom(32).hex()
            print(
                "WARNING: Using temporary SECRET_KEY. "
                "Set SECRET_KEY environment variable!"
            )

    # Session Configuration
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

    # File Upload Security
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB

    # Security headers are NOT defined here. They are sent from
    # app/__init__.py:_register_after_request, which is the after_request that is
    # actually registered. This class held a second Content-Security-Policy that
    # nothing read -- it allowed cdnjs.cloudflare.com, which this application has
    # never used, and omitted 'unsafe-inline' from script-src, so sending it would
    # have broken every page with an inline handler. Two dead policies naming two
    # different CDNs is how nobody notices the live answer is "no policy at all".
    # Keep one policy, in the place that sends it.

    # HTTPS / TLS Configuration
    FORCE_HTTPS = os.getenv("FLASK_ENV") == "production"
