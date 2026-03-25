"""Arcade Tracker application package.

Provides the :func:`create_app` factory used to build and configure the
Flask application instance.
"""

from __future__ import annotations

import os
import uuid

from dotenv import load_dotenv
from flask import Flask, Response

from app.extensions import csrf, db, limiter, login_manager, migrate


def create_app() -> Flask:
    """Create and configure the Flask application.

    * Loads environment from ``.env``
    * Configures database, uploads, sessions, and security
    * Initialises extensions and registers blueprints
    * Adds security headers via ``after_request``

    Returns:
        A fully-configured :class:`~flask.Flask` instance.
    """
    load_dotenv()

    app = Flask(
        __name__,
        instance_relative_config=False,
        template_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates"),
        static_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "static"),
    )

    _configure_app(app)
    _create_directories(app)
    _init_extensions(app)
    _register_blueprints(app)
    _register_context_processors(app)
    _register_after_request(app)

    return app


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------

def _configure_app(app: Flask) -> None:
    """Apply all configuration values to *app*."""
    base_dir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    instance_folder = os.path.join(base_dir, "instance")

    # Secret key ---------------------------------------------------
    secret_key = os.environ.get("SECRET_KEY")
    if not secret_key or secret_key == "your-secret-key-change-this-for-production":
        print("WARNING: Using temporary SECRET_KEY. Set SECRET_KEY environment variable!")
        secret_key = "dev-secret-key-" + str(uuid.uuid4())
    app.config["SECRET_KEY"] = secret_key

    # Database -----------------------------------------------------
    db_path = os.path.join(instance_folder, "arcade.db")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{db_path}",
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Uploads ------------------------------------------------------
    app.config["UPLOAD_FOLDER"] = os.path.join(base_dir, "uploads")
    app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB

    # CSRF ---------------------------------------------------------
    app.config["WTF_CSRF_CHECK_DEFAULT"] = False

    # Session / Remember-me ----------------------------------------
    import datetime as dt

    app.config["REMEMBER_COOKIE_DURATION"] = dt.timedelta(days=30)
    app.config["PERMANENT_SESSION_LIFETIME"] = dt.timedelta(days=30)
    app.config["REMEMBER_COOKIE_SECURE"] = False
    app.config["REMEMBER_COOKIE_HTTPONLY"] = True
    app.config["REMEMBER_COOKIE_REFRESH_EACH_REQUEST"] = False
    app.config["SESSION_COOKIE_SECURE"] = False
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


def _create_directories(app: Flask) -> None:
    """Ensure all required directories exist."""
    base_dir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    directories = [
        os.path.join(base_dir, "instance"),
        app.config["UPLOAD_FOLDER"],
        os.path.join(base_dir, "backups"),
        os.path.join(base_dir, "logs"),
        os.path.join(base_dir, "static", "maintenance_photos"),
        os.path.join(base_dir, "static", "profile_pics"),
    ]
    for directory in directories:
        os.makedirs(directory, exist_ok=True)


def _init_extensions(app: Flask) -> None:
    """Bind all Flask extensions to *app*."""
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # Import models so that SQLAlchemy is aware of them
    from app import models as _models  # noqa: F401

    @login_manager.user_loader
    def load_user(user_id: str):  # noqa: ANN202
        from app.models import User

        return db.session.get(User, int(user_id))


def _register_blueprints(app: Flask) -> None:
    """Import and register all application blueprints."""
    blueprint_imports: list[tuple[str, str]] = [
        ("app.routes.auth", "auth_bp"),
        ("app.routes.dashboard", "dashboard_bp"),
        ("app.routes.games", "games_bp"),
        ("app.routes.maintenance", "maintenance_bp"),
        ("app.routes.inventory", "inventory_bp"),
        ("app.routes.reports", "reports_bp"),
        ("app.routes.admin", "admin_bp"),
        ("app.routes.skeeball", "skeeball_bp"),
    ]

    import importlib

    for module_path, bp_name in blueprint_imports:
        try:
            mod = importlib.import_module(module_path)
            bp = getattr(mod, bp_name, None)
            if bp is not None:
                app.register_blueprint(bp)
        except ImportError as exc:
            print(f"⚠️  Blueprint {module_path} not available: {exc}")


def _register_context_processors(app: Flask) -> None:
    """Register Jinja2 context processors for global template helpers."""
    from datetime import date as _date
    from flask import url_for as _url_for

    @app.context_processor
    def utility_processor() -> dict:
        def get_cloud_url(filename: str) -> str:
            """Return a cloud or local URL for a maintenance photo."""
            use_cloud = app.config.get("USE_CLOUD_STORAGE", False)
            bucket = app.config.get("AWS_BUCKET_NAME", "")
            region = app.config.get("AWS_REGION", "us-east-1")
            if use_cloud and bucket:
                return (
                    f"https://{bucket}.s3.{region}.amazonaws.com/"
                    f"maintenance_photos/{filename}"
                )
            return _url_for("static", filename=f"maintenance_photos/{filename}")

        return {"today": _date.today, "get_cloud_url": get_cloud_url}


def _register_after_request(app: Flask) -> None:
    """Add security headers to every response."""

    @app.after_request
    def add_security_headers(response: Response) -> Response:
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response
