"""Flask extension instances.

Singleton extension objects initialized here and bound to the app
in the factory function via ``init_app()``.
"""

from flask_limiter import Limiter
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

from app.security.https import client_ip

db: SQLAlchemy = SQLAlchemy()
migrate: Migrate = Migrate()
login_manager: LoginManager = LoginManager()
csrf: CSRFProtect = CSRFProtect()
# Keyed on the real visitor (F-23), not the connecting address: through the tunnel that is
# 127.0.0.1 for everyone. The default is an abuse ceiling, not a security boundary -- a whole
# arcade shares one public address, and a collection round alone is a few hundred pages.
# Logins have their own, much tighter limit (app/routes/auth.py).
limiter: Limiter = Limiter(
    key_func=client_ip,
    default_limits=["5000 per hour"],
    storage_uri="memory://",
)

# LoginManager configuration
login_manager.login_view = "auth.login"
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "info"
login_manager.session_protection = None  # Disable strict protection for remember-me
