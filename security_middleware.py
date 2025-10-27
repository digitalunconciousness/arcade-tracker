# security_middleware.py
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

def init_security(app):
    """
    Initialize security middleware and rate limiting.
    
    Args:
        app: Flask application instance
    
    Returns:
        Limiter: Flask-Limiter instance
    """
    # Apply security configuration
    app.config.from_object('security_config.SecurityConfig')
    
    # Setup security logging - pass the app object and log file path
    from security_utils import setup_security_logging
    log_file = app.config.get('SECURITY_LOG_FILE', 'logs/security.log')
    setup_security_logging(app, log_file)
    
    # Initialize rate limiter
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://"
    )
    
    # Add security headers middleware
    @app.after_request
    def add_security_headers(response):
        """Add security headers to all responses."""
        # Prevent clickjacking
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        
        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        
        # Enable XSS protection (for older browsers)
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Strict transport security (HTTPS only)
        # Uncomment when using HTTPS in production
        # response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        # Content Security Policy
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://cdn.jsdelivr.net;"
        )
        
        return response
    
    app.logger.info("✅ Security middleware and rate limiting initialized.")
    
    return limiter