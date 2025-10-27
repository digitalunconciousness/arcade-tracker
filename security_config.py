"""
Security Configuration Module
"""

import os
from datetime import timedelta

class SecurityConfig:
    """Security configuration settings"""
    
    # Secret Key - MUST be set via environment variable in production
    SECRET_KEY = os.getenv('SECRET_KEY')
    if not SECRET_KEY:
        if os.getenv('FLASK_ENV') == 'production':
            raise ValueError("SECRET_KEY must be set in production environment!")
        else:
            # Generate a random key for development (will change on restart)
            SECRET_KEY = os.urandom(32).hex()
            print("WARNING: Using temporary SECRET_KEY. Set SECRET_KEY environment variable!")
    
    # Session Configuration
    SESSION_COOKIE_SECURE = True  # Only send cookies over HTTPS
    SESSION_COOKIE_HTTPONLY = True  # Prevent JavaScript access to session cookie
    SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)  # 30-minute timeout
    
    # File Upload Security
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    
    # Security Headers
    SECURITY_HEADERS = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Content-Security-Policy': (
            "default-src 'self'; "
            "script-src 'self' https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://cdnjs.cloudflare.com; "
        ),
    }
    
    # HTTPS/TLS Configuration
    FORCE_HTTPS = os.getenv('FLASK_ENV') == 'production'
