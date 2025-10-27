# security_utils.py
import logging
import os
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from flask import request
import ipaddress

# -------------------------------------------------------------
# 🔐 FAILED LOGIN TRACKING
# -------------------------------------------------------------
failed_login_attempts = {}  # {username_or_ip: [timestamp, timestamp, ...]}
LOCKOUT_THRESHOLD = 5  # Number of failed attempts before lockout
LOCKOUT_DURATION = 900  # 15 minutes in seconds

def setup_security_logging(app, log_file="logs/security.log"):
    """
    Set up rotating security log handler for the Flask app.
    
    Args:
        app: Flask application instance
        log_file: Path to security log file
    """
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    security_handler = RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5
    )
    security_handler.setLevel(logging.INFO)
    security_handler.setFormatter(logging.Formatter(
        '[%(asctime)s] %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    
    app.logger.addHandler(security_handler)
    app.logger.setLevel(logging.INFO)
    
    return app.logger

def log_security_event(event_type, user_id=None, details="", level="info"):
    """
    Log a security event.
    
    Args:
        event_type: Type of security event (e.g., 'LOGIN_SUCCESS', 'UNAUTHORIZED_ACCESS')
        user_id: ID of user involved (if applicable)
        details: Additional details about the event
        level: Log level ('info', 'warning', 'error')
    """
    from flask import current_app
    
    ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    message = f"[SECURITY] {event_type} | IP: {ip} | User: {user_id or 'Anonymous'} | {details} | Agent: {user_agent}"
    
    if level == "warning":
        current_app.logger.warning(message)
    elif level == "error":
        current_app.logger.error(message)
    else:
        current_app.logger.info(message)

def get_client_ip():
    """Get the real client IP address, considering proxies."""
    if request.headers.get('X-Forwarded-For'):
        # Handle proxy headers
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr or 'Unknown'

def record_failed_login(username, ip=None):
    """
    Record a failed login attempt.
    
    Args:
        username: Username that failed to login
        ip: IP address of the attempt (optional)
    
    Returns:
        bool: True if account is now locked, False otherwise
    """
    if ip is None:
        ip = get_client_ip()
    
    key = f"{username}:{ip}"
    current_time = datetime.now()
    
    if key not in failed_login_attempts:
        failed_login_attempts[key] = []
    
    # Add current attempt
    failed_login_attempts[key].append(current_time)
    
    # Remove attempts older than lockout duration
    cutoff_time = current_time - timedelta(seconds=LOCKOUT_DURATION)
    failed_login_attempts[key] = [
        attempt for attempt in failed_login_attempts[key]
        if attempt > cutoff_time
    ]
    
    # Check if account should be locked
    return len(failed_login_attempts[key]) >= LOCKOUT_THRESHOLD

def is_account_locked(username, ip=None):
    """
    Check if an account is currently locked due to failed login attempts.
    
    Args:
        username: Username to check
        ip: IP address to check (optional)
    
    Returns:
        bool: True if account is locked, False otherwise
    """
    if ip is None:
        ip = get_client_ip()
    
    key = f"{username}:{ip}"
    current_time = datetime.now()
    
    if key not in failed_login_attempts:
        return False
    
    # Remove old attempts
    cutoff_time = current_time - timedelta(seconds=LOCKOUT_DURATION)
    failed_login_attempts[key] = [
        attempt for attempt in failed_login_attempts[key]
        if attempt > cutoff_time
    ]
    
    # Check if still locked
    return len(failed_login_attempts[key]) >= LOCKOUT_THRESHOLD

def clear_failed_login_attempts(username, ip=None):
    """
    Clear failed login attempts for a user (called after successful login).
    
    Args:
        username: Username to clear attempts for
        ip: IP address to clear (optional)
    """
    if ip is None:
        ip = get_client_ip()
    
    key = f"{username}:{ip}"
    if key in failed_login_attempts:
        del failed_login_attempts[key]

def check_password_strength(password):
    """
    Check if a password meets minimum security requirements.
    
    Args:
        password: Password to check
    
    Returns:
        tuple: (bool, str) - (is_valid, error_message)
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
    """
    Safely join paths to prevent directory traversal attacks.
    
    Args:
        base_path: Base directory path
        user_path: User-provided path component
    
    Returns:
        str: Safe joined path or None if unsafe
    """
    # Resolve to absolute paths
    base = os.path.abspath(base_path)
    target = os.path.abspath(os.path.join(base, user_path))
    
    # Ensure target is within base directory
    if not target.startswith(base):
        log_security_event(
            'PATH_TRAVERSAL_ATTEMPT',
            details=f"Attempted path: {user_path}"
        )
        return None
    
    return target

def validate_file_upload(file, allowed_extensions, max_size_mb=10):
    """
    Validate an uploaded file.
    
    Args:
        file: Werkzeug FileStorage object
        allowed_extensions: Set of allowed file extensions (e.g., {'png', 'jpg'})
        max_size_mb: Maximum file size in megabytes
    
    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    if not file or not file.filename:
        return False, "No file provided"
    
    # Check extension
    if '.' not in file.filename:
        return False, "File has no extension"
    
    ext = file.filename.rsplit('.', 1)[1].lower()
    if ext not in allowed_extensions:
        return False, f"File type .{ext} not allowed. Allowed: {', '.join(allowed_extensions)}"
    
    # Check file size (seek to end to get size)
    file.seek(0, os.SEEK_END)
    size_mb = file.tell() / (1024 * 1024)
    file.seek(0)  # Reset to beginning
    
    if size_mb > max_size_mb:
        return False, f"File too large ({size_mb:.1f}MB). Maximum: {max_size_mb}MB"
    
    return True, ""

def sanitize_filename(filename):
    """
    Sanitize a filename to prevent security issues.
    
    Args:
        filename: Original filename
    
    Returns:
        str: Sanitized filename
    """
    from werkzeug.utils import secure_filename
    return secure_filename(filename)

def is_safe_redirect_url(target):
    """
    Check if a redirect URL is safe (prevents open redirect vulnerabilities).
    
    Args:
        target: Target URL to redirect to
    
    Returns:
        bool: True if safe, False otherwise
    """
    if not target:
        return False
    
    # Only allow relative URLs
    if target.startswith('/'):
        return True
    
    return False