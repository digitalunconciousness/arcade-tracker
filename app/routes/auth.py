"""Authentication blueprint — login, logout, setup, profile, change password."""

import os
import uuid
import datetime as dt
from datetime import datetime

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

from app.extensions import db
from app.models import User
from app.forms.auth import LoginForm, RegisterForm, ChangePasswordForm, ProfileForm
from app.utils.helpers import allowed_file, compress_and_save_image
from app.security.utils import (
    log_security_event,
    record_failed_login,
    is_account_locked,
    clear_failed_login_attempts,
    get_client_ip,
    check_password_strength,
    is_safe_redirect_url,
)

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.home"))

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()

        # Check if account is locked
        if is_account_locked(username):
            log_security_event(
                "LOGIN_ATTEMPT_LOCKED_ACCOUNT",
                details=f"Username: {username}, IP: {get_client_ip()}",
            )
            flash(
                "Account temporarily locked due to multiple failed login attempts. "
                "Try again in 15 minutes.",
                "error",
            )
            return render_template("login.html", form=form)

        # Case-insensitive username lookup
        user = User.query.filter(User.username.ilike(username)).first()

        if user and user.check_password(form.password.data) and user.is_active:
            # Clear failed login attempts
            clear_failed_login_attempts(username)

            # Update last login
            user.last_login = datetime.now(dt.UTC)
            db.session.commit()

            # Login user with remember me option
            session.permanent = True
            login_user(
                user,
                remember=form.remember.data,
                duration=dt.timedelta(days=30),
            )

            # Log successful login
            log_security_event(
                "LOGIN_SUCCESS",
                user_id=user.id,
                details=f"Username: {username}",
            )

            # Check if user must change password
            if user.must_change_password:
                flash("You must change your password before continuing.", "warning")
                return redirect(url_for("auth.change_password"))

            flash(f"Welcome back, {user.username}!", "success")

            # Validate redirect URL to prevent open redirect
            next_page = request.args.get("next")
            if next_page and not is_safe_redirect_url(next_page):
                next_page = None

            return redirect(next_page) if next_page else redirect(
                url_for("dashboard.home")
            )

        # Record failed login attempt
        is_locked = record_failed_login(username)

        # Log failed login
        log_security_event(
            "LOGIN_FAILED",
            details=f"Username: {username}, IP: {get_client_ip()}",
        )

        if is_locked:
            flash(
                "Too many failed login attempts. Account locked for 15 minutes.",
                "error",
            )
        else:
            flash("Invalid username or password", "error")

    return render_template("login.html", form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    log_security_event(
        "LOGOUT",
        user_id=current_user.id,
        details=f"Username: {current_user.username}",
    )
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/setup", methods=["GET", "POST"])
def setup():
    """First-time setup — only works when no users exist."""
    if User.query.count() > 0:
        flash("Setup has already been completed.", "info")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("setup.html")

        user = User(
            username=username,
            role="admin",
            is_active=True,
            must_change_password=False,
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Admin account created successfully! Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("setup.html")


@auth_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    form = ProfileForm()
    if form.validate_on_submit():
        # Handle profile picture upload
        if form.profile_picture.data:
            file = form.profile_picture.data
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                name_part, ext = os.path.splitext(filename)
                unique_filename = (
                    f"profile_{current_user.id}_{uuid.uuid4().hex[:8]}{ext}"
                )

                from flask import current_app

                upload_dir = os.path.join(
                    current_app.root_path,
                    os.pardir,
                    "static",
                    "profile_pics",
                )
                upload_dir = os.path.abspath(upload_dir)
                os.makedirs(upload_dir, exist_ok=True)
                file_path = os.path.join(upload_dir, unique_filename)

                # Delete old profile picture if it exists
                if current_user.profile_picture:
                    old_path = os.path.join(
                        upload_dir, current_user.profile_picture
                    )
                    if os.path.exists(old_path):
                        try:
                            os.remove(old_path)
                        except OSError:
                            pass

                compress_and_save_image(file, file_path)
                current_user.profile_picture = unique_filename
                db.session.commit()
                flash("Profile picture updated successfully.", "success")
            else:
                flash(
                    "Invalid file type. Please upload PNG, JPG, JPEG, or GIF.",
                    "error",
                )

        return redirect(url_for("auth.profile"))

    return render_template("profile.html", form=form)


@auth_bp.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()

    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash("Current password is incorrect.", "danger")
        else:
            # Check password strength
            is_strong, msg = check_password_strength(form.new_password.data)
            if not is_strong:
                flash(msg, "danger")
            else:
                current_user.set_password(form.new_password.data)
                if current_user.must_change_password:
                    current_user.must_change_password = False
                db.session.commit()
                flash("Your password has been successfully updated.", "success")
                return redirect(url_for("auth.profile"))

    return render_template("change_password.html", form=form)
