"""Admin blueprint — user management, storage, backups."""

import os
import sys
import glob as glob_mod

from datetime import datetime

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import current_user, login_required

from app.extensions import db
from app.models import MaintenanceRecord, User
from app.security.utils import log_security_event
from app.utils.decorators import requires_role
from app.utils.helpers import cleanup_old_photos, get_directory_size

admin_bp = Blueprint("admin", __name__)

MAX_TOTAL_STORAGE_MB = 500


def _users_page(revealed=None, status=200):
    from app.services.accounts import ROLE_TEXT, ROLES, history_count

    users = User.query.order_by(User.is_active.desc(), User.username.asc()).all()
    return render_template(
        "manage_users.html", users=users, roles=ROLES, role_text=ROLE_TEXT,
        history={u.id: history_count(u) for u in users}, revealed=revealed,
    ), status


@admin_bp.route("/admin/users", methods=["GET", "POST"])
@login_required
@requires_role("admin")
def manage_users():
    """Accounts: roles, active or not, password resets, deletes."""
    from app.services.accounts import one_time_password, refusal

    if request.method == "GET":
        return _users_page()

    action = request.form.get("action")
    user = db.get_or_404(User, request.form.get("user_id", type=int))
    new_role = request.form.get("new_role")
    why_not = refusal(current_user, user, action, new_role)
    if why_not:
        flash(why_not, "error")
        return redirect(url_for("admin.manage_users"))

    if action == "toggle_active":
        user.is_active = not user.is_active
        db.session.commit()
        state = "activated" if user.is_active else "deactivated"
        log_security_event("USER_ACCOUNT_TOGGLED", user_id=current_user.id,
                           details=f"Target user: {user.username} (id={user.id}), state: {state}",
                           level="warning")
        flash(f"{user.username} is {state}.", "success")

    elif action == "reset_password":
        password = one_time_password()
        user.set_password(password)
        user.must_change_password = True
        db.session.commit()
        log_security_event("USER_PASSWORD_RESET", user_id=current_user.id,
                           details=f"Target user: {user.username} (id={user.id})",
                           level="warning")
        # Shown once, in this response only: never in a flash message, which would put it in
        # the session cookie, and never in a log (F-19).
        return _users_page(revealed=(user, password))

    elif action == "change_role":
        old_role = user.role
        user.role = new_role
        db.session.commit()
        log_security_event("USER_ROLE_CHANGED", user_id=current_user.id,
                           details=f"Target user: {user.username} (id={user.id}), "
                                   f"{old_role} → {new_role}",
                           level="warning")
        flash(f"{user.username} is now {new_role}.", "success")

    elif action == "delete_user":
        log_security_event("USER_DELETED", user_id=current_user.id,
                           details=f"Target user: {user.username} (id={user.id})",
                           level="warning")
        db.session.delete(user)
        db.session.commit()
        flash(f"Deleted {user.username}.", "success")

    return redirect(url_for("admin.manage_users"))


@admin_bp.route("/admin/create_user", methods=["GET", "POST"])
@login_required
@requires_role("admin")
def create_user():
    """Add an account. Leave the password blank to have a one-time one made and shown once."""
    from app.services.accounts import ROLE_TEXT, ROLES, create_user as make_user
    from app.services.accounts import validate_new_user

    values = {"role": "operator"}
    errors: dict[str, str] = {}
    if request.method == "POST":
        values = {"username": request.form.get("username", "").strip(),
                  "role": request.form.get("role", "")}
        password = request.form.get("password", "")
        errors = validate_new_user(values["username"], password, values["role"])
        if not errors:
            user, generated = make_user(values["username"], password, values["role"])
            db.session.commit()
            log_security_event("USER_CREATED", user_id=current_user.id,
                               details=f"Created user: {user.username} with role: {user.role}")
            if generated:
                return _users_page(revealed=(user, generated))
            flash(f"Added {user.username}. They choose a new password at first sign-in.",
                  "success")
            return redirect(url_for("admin.manage_users"))
    return render_template("create_user.html", values=values, errors=errors, roles=ROLES,
                           role_text=ROLE_TEXT), (400 if errors else 200)


@admin_bp.route("/admin/storage")
@login_required
@requires_role("admin")
def storage_admin():
    """Storage management dashboard."""
    upload_dir = os.path.join(current_app.root_path, "..", "static", "maintenance_photos")
    upload_dir = os.path.normpath(upload_dir)

    current_size_mb = get_directory_size(upload_dir)
    file_count = len(os.listdir(upload_dir)) if os.path.exists(upload_dir) else 0

    total_records = MaintenanceRecord.query.count()
    records_with_photos = MaintenanceRecord.query.filter(
        MaintenanceRecord.photos.isnot(None)
    ).count()

    stats = {
        "current_size_mb": current_size_mb,
        "max_size_mb": MAX_TOTAL_STORAGE_MB,
        "usage_percent": (current_size_mb / MAX_TOTAL_STORAGE_MB) * 100,
        "file_count": file_count,
        "total_records": total_records,
        "records_with_photos": records_with_photos,
    }

    return render_template("storage_admin.html", stats=stats)


@admin_bp.route("/admin/cleanup_photos", methods=["POST"])
@login_required
@requires_role("manager")
def admin_cleanup_photos():
    """Clean up old/orphaned photos."""
    try:
        removed_count = cleanup_old_photos(max_age_days=365)
        upload_dir = os.path.join(current_app.root_path, "..", "static", "maintenance_photos")
        upload_dir = os.path.normpath(upload_dir)
        current_size_mb = get_directory_size(upload_dir)
        flash(
            f"Cleanup complete: {removed_count} photos removed. Current storage: {current_size_mb:.1f}MB",
            "success",
        )
    except Exception as e:
        flash(f"Cleanup failed: {str(e)}", "error")

    return redirect(request.referrer or url_for("dashboard.home"))


@admin_bp.route("/backup_management")
@login_required
@requires_role("admin")
def backup_management():
    """Database backup and restore management interface."""
    backup_dir = "backups"
    backups = []

    if os.path.exists(backup_dir):
        backup_files = glob_mod.glob(os.path.join(backup_dir, "arcade_backup_*.db"))
        for backup_file in backup_files:
            file_size = os.path.getsize(backup_file)
            file_time = datetime.fromtimestamp(os.path.getmtime(backup_file))
            days_ago = (datetime.now() - file_time).days
            backups.append(
                {
                    "filename": os.path.basename(backup_file),
                    "filepath": backup_file,
                    "size": file_size,
                    "created": file_time,
                    "days_ago": days_ago,
                }
            )

    backups.sort(key=lambda x: x["created"], reverse=True)
    return render_template("backup_management.html", backups=backups)


@admin_bp.route("/create_backup", methods=["POST"])
@login_required
@requires_role("admin")
def create_backup():
    """Create a new database backup."""
    import subprocess

    try:
        script_path = os.path.join("scripts", "backup_database.py")
        result = subprocess.run(
            [sys.executable, script_path, "backup"],
            capture_output=True,
            text=True,
            cwd=os.getcwd(),
        )

        if result.returncode == 0:
            flash("Database backup created successfully!", "success")
        else:
            flash(f"Backup failed: {result.stderr}", "error")
    except Exception as e:
        flash(f"Error creating backup: {str(e)}", "error")

    return redirect(url_for("admin.backup_management"))


@admin_bp.route("/restore_backup", methods=["POST"])
@login_required
@requires_role("admin")
def restore_backup():
    """Restore database from backup."""
    import subprocess

    backup_file = request.form.get("backup_file")
    if not backup_file:
        flash("No backup file specified", "error")
        return redirect(url_for("admin.backup_management"))

    backup_path = os.path.join("backups", backup_file)
    if not os.path.exists(backup_path):
        flash("Backup file not found", "error")
        return redirect(url_for("admin.backup_management"))

    try:
        script_path = os.path.join("scripts", "restore_database.py")
        result = subprocess.run(
            [sys.executable, script_path, "--backup-file", backup_path],
            capture_output=True,
            text=True,
            cwd=os.getcwd(),
        )

        if result.returncode == 0:
            flash("Database restored successfully! Please restart the application.", "success")
        else:
            flash(f"Restore failed: {result.stderr}", "error")
    except Exception as e:
        flash(f"Error restoring backup: {str(e)}", "error")

    return redirect(url_for("admin.backup_management"))


@admin_bp.route("/download_backup/<filename>")
@login_required
@requires_role("admin")
def download_backup(filename):
    """Download a backup file."""
    backup_path = os.path.join("backups", filename)

    if not os.path.exists(backup_path) or not filename.startswith("arcade_backup_"):
        flash("Backup file not found", "error")
        return redirect(url_for("admin.backup_management"))

    return send_file(backup_path, as_attachment=True, download_name=filename)


@admin_bp.route("/delete_backup", methods=["POST"])
@login_required
@requires_role("admin")
def delete_backup():
    """Delete a backup file."""
    backup_dir = "backups"
    backup_file = request.form.get("backup_file")
    if not backup_file:
        flash("No backup file specified.", "danger")
        return redirect(url_for("admin.backup_management"))

    backup_path = os.path.join(backup_dir, backup_file)
    if os.path.exists(backup_path):
        os.remove(backup_path)
        flash(f"Backup {backup_file} deleted successfully.", "success")
    else:
        flash("Backup file not found.", "warning")

    return redirect(url_for("admin.backup_management"))
