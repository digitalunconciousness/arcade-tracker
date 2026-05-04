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


@admin_bp.route("/admin/users", methods=["GET", "POST"])
@login_required
@requires_role("admin")
def manage_users():
    """Admin user management dashboard."""
    users = User.query.order_by(User.username.asc()).all()

    if request.method == "POST":
        action = request.form.get("action")
        user_id = request.form.get("user_id")
        user = User.query.get_or_404(user_id)

        if action == "toggle_active":
            user.is_active = not user.is_active
            db.session.commit()
            new_state = "activated" if user.is_active else "deactivated"
            log_security_event(
                "USER_ACCOUNT_TOGGLED",
                user_id=current_user.id,
                details=f"Target user: {user.username} (id={user.id}), state: {new_state}",
                level="warning",
            )
            flash(f"User {user.username} has been {new_state}.", "info")

        elif action == "reset_password":
            new_password = "Arcade123!"
            user.set_password(new_password)
            user.must_change_password = True
            db.session.commit()
            log_security_event(
                "USER_PASSWORD_RESET",
                user_id=current_user.id,
                details=f"Target user: {user.username} (id={user.id})",
                level="warning",
            )
            flash(
                f'Password for {user.username} reset to "{new_password}" (user must change on next login).',
                "warning",
            )

        elif action == "change_role":
            new_role = request.form.get("new_role")
            if new_role in ["readonly", "operator", "manager", "admin"]:
                old_role = user.role
                user.role = new_role
                db.session.commit()
                log_security_event(
                    "USER_ROLE_CHANGED",
                    user_id=current_user.id,
                    details=f"Target user: {user.username} (id={user.id}), {old_role} → {new_role}",
                    level="warning",
                )
                flash(f"{user.username} role changed to {new_role}.", "success")
            else:
                flash("Invalid role selected.", "error")

        elif action == "delete_user":
            if user.id == current_user.id:
                flash("You cannot delete your own account.", "error")
            else:
                log_security_event(
                    "USER_DELETED",
                    user_id=current_user.id,
                    details=f"Target user: {user.username} (id={user.id})",
                    level="warning",
                )
                db.session.delete(user)
                db.session.commit()
                flash(f"User {user.username} deleted.", "warning")

        return redirect(url_for("admin.manage_users"))

    return render_template("manage_users.html", users=users)


@admin_bp.route("/admin/create_user", methods=["GET", "POST"])
@login_required
@requires_role("admin")
def create_user():
    """Create a new user."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password")
        role = request.form.get("role", "readonly")

        if not username or len(username) < 3:
            flash("Username must be at least 3 characters long.", "error")
            return render_template("create_user.html")

        if not password or len(password) < 6:
            flash("Password must be at least 6 characters long.", "error")
            return render_template("create_user.html")

        existing_user = User.query.filter(User.username.ilike(username)).first()
        if existing_user:
            flash("Username already exists.", "error")
            return render_template("create_user.html")

        if role not in ["readonly", "operator", "manager", "admin"]:
            flash("Invalid role selected.", "error")
            return render_template("create_user.html")

        new_user = User(
            username=username,
            role=role,
            is_active=True,
            must_change_password=True,
        )
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        log_security_event(
            "USER_CREATED",
            user_id=current_user.id,
            details=f"Created user: {username} with role: {role}",
        )

        flash(
            f'User "{username}" created successfully! They will be prompted to change their password on first login.',
            "success",
        )
        return redirect(url_for("admin.manage_users"))

    return render_template("create_user.html")


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
