"""The arcade's name, logo and sign-in background: the admin page, and serving the files.

See app/services/branding.py. The files are public: the sign-in page and the coin-door form
show them to people who aren't signed in.
"""
from __future__ import annotations

import os

from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from flask_login import login_required

from app.extensions import db
from app.models.alerts import Setting
from app.services import branding as service
from app.utils.decorators import requires_role

branding_bp = Blueprint("branding", __name__)

# An SVG opened on its own is a document, and would run script as this site. sandbox stops
# that whatever the file says; the cleaning on upload is the other half (see the service).
SVG_POLICY = "default-src 'none'; style-src 'unsafe-inline'; sandbox"
WEEK = 7 * 24 * 3600


def _serve(kind: str):
    name = Setting.get(f"{kind}_file")
    if not name or not os.path.exists(os.path.join(service.folder(), name)):
        abort(404)
    resp = send_from_directory(service.folder(), name, max_age=WEEK)
    if name.endswith(".svg"):
        resp.mimetype = "image/svg+xml"
        resp.headers["Content-Security-Policy"] = SVG_POLICY
    return resp


@branding_bp.route("/branding/logo")
def logo():
    return _serve("logo")


@branding_bp.route("/branding/print-logo")
def print_logo():
    return _serve("print_logo")


@branding_bp.route("/branding/background")
def background():
    return _serve("background")


@branding_bp.route("/admin/branding", methods=["GET", "POST"])
@login_required
@requires_role("admin")
def settings():
    if request.method == "POST":
        problems = []
        problem = service.set_name(request.form.get("arcade_name", ""))
        if problem:
            problems.append(problem)
        for kind, save in (("logo", service.save_logo), ("print_logo", service.save_print_logo),
                           ("background", service.save_background)):
            upload = request.files.get(kind)
            if request.form.get(f"remove_{kind}") == "1":
                service.remove(kind)
            elif upload and upload.filename:
                try:
                    save(upload)
                except service.BrandingError as e:
                    problems.append(str(e))
        db.session.commit()
        for p in problems:
            flash(p, "error")
        if not problems:
            flash("Branding saved.", "success")
        return redirect(url_for("branding.settings"))
    return render_template("branding.html", name=Setting.get("arcade_name") or "")
