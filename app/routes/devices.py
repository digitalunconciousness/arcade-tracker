"""GATBOX devices: which machines each may use, and whether it may call in at all (the device
allow-list, owner's decisions 2026-10-26). Admin only.

Minting a token stays in ``scripts/create_device.py``: a token is shown once, and a terminal on
the server is a better place for that than a browser.
"""
from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.models import Device, Game
from app.security.utils import log_security_event
from app.utils.decorators import requires_role

devices_bp = Blueprint("devices", __name__, url_prefix="/admin/devices")


@devices_bp.route("/")
@login_required
@requires_role("admin")
def overview():
    return render_template("devices.html",
                           devices=Device.query.order_by(Device.name).all())


@devices_bp.route("/<int:device_id>", methods=["GET", "POST"])
@login_required
@requires_role("admin")
def edit(device_id):
    device = db.get_or_404(Device, device_id)
    games = (Game.query.filter(Game.barcode.isnot(None)).order_by(Game.location, Game.name)
             .all())
    if request.method == "POST":
        all_machines = request.form.get("scope") != "list"
        wanted = set(request.form.getlist("machines"))
        chosen = [g for g in games if str(g.id) in wanted]
        if not all_machines and not chosen:
            flash("Tick at least one machine, or allow all of them. To stop the device "
                  "altogether, untick Enabled.", "error")
            return render_template("device_form.html", device=device, games=games,
                                   chosen={g.id for g in chosen}, all_machines=all_machines,
                                   enabled=request.form.get("enabled") == "1"), 400
        device.all_machines = all_machines
        device.machines = [] if all_machines else chosen
        device.enabled = request.form.get("enabled") == "1"
        device.notes = (request.form.get("notes") or "").strip() or None
        scope = "all machines" if all_machines else f"{len(chosen)} machine(s)"
        log_security_event("DEVICE_SCOPE_CHANGED", user_id=current_user.id,
                           details=f"Device {device.name} ({device.public_id}): {scope}, "
                                   f"{'enabled' if device.enabled else 'disabled'}",
                           level="warning")
        db.session.commit()
        flash(f'Saved "{device.name}": {scope}, '
              f'{"enabled" if device.enabled else "turned off"}.', "success")
        return redirect(url_for("devices.overview"))
    return render_template("device_form.html", device=device, games=games,
                           chosen={g.id for g in device.machines},
                           all_machines=device.all_machines, enabled=device.enabled)
