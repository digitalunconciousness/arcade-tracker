"""Alert channels, opening hours and the alert log (feature step 6). Admin only: a channel
holds secrets (a Discord webhook address, an ntfy token)."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import login_required

from app.extensions import db
from app.models.alerts import EVENTS, Alert, AlertChannel, Setting
from app.services import alerts as service
from app.utils.decorators import requires_role

alerts_bp = Blueprint("alerts", __name__, url_prefix="/admin/alerts")

TOPIC = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
DISCORD_HOSTS = {"discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com"}


@alerts_bp.route("/")
@login_required
@requires_role("admin")
def overview():
    channels = AlertChannel.query.order_by(AlertChannel.name).all()
    recent = Alert.query.order_by(Alert.created_at.desc(), Alert.id.desc()).limit(50).all()
    waiting = Alert.query.filter(Alert.status.in_(("pending", "held"))).count()
    return render_template("alerts.html", channels=channels, recent=recent, waiting=waiting,
                           events=EVENTS, hours=service.opening_hours(),
                           open_time=Setting.get("open_time") or "",
                           close_time=Setting.get("close_time") or "")


@alerts_bp.route("/hours", methods=["POST"])
@login_required
@requires_role("admin")
def hours():
    opens = (request.form.get("open_time") or "").strip()
    closes = (request.form.get("close_time") or "").strip()
    if bool(opens) != bool(closes) or (opens and (service._hm(opens) is None
                                                  or service._hm(closes) is None)):
        flash("Give both times, like 10:00 and 22:00, or clear both.", "error")
    elif opens and opens == closes:
        flash("Opening and closing can't be the same time.", "error")
    else:
        Setting.put("open_time", opens or None)
        Setting.put("close_time", closes or None)
        db.session.commit()
        flash(f"Open {opens} to {closes}." if opens else
              "No opening hours: alerts always go out straight away, and no daily summary.",
              "success")
    return redirect(url_for("alerts.overview"))


def _check_ntfy(url: str) -> str | None:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return "An ntfy topic address starts with http:// or https://."
    topic = parts.path.rstrip("/").rpartition("/")[2]
    if not TOPIC.match(topic) or parts.query or parts.fragment:
        return "End it with the topic: letters, numbers, - and _ only."
    return None


def _check_discord(url: str) -> str | None:
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in DISCORD_HOSTS \
            or not parts.path.startswith("/api/webhooks/"):
        return "That isn't a Discord webhook address (https://discord.com/api/webhooks/...)."
    return None


def _parse(form, channel: AlertChannel | None):
    errors: dict[str, str] = {}
    v = {"name": (form.get("name") or "").strip(),
         "ntfy_url": (form.get("ntfy_url") or "").strip() or None,
         "events": ",".join(e for e in EVENTS if e in form.getlist("events")),
         "quiet": form.get("quiet") == "1", "active": form.get("active") == "1"}
    if not v["name"] or len(v["name"]) > 60:
        errors["name"] = "Name the channel (60 characters at most), like \"Techs\"."
    if v["ntfy_url"]:
        errors.update({"ntfy_url": m} if (m := _check_ntfy(v["ntfy_url"])) else {})
    # Secrets are never shown back: blank keeps what is saved, "remove" clears it.
    for key, check in (("discord_webhook", _check_discord), ("ntfy_token", None)):
        raw = (form.get(key) or "").strip()
        if form.get(f"remove_{key}") == "1":
            v[key] = None
        elif raw:
            if check and (m := check(raw)):
                errors[key] = m
            v[key] = raw
        else:
            v[key] = getattr(channel, key) if channel else None
    if not v["ntfy_url"] and not v["discord_webhook"]:
        errors.setdefault("ntfy_url", "Give an ntfy topic, a Discord webhook, or both.")
    if not v["events"]:
        errors["events"] = "Pick at least one thing to send."
    return v, errors


def _form(channel: AlertChannel | None):
    if request.method == "GET":
        values = ({"name": channel.name, "ntfy_url": channel.ntfy_url or "",
                   "events": channel.events, "quiet": channel.quiet, "active": channel.active}
                  if channel else {"events": "", "quiet": True, "active": True})
        return render_template("alert_channel_form.html", channel=channel, values=values,
                               errors={}, events=EVENTS)
    v, errors = _parse(request.form, channel)
    if errors:
        shown = {k: val for k, val in v.items() if k not in ("discord_webhook", "ntfy_token")}
        return render_template("alert_channel_form.html", channel=channel, values=shown,
                               errors=errors, events=EVENTS), 400
    if channel is None:
        channel = AlertChannel()
        db.session.add(channel)
    for key, value in v.items():
        setattr(channel, key, value)
    db.session.commit()
    flash(f'Saved the "{channel.name}" channel. Send it a test to check it arrives.', "success")
    return redirect(url_for("alerts.overview"))


@alerts_bp.route("/new", methods=["GET", "POST"])
@login_required
@requires_role("admin")
def new():
    return _form(None)


@alerts_bp.route("/<int:channel_id>/edit", methods=["GET", "POST"])
@login_required
@requires_role("admin")
def edit(channel_id):
    return _form(db.get_or_404(AlertChannel, channel_id))


@alerts_bp.route("/<int:channel_id>/delete", methods=["POST"])
@login_required
@requires_role("admin")
def delete(channel_id):
    channel = db.get_or_404(AlertChannel, channel_id)
    name = channel.name
    # By hand: SQLite here doesn't enforce ON DELETE CASCADE.
    Alert.query.filter_by(channel_id=channel.id).delete(synchronize_session=False)
    db.session.delete(channel)
    db.session.commit()
    flash(f'Deleted the "{name}" channel and its alert log.', "success")
    return redirect(url_for("alerts.overview"))


@alerts_bp.route("/<int:channel_id>/test", methods=["POST"])
@login_required
@requires_role("admin")
def test(channel_id):
    channel = db.get_or_404(AlertChannel, channel_id)
    for target, error in service.send_test(channel):
        name = "ntfy" if target == "ntfy" else "Discord"
        if error:
            flash(f"{name}: not sent ({error}). Check the address, and that this server can "
                  "reach it.", "error")
        else:
            flash(f"{name}: test sent. Check it arrived.", "success")
    return redirect(url_for("alerts.overview"))
