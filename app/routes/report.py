"""Coin-door reporting: a maintenance request filed with no login.

Phase 2.5. The authorisation is physical — the QR is inside the coin door, so reading it
means holding the key. Possession of ``game.report_token`` stands in for that.

**This is the only unauthenticated write endpoint in the application**, on a site published
to the internet through a Cloudflare tunnel. Its own blueprint, not a route on
``maintenance_bp``, so that "this cannot reach anything else" is something you can read off
the route table rather than take on trust: it creates one record for one machine, shows a
count, and offers nothing else. There is no session to escape with, and nothing to escape to.

What it honestly authorises is "someone who has seen inside this coin door, or anyone they
told". A photographed label is a shared credential. Per-machine tokens and easy rotation are
the mitigation, not prevention; it is not a substitute for accounts where attribution matters.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for

from app.extensions import csrf, db, limiter
from app.models import Game, MaintenanceRecord
from app.security.utils import log_security_event

report_bp = Blueprint("report", __name__)

# Exempt from the app-wide CSRF check (enforced since 2026-10-08), deliberately. The token in
# the URL is the authorisation and it is a capability, not an ambient credential: a cross-site
# POST can only reach this endpoint if it already knows the token, and anything that knows it
# can post directly. Enforcing CSRF here would add nothing but a way to fail -- a QR scanner's
# cookie-less in-app browser could no longer file a report. The per-token rate limit is the
# control against abuse. tests/test_coin_door_report.py holds this design to account.
csrf.exempt(report_bp)

# What this application means by "still open", everywhere else too: a machine someone is
# already working on is not a machine that needs reporting again.
OPEN_STATUSES = ("Open", "In_Progress")

# The textarea's maxlength is a hint to a browser. This endpoint is reachable from the
# internet with curl, so the limit is enforced here as well.
MAX_ISSUE = 2000

# Per machine, per hour. A coin door is not opened often, and a second report for the same
# fault is noise in the queue rather than information.
MAX_PER_HOUR = 5


def _token_rate_key() -> str:
    """The rate-limit bucket for one machine.

    Per machine, not per address: ``get_remote_address`` resolves to ``request.remote_addr``,
    which through the Cloudflare tunnel is cloudflared's own address -- so every visitor from
    the internet already shares one bucket and an address-keyed limit here would be close to
    decorative. (``app/security/utils.get_client_ip`` does read X-Forwarded-For, so logging
    can see the real client; the limiter cannot. Changing that means deciding to trust a
    header, which is its own piece of work.)

    Hashed rather than raw, because the key becomes a storage key: ``memory://`` today, but a
    backend that persists would otherwise hold the credential.
    """
    token = (request.view_args or {}).get("token") or ""
    return "coindoor:" + hashlib.sha256(token.encode()).hexdigest()[:32]


def _rate_limited(_limit) -> None:
    """Record a refused report. Never the token: a log outlives everything, and this one is
    a credential. The machine is named instead, which is what anyone reading the log wants."""
    game = Game.by_report_token((request.view_args or {}).get("token"))
    log_security_event(
        "COINDOOR_RATE_LIMITED",
        details=f"machine: {game.name if game else '<unknown token>'}",
        level="warning",
    )


def _utc_now() -> datetime:
    """Naive UTC, for the TIMESTAMP WITHOUT TIME ZONE column this writes to.

    ``MaintenanceRecord.date_reported``'s model default hands it an *aware* datetime.
    psycopg2 then converts that to the database session's zone and drops the offset, so
    13:00 UTC is stored as 08:00 and labelled UTC -- the bug Phase 2 shipped and then fixed
    on the API path. The default itself is unchanged here: nine other columns across five
    models share it, and a repo-wide sweep is its own piece of work, not a side effect of
    adding a form.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _machine_or_404(token: str) -> Game:
    """The machine a token belongs to.

    404 for an unknown token and 404 for a wrong one: nothing here distinguishes "no such
    token" from "not this machine's token", because telling them apart would turn this into
    an oracle for guessing.
    """
    game = Game.by_report_token(token)
    if game is None:
        abort(404)
    return game


def _open_count(game: Game) -> int:
    return (
        MaintenanceRecord.query
        .filter(MaintenanceRecord.game_id == game.id)
        .filter(MaintenanceRecord.status.in_(OPEN_STATUSES))
        .count()
    )


@report_bp.route("/report/<token>", methods=["GET", "POST"])
# Filing only. Someone re-reading the page, or scanning the label twice because the first
# scan did not focus the field, must not spend the machine's budget.
@limiter.limit(f"{MAX_PER_HOUR} per hour", key_func=_token_rate_key, methods=["POST"],
               on_breach=_rate_limited)
def report_form(token: str):
    """The form, and the one thing it can do.

    GET shows the machine's name -- which is on the cabinet anyway, and is how someone knows
    they scanned the right one -- and a count of what is already open, so a fifth report is
    not filed for a machine everybody knows is down.

    POST creates the record and redirects back here. Post/redirect/get rather than rendering
    the result: the one client this has is a phone, and a phone that pulls to refresh must
    not file a second report.
    """
    game = _machine_or_404(token)

    if request.method == "POST":
        issue = (request.form.get("issue_description") or "").strip()
        if not issue:
            flash("Please describe the problem before sending it.", "error")
            return redirect(url_for("report.report_form", token=token))
        if len(issue) > MAX_ISSUE:
            flash(f"That is too long -- {MAX_ISSUE} characters at most.", "error")
            return redirect(url_for("report.report_form", token=token))
        db.session.add(MaintenanceRecord(
            game_id=game.id,
            work_order_type="game",
            issue_description=issue,
            status="Open",
            # Phase 2's column. A tech reading the queue can tell this came from whoever was
            # standing at the machine, with no account behind it.
            source="coindoor",
            date_reported=_utc_now(),
        ))
        db.session.commit()
        # No record id, here or in the page: there is nothing to look up afterwards, so
        # there is nothing to enumerate.
        flash("Thank you -- that is in the work queue now.", "success")
        return redirect(url_for("report.report_form", token=token))

    return render_template(
        "coin_door_report.html",
        game=game,
        token=token,
        open_count=_open_count(game),
    )
