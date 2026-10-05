"""Rail-voltage history: what GATBOX measured, drawn.

Three views. The floor (what has arrived lately), one machine's history, and one session's
trace. Nothing here computes a statistic: Phase 2 stores what GATBOX decided, including the
verdict, and deriving a second opinion would be two chances to disagree about whether a
machine passed. These views select, format and draw.

Two things about the data shape drive most of the code below:

* **A machine's window is not a constant.** `window_source` is `profile`, `user`,
  `machine:<slug>` or `actual:<slug>`, and a spec can be confirmed or an actual recorded at
  any time, so `window_lo`/`window_hi` can differ from one session to the next. Drawing one
  shaded band across a history would state something false, so they go to the chart as
  stepped series and a change reads as a step.
* **An over-range reading has no value.** `Reading.v` is null where the meter read infinity.
  It must reach the chart as null -- `v or 0` would draw a dive to zero volts that never
  happened, on a chart whose purpose is spotting exactly that.
"""

from __future__ import annotations

from datetime import timezone

from flask import Blueprint, render_template
from flask_login import login_required
from sqlalchemy.orm import load_only

from app.extensions import db
from app.models import Game, MaintenanceRecord, RailSession, Reading

rails_bp = Blueprint("rails", __name__, url_prefix="/rails")

FLOOR_LIMIT = 50          # the floor view: recent arrivals, not an archive
TABLE_LIMIT = 300         # readings shown as rows; 2000 is not a table anyone finishes

# The verdicts GATBOX decides, and the palette already in cyberpunk.css. A session with no
# window has no verdict at all (bench and free profiles have nothing to pass), which is not
# the same as passing -- so it gets its own entry rather than falling through to "held".
VERDICT = {
    "held": {"label": "held the window", "colour": "#00ff00", "css": "ok"},
    "left": {"label": "left the window", "colour": "#ff8000", "css": "warn"},
    "over": {"label": "over-voltage", "colour": "#ff00ff", "css": "bad"},
    None: {"label": "no window", "colour": "#888888", "css": "mut"},
}

# Columns the history view needs. Named explicitly so the query cannot drift into loading
# `readings`: that relationship is lazy, so touching it once per session would be one query
# per session, each pulling up to 2000 rows.
SUMMARY_COLUMNS = (
    RailSession.id, RailSession.uid, RailSession.file, RailSession.started,
    RailSession.ended, RailSession.duration_s, RailSession.samples,
    RailSession.profile_id, RailSession.profile_label, RailSession.rail,
    RailSession.mode, RailSession.window_lo, RailSession.window_hi,
    RailSession.window_source, RailSession.alarm_hi, RailSession.powered_mean,
    RailSession.powered_min, RailSession.powered_max, RailSession.in_window_pct,
    RailSession.verdict, RailSession.verdict_detail, RailSession.clock,
    RailSession.over_voltage, RailSession.excursions, RailSession.power_cycles,
    RailSession.suspect, RailSession.received,
)


def _epoch(value):
    """A stored datetime to an epoch for the client to format.

    Charts format from epochs in the browser, so a viewer sees their own local time without
    this application having to know a timezone it is never told. The models write
    ``datetime.now(timezone.utc)`` into a naive column, so a value read back is naive UTC
    and is treated as such rather than as local.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.timestamp()


def verdict_of(session):
    return VERDICT.get(session.verdict, VERDICT[None])


@rails_bp.route("/")
@login_required
def floor():
    """What has arrived lately, across every machine.

    Also the page that answers "is anything coming in at all", which is why it leads with the
    most recent session rather than a total.
    """
    rows = (
        db.session.query(RailSession, Game)
        .outerjoin(Game, Game.id == RailSession.game_id)
        .order_by(RailSession.started.desc().nullslast(), RailSession.id.desc())
        .limit(FLOOR_LIMIT)
        .all()
    )
    sessions = [
        {"s": s, "game": g, "verdict": verdict_of(s)} for s, g in rows
    ]
    return render_template("rails_floor.html", sessions=sessions, verdicts=VERDICT,
                           limit=FLOOR_LIMIT)


@rails_bp.route("/machine/<slug>")
@login_required
def machine(slug):
    """One machine's history: powered mean per session, against the window of the day.

    Addressed by slug, not database id, so the URL is the identifier the cabinet label and
    GATBOX already use.
    """
    game = Game.query.filter_by(barcode=slug).first_or_404(
        description=f"No machine with slug {slug!r}."
    )
    sessions = (
        RailSession.query.options(load_only(*SUMMARY_COLUMNS))
        .filter_by(game_id=game.id)
        .order_by(RailSession.started.asc().nullsfirst(), RailSession.id.asc())
        .all()
    )

    # One point per session. window_lo/hi travel per point rather than as a single band,
    # because they can change between sessions and a single band would be a claim that they
    # did not.
    chart = {
        "points": [
            {
                "uid": s.uid,
                "t": _epoch(s.started),
                "mean": s.powered_mean,
                "min": s.powered_min,
                "max": s.powered_max,
                "lo": s.window_lo,
                "hi": s.window_hi,
                "alarm": s.alarm_hi,
                "verdict": s.verdict,
                "colour": verdict_of(s)["colour"],
                "source": s.window_source,
            }
            for s in sessions
        ],
        "unit": next((s.window_unit for s in sessions if s.window_unit), "V")
        if sessions else "V",
    }
    # Whether the window ever moved. The template says so out loud when it did, because a
    # step in the band is easy to miss and changes how the earlier points should be read.
    windows = {(s.window_lo, s.window_hi) for s in sessions if s.window_lo is not None}

    return render_template(
        "rails_machine.html",
        game=game,
        sessions=[{"s": s, "verdict": verdict_of(s)} for s in reversed(sessions)],
        timeline=[{"s": s, "verdict": verdict_of(s)} for s in sessions],
        chart=chart,
        window_changed=len(windows) > 1,
        verdicts=VERDICT,
    )


@rails_bp.route("/session/<uid>")
@login_required
def session(uid):
    """One session: the trace, the summary GATBOX computed, and the readings."""
    s = RailSession.query.filter_by(uid=uid).first_or_404(
        description=f"No session {uid!r}."
    )
    readings = (
        Reading.query.filter_by(rail_session_id=s.id)
        .order_by(Reading.epoch.asc())
        .all()
    )

    # The x-axis is seconds from the session's own start, taken from `up` -- the Pi's
    # monotonic uptime. It stays correct even when the wall clock does not, which is the
    # whole point of the clock field, and "0-85 min" is what you want to read anyway.
    base_up = next((r.up for r in readings if r.up is not None), None)
    base_epoch = readings[0].epoch if readings else None

    def offset(r):
        if r.up is not None and base_up is not None:
            return round(r.up - base_up, 3)
        if base_epoch is not None:
            return round(r.epoch - base_epoch, 3)
        return None

    trace = {
        # v stays null for an over-range reading. Chart.js draws a gap; a zero would draw a
        # dropout to 0 V that the meter never reported.
        "points": [{"x": offset(r), "y": r.v, "alarm": r.alarm, "ol": r.ol}
                   for r in readings],
        "lo": s.window_lo, "hi": s.window_hi, "alarm": s.alarm_hi,
        "unit": s.window_unit or (readings[0].unit if readings else None) or "V",
    }

    orders = (
        MaintenanceRecord.query.filter_by(rail_session_id=s.id)
        .order_by(MaintenanceRecord.date_reported.desc())
        .all()
    )

    return render_template(
        "rails_session.html",
        s=s,
        game=s.game,
        verdict=verdict_of(s),
        trace=trace,
        readings=readings[:TABLE_LIMIT],
        reading_total=len(readings),
        table_limit=TABLE_LIMIT,
        ol_count=sum(1 for r in readings if r.ol),
        orders=orders,
    )
