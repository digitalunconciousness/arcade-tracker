"""Raise alerts, and deliver them (feature step 6). See app/models/alerts.py for the shape.

Owner's decisions (2026-10-25): channels send to ntfy (self-hosted on the arcade's Proxmox) and
to Discord; each channel picks its own events; outside opening hours alerts are held and go
out together at opening, unless the channel is set to always send; a daily summary goes out at
opening.

``notify()`` only writes rows, in the caller's transaction. ``deliver()`` sends them, from
``scripts/send_alerts.py`` every minute. A failed send is retried with growing gaps (1, 2, 4 ...
up to 60 minutes) for a day, then marked failed; the admin page lists what went out and what
didn't.
"""
from __future__ import annotations

import datetime as dt
import logging
import re
from urllib.parse import urlsplit

from app.extensions import db
from app.models.alerts import Alert, AlertChannel, Setting, _utc_now

log = logging.getLogger("arcade.alerts")

GIVE_UP_AFTER = dt.timedelta(days=1)
MAX_GAP_MINUTES = 60
TIMEOUT_S = 10
DISCORD_LIMIT = 2000
PRIORITY = {"coin_door": 4, "machine_down": 4, "rail_window": 4}     # ntfy: 3 is default
TAGS = {"coin_door": "rotating_light", "machine_down": "warning", "rail_window": "zap",
        "low_stock": "package", "pm_due": "wrench", "round_flag": "triangular_flag_on_post",
        "part_request": "truck", "summary": "sunrise", "test": "white_check_mark"}


# --- opening hours ------------------------------------------------------------------------------

def local_now() -> dt.datetime:
    """The arcade's clock: the server's local time, like the dates readings carry."""
    return dt.datetime.now()  # noqa: DTZ005 -- local on purpose, see above


def _hm(value: str | None) -> dt.time | None:
    try:
        return dt.time.fromisoformat(value) if value else None
    except ValueError:
        return None


def opening_hours() -> tuple[dt.time, dt.time] | None:
    """(opens, closes), or None when not set: then it is always open."""
    opens, closes = _hm(Setting.get("open_time")), _hm(Setting.get("close_time"))
    return (opens, closes) if opens and closes and opens != closes else None


def is_open(now: dt.datetime | None = None) -> bool:
    hours = opening_hours()
    if hours is None:
        return True
    t = (now or local_now()).time()
    opens, closes = hours
    if opens < closes:
        return opens <= t < closes
    return t >= opens or t < closes          # closes after midnight


# --- raising ------------------------------------------------------------------------------------

def notify(event: str, title: str, body: str = "", path: str | None = None,
           now: dt.datetime | None = None) -> int:
    """Queue *event* for every active channel that wants it. Returns the number of rows.

    Adds to the session and leaves the commit to the caller, so the alert is saved with
    whatever caused it, or not at all. Safe inside a flush hook: nothing here flushes.
    """
    held = not is_open(now)
    count = 0
    with db.session.no_autoflush:
        for channel in AlertChannel.query.filter_by(active=True).all():
            if not channel.wants(event):
                continue
            for target in channel.targets:
                db.session.add(Alert(channel=channel, target=target, event=event,
                                     title=title[:200], body=body, path=path,
                                     status="held" if held and channel.quiet else "pending"))
                count += 1
    return count


# --- sending ------------------------------------------------------------------------------------

class SendError(Exception):
    """A send failed. The message is safe to store: never a URL, which may hold a secret."""


def _link(path: str | None) -> str | None:
    from flask import current_app

    base = (current_app.config.get("BASE_URL") or "").rstrip("/")
    return f"{base}{path}" if base and path else None


ERRNO = re.compile(r"\[Errno -?\d+\][^)'\"]*")


def describe(error: Exception, url: str) -> str:
    """What went wrong, safe to store: the kind of failure, the OS's reason, and the server's
    name -- never the path, which for a Discord webhook is the secret.

    requests wraps the real failure (a DNS lookup, a refused or timed-out connection) inside
    its own; "ConnectionError" alone couldn't tell those apart, or show a mistyped name.
    """
    reason = getattr(error.args[0], "reason", None) if error.args else None
    detail = ERRNO.search(str(reason or error))
    cause = detail.group(0).strip() if detail else type(reason or error).__name__
    host = urlsplit(url).hostname or "unknown host"
    return f"{type(error).__name__}: {cause} ({host})"


def _post(url: str, **kw):
    import requests

    try:
        resp = requests.post(url, timeout=TIMEOUT_S, **kw)
    except requests.RequestException as e:
        raise SendError(describe(e, url)) from None
    if resp.status_code >= 300:
        raise SendError(f"HTTP {resp.status_code} ({urlsplit(url).hostname})")
    return resp


def send_ntfy(channel: AlertChannel, alert: Alert) -> None:
    base, _, topic = channel.ntfy_url.rstrip("/").rpartition("/")
    payload = {"topic": topic, "title": alert.title, "message": alert.body or alert.title,
               "priority": PRIORITY.get(alert.event, 3)}
    if alert.event in TAGS:
        payload["tags"] = [TAGS[alert.event]]
    link = _link(alert.path)
    if link:
        payload["click"] = link
    headers = {"Authorization": f"Bearer {channel.ntfy_token}"} if channel.ntfy_token else {}
    _post(base or channel.ntfy_url, json=payload, headers=headers)


def send_discord(channel: AlertChannel, alert: Alert) -> None:
    link = _link(alert.path)
    text = f"**{alert.title}**" + (f"\n{alert.body}" if alert.body else "")
    tail = f"\n<{link}>" if link else ""
    text = text[:DISCORD_LIMIT - len(tail) - 1] + tail
    # No @everyone or role pings from text a customer typed into a coin-door report.
    _post(channel.discord_webhook, json={"content": text, "allowed_mentions": {"parse": []}})


SENDERS = {"ntfy": send_ntfy, "discord": send_discord}


def send(alert: Alert, now: dt.datetime | None = None) -> bool:
    """Try one alert now. Records the outcome on the row; the caller commits."""
    now = now or _utc_now()
    alert.attempts = (alert.attempts or 0) + 1         # None until saved, as for a test
    alert.created_at = alert.created_at or now
    try:
        SENDERS[alert.target](alert.channel, alert)
    except (SendError, KeyError, AttributeError, ValueError) as e:
        alert.error = str(e)[:300] or type(e).__name__
        if now - alert.created_at > GIVE_UP_AFTER:
            alert.status = "failed"
        else:
            gap = min(2 ** (alert.attempts - 1), MAX_GAP_MINUTES)
            alert.next_try_at = now + dt.timedelta(minutes=gap)
        log.warning("alert not sent", extra={"fields": {
            "event": "ALERT_FAILED", "alert_id": alert.id, "target": alert.target,
            "error": alert.error, "attempts": alert.attempts}})
        return False
    alert.status, alert.sent_at, alert.error = "sent", now, None
    return True


# --- the minute-by-minute run -------------------------------------------------------------------

def release_held(now_local: dt.datetime | None = None) -> int:
    """At opening, turn what was held overnight into one message per channel and target."""
    if not is_open(now_local):
        return 0
    held = Alert.query.filter_by(status="held").order_by(Alert.created_at).all()
    groups: dict[tuple[int, str], list[Alert]] = {}
    for a in held:
        groups.setdefault((a.channel_id, a.target), []).append(a)
    for rows in groups.values():
        if len(rows) == 1:
            rows[0].status = "pending"
            continue
        lines = [f"- {a.title}" for a in rows]
        db.session.add(Alert(channel=rows[0].channel, target=rows[0].target, event="summary",
                             title=f"{len(rows)} alerts while closed",
                             body="\n".join(lines), path="/maintenance_orders"))
        for a in rows:
            a.status, a.error = "sent", "sent in the opening digest"
    return len(held)


def summary_text() -> tuple[str, str]:
    """Today's summary: what's down, what's open, what's low, what's due (machines, and
    inventory counts and deliveries)."""
    from app.models import Game, LowStockAlert, MaintenanceRecord

    down = (Game.query.filter(Game.location == "Floor",
                              Game.status.in_(("Not_Working", "Being_Fixed")))
            .order_by(Game.name).all())
    open_orders = MaintenanceRecord.query.filter(
        MaintenanceRecord.status.in_(("Open", "In_Progress"))).count()
    pm = MaintenanceRecord.query.filter(MaintenanceRecord.source == "pm",
                                        MaintenanceRecord.status.in_(("Open", "In_Progress"))
                                        ).count()
    low = LowStockAlert.query.filter_by(resolved=False).count()
    lines = [f"Machines down: {len(down)}" + (f" ({', '.join(g.name for g in down[:10])}"
                                               f"{', ...' if len(down) > 10 else ''})"
                                               if down else ""),
             f"Open work orders: {open_orders} ({pm} preventive maintenance)",
             f"Parts low: {low}"]
    from app.services.inventory_due import due

    inv = due()
    if inv.counts_late:
        lines.append(f"Counts overdue: {inv.counts_late}")
    if inv.deliveries:
        lines.append(f"Deliveries due: {inv.deliveries}")
    return "Today's summary", "\n".join(lines)


def queue_summary(now_local: dt.datetime | None = None) -> int:
    """Once a day, at opening: the summary for every channel that wants it."""
    now_local = now_local or local_now()
    hours = opening_hours()
    if hours is None or not is_open(now_local):
        return 0
    today = now_local.date().isoformat()
    if Setting.get("last_summary_date") == today:
        return 0
    Setting.put("last_summary_date", today)
    title, body = summary_text()
    return notify("summary", title, body, path="/", now=now_local)


def deliver(now: dt.datetime | None = None, now_local: dt.datetime | None = None) -> dict:
    """One run of the sender: release, summarise, send what is due. Commits."""
    now = now or _utc_now()
    released = release_held(now_local)
    summaries = queue_summary(now_local)
    db.session.flush()
    due = (Alert.query.filter(Alert.status == "pending",
                              (Alert.next_try_at.is_(None)) | (Alert.next_try_at <= now))
           .order_by(Alert.created_at).limit(200).all())
    sent = sum(send(a, now) for a in due)
    db.session.commit()
    return {"released": released, "summaries": summaries, "sent": sent,
            "failed": len(due) - sent}


def send_test(channel: AlertChannel) -> list[tuple[str, str | None]]:
    """Send a test to each of a channel's targets now, for the admin page. Commits."""
    results = []
    for target in channel.targets:
        alert = Alert(channel=channel, target=target, event="test",
                      title=f"Test from Cabcrawl: {channel.name}",
                      body="If you can read this, the channel works.", path="/")
        db.session.add(alert)
        ok = send(alert)
        if not ok:
            alert.status = "failed"            # a test isn't retried
        results.append((target, None if ok else alert.error))
    db.session.commit()
    return results
