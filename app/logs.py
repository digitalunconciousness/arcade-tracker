"""Structured logging (Step 5.5).

One format, one destination: ``key=value`` lines on stderr, which systemd's journal keeps.
Readable as it is, and greppable by field::

    journalctl -u arcade-tracker | grep event=LOGIN_FAILED
    journalctl -u arcade-tracker | grep request_id=8a1f2c...

Every line written during a request carries that request's ``request_id``. Through the tunnel
it is Cloudflare's ``CF-Ray``, so it also finds the request in Cloudflare's dashboard; otherwise
a random one. It goes back to the browser as ``X-Request-ID`` and on the error page, so anyone
who hits an error can quote it.

Each page request writes one ``event=request`` line (static files don't). Its path never
carries a credential: the coin-door URL is ``/report/<token>`` and the token is the key, so
any route with a ``token`` in it is logged by its pattern instead.

Until this step the app logger had no level, so it kept WARNING and up only: every
LOGIN_SUCCESS, LOGIN_FAILED and backup event was dropped (F-23). ``LOG_LEVEL`` sets the level;
INFO is the default.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
import uuid
from datetime import UTC, datetime

from flask import Flask, g, has_request_context, request

# Route parameters whose value is a credential, and so never reaches a log.
SECRET_PARAMS = frozenset({"token"})
_PLAIN = re.compile(r"^[\w.:/@<>+-]+$")


def _value(v) -> str:
    """One field value: bare when it's a simple token, JSON-quoted otherwise (spaces, quotes,
    newlines), so every event stays on one line and parses back unambiguously."""
    s = "-" if v is None else str(v)
    return s if s and _PLAIN.match(s) else json.dumps(s, ensure_ascii=False)


class Logfmt(logging.Formatter):
    """``ts=… level=… logger=… request_id=… <fields> msg=…``. A traceback becomes one field."""

    def format(self, record: logging.LogRecord) -> str:
        fields = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds")
                  .replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "request_id": getattr(record, "request_id", "-"),
        }
        fields.update(getattr(record, "fields", {}) or {})
        fields["msg"] = record.getMessage()
        if record.exc_info:
            fields["exc"] = self.formatException(record.exc_info)
        return " ".join(f"{k}={_value(v)}" for k, v in fields.items())


class RequestId(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = getattr(g, "request_id", "-") if has_request_context() else "-"
        return True


def log_path() -> str:
    """The path to log: the route pattern when a parameter is a credential."""
    if request.url_rule is not None and SECRET_PARAMS & set(request.view_args or {}):
        return request.url_rule.rule
    return request.path


def _request_id() -> str:
    """Cloudflare's ray ID when the request came through the tunnel, else a random one."""
    from app.security.https import LOOPBACK

    ray = request.headers.get("CF-Ray", "")
    if request.remote_addr in LOOPBACK and re.fullmatch(r"[0-9a-f]{8,32}(-[A-Z]{3})?", ray):
        return ray
    return uuid.uuid4().hex[:16]


def configure(app: Flask) -> None:
    level = os.environ.get("LOG_LEVEL", "INFO").upper()
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(Logfmt())
    handler.addFilter(RequestId())
    handler._arcade = True  # marks ours, so a second create_app() replaces it

    root = logging.getLogger()
    root.handlers = [h for h in root.handlers if not getattr(h, "_arcade", False)]
    root.addHandler(handler)
    if root.level > logging.WARNING or root.level == logging.NOTSET:
        root.setLevel(logging.WARNING)       # libraries: warnings and up
    for name in (app.logger.name, "arcade"):
        logging.getLogger(name).setLevel(level)

    access = logging.getLogger("arcade.request")

    @app.before_request
    def _start() -> None:
        g.request_id = _request_id()
        g.request_started = time.perf_counter()

    @app.after_request
    def _finish(response):
        response.headers["X-Request-ID"] = g.get("request_id", "-")
        if request.endpoint != "static":
            from flask_login import current_user

            from app.security.https import client_ip

            access.info("%s %s %s", request.method, log_path(), response.status_code,
                        extra={"fields": {
                "event": "request",
                "method": request.method,
                "path": log_path(),
                "status": response.status_code,
                "ms": round((time.perf_counter() - g.get("request_started", time.perf_counter()))
                            * 1000, 1),
                "user": current_user.username if current_user.is_authenticated else "-",
                "ip": client_ip(),
            }})
        return response
