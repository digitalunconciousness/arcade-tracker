#!/usr/bin/env python3
"""Deliver waiting alerts, release the ones held overnight, and send the daily summary.

Run every minute by deploy/arcade-tracker-alerts.timer, from the repository root, with the
application's environment (create_app reads .env):

    /opt/arcade-tracker-venv/bin/python scripts/send_alerts.py

Prints one line of counts, which the journal keeps. Exits 0 even when a send fails: the alert
stays queued and is tried again next minute, and the admin page shows it.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main(app=None) -> int:
    if app is None:
        from app import create_app

        app = create_app()
    from app.services.alerts import deliver

    with app.app_context():
        counts = deliver()
    print(" ".join(f"{k}={v}" for k, v in counts.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
