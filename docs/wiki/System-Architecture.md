# System architecture

## The stack

- **Python 3.11+ and Flask 3.1**, with SQLAlchemy 2, Flask-Login, Flask-WTF (CSRF on every form),
  Flask-Limiter and Flask-Migrate (Alembic).
- **PostgreSQL** in production; **SQLite** for development and tests.
- **waitress** serves the app. In production it listens on the loopback address behind a
  **Cloudflare tunnel**, and on the LAN for GATBOX.
- **Pages** are server-rendered Jinja templates, with one stylesheet set and a little plain
  JavaScript: no framework and no build step. The content security policy allows only the site's
  own scripts.
- **Charts** with Chart.js; **PDFs** with ReportLab; **QR codes** with segno.
- It can be installed on a phone's home screen.

## How it runs

```
phone / desk browser ──► Cloudflare tunnel ──► waitress ──► Flask app ──► PostgreSQL
GATBOX ──────────────── LAN ─────────────────► /api/v1 ───┘
systemd timer (every minute) ──► scripts/send_alerts.py ──► ntfy, Discord
```

On the server, the app is the `arcade-tracker.service` systemd unit and alerts are the
`arcade-tracker-alerts.timer` unit. Those names, and the paths under `/opt/arcade-tracker`, are
from before the rename and stay as they are. `deploy/deploy.sh` takes a database backup, pulls,
installs requirements, runs migrations and restarts the service.

## The code

| Folder | What's in it |
|---|---|
| `app/models/` | The database tables |
| `app/routes/` | One blueprint per area: machines, work orders, inventory, purchasing, counts, rails, reports, admin... |
| `app/services/` | The work: stock changes, purchasing, counts, alerts, rotation, labels |
| `templates/` | Pages, built from shared macros in `templates/ui.html` |
| `static/` | CSS (design tokens, base, components), JavaScript, icons |
| `migrations/` | Alembic migrations |
| `scripts/` | Command-line tools: create an admin or a device, alerts, reset history, checks |
| `contract/` | The GATBOX API contract and its checksums |
| `deploy/` | systemd units, `deploy.sh` and the RUNBOOK |
| `tests/` | pytest suites, including characterization tests of every page and form |

Every stock change goes through one service (`app/services/stock_places.py`), so the total and the
amount in each place always agree.

## The GATBOX API

`/api/v1` is how GATBOX talks to Cabcrawl: health, sending sessions and orders, the machine
roster, and a machine's open orders. Each device signs in with its own bearer token. The contract
is written down in `contract/v1/` and checked by tests, so a change to it is deliberate and goes
to GATBOX's copy at the same time.
