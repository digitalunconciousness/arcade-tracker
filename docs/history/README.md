# Superseded code, kept for reference

Nothing in this directory runs. It is here so the history of how the application
used to work stays readable, and so a question like "what did the old route do?"
has an answer that is not a `git log` archaeology session.

The live application is the factory in `app/`, started by `run.py` through
`arcade-tracker.service`.

| File | Superseded by | Why it was retired |
|---|---|---|
| `app.py` | `app/` (the application factory) | The 172 KB monolith. Everything in it was split into `app/routes/`, `app/models/`, `app/forms/` and `app/security/`. |
| `security_utils.py` | `app/security/utils.py` | A byte-for-byte dead duplicate; only `app.py` imported it. `test_security_utils.py` used to test *this* copy, so the suite was exercising code that never ran. It now tests the live module. |
| `security_middleware.py` | `app/security/middleware.py` | Same split. |
| `skeeball_routes.py` | `app/routes/skeeball.py` | Registered by `app.py` only. |
| `run_app.sh`, `start.app.sh` | `run.sh`, `arcade-tracker.service` | Both launched `app.py`. |
| `deploy-to-proxmox.sh` | `deploy/deploy.sh` | Installed Docker and docker-compose. The deployment is a plain systemd service in an LXC and never used them. |
| `deploy_to_pi.sh`, `deploy_stats_api.sh` | — | One-off rsync scripts for the skeeball Pi. |
| `create_admin.py` | `scripts/create_admin.py` | Written against `app.py`. The replacement uses the factory and can also rotate an existing password. |
| `create_request_history_table.py` | migration `f1c2d3e4a5b6` | Created `inventory_request_history` by hand because no migration did. There is one now. |
| `arcade-tracker-ngrok.service`, `scripts/get_ngrok_url.sh`, `scripts/setup_ngrok_autostart.sh` | Cloudflare Tunnel | ngrok is not installed on the server and never was in this deployment; the unit misled anyone reading the repo into thinking port 5000 was published by ngrok. |

## The one-off maintenance scripts (retired 2026-10-01)

Every one of these was broken against the current application, in one of two ways.

**Stale imports.** `from app import app, db` (sometimes `, Game` or `, User`) worked
against the monolithic `app.py`, which re-exported those names at module level. The
factory package exports only `create_app`, so each of these raises `ImportError` the
moment it is run:

`create_inventory_requests_table.py` · `create_manager.py` ·
`create_work_log_table.py` · `init_db.py` · `list_users.py` ·
`register_skeeball_lanes.py` · `reset_ranking_counters.py` ·
`scripts/import_csv_backup.py` · `scripts/migrate_database.py` ·
`templates/dbmigrate.py` (a Python file inside the template directory)

**Wrong database.** These open `sqlite3` directly, but the deployment has run on
PostgreSQL for months. Rather than failing, they would have quietly inspected or
modified `instance/arcade.db` — a stale, empty leftover — and reported confident
nonsense about a database nobody uses:

`migrate_db.py` · `migrate_all_missing.py` · `check_all_schemas.py` ·
`check_db_schema.py` · `init_db.py` (both faults)

What replaced them: schema changes go through Flask-Migrate
(`flask --app run:app db migrate` / `db upgrade`), `scripts/check_schema.py`
compares the live schema against the models, `scripts/create_admin.py` handles
accounts (`--list`, `--reset-password`), and `deploy/deploy.sh` runs the whole
deployment including the `pg_dump` backup.

Still at the repository root on purpose: `run.py`, `run.sh` and `config.py`.
