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

Still at the repository root on purpose: `run.py` (the entry point), `arcade-tracker.service`
(the systemd unit keeps its old name, see `deploy/RUNBOOK.md`), and the container files, which
are being rebuilt.

## The old root documents and scripts (retired 2026-10-27, Step 6)

Moved to `root/` when the README was rewritten for Cabcrawl (F-4). None of them is imported or
run by the application, and the documents describe the v1.0 app, a Docker deployment that
production never used, and SQLite backups. What is still true is in the README, the wiki
(`docs/wiki/`) and `deploy/RUNBOOK.md`.

| File | Superseded by |
|---|---|
| `ARCADE_TRACKER_DOCS.md`, `FLASK_INTEGRATION.md`, `FLASK_READY.md`, `CHANGES_SUMMARY.md`, `VERSION_1.0_RELEASE_NOTES.md` | `README.md`, `CHANGELOG.md` and the wiki |
| `AUTHENTICATION.md` | the wiki's Roles and permissions and Security overview pages |
| `BACKUP_SYSTEM.md` | `deploy/RUNBOOK.md` (PostgreSQL dumps before every deploy) |
| `DEPLOYMENT.md`, `DEPLOYMENT_CHECKLIST.md` | `deploy/RUNBOOK.md` |
| `BRANCHES.md` | nothing: the branches it describes are gone |
| `CLOUD_SETUP.md`, `TRACKING_SETUP.md` | the wiki's Configuration page |
| `WARP.md` | `CLAUDE.md` |
| `run.sh` | the README's "Run it locally" |
| `create_tables.py`, `load_env.py`, `security_config.py` | the application factory, `app/config.py` |
| `create_docs_pdf.py`, `generate_documentation.py`, `create_iso_backup.py`, `generate_icons.py`, `remove_emojis.py` | nothing: one-off tools for the v1.0 documents and icons |

