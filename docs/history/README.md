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

Still at the repository root on purpose: `run.py` and `run.sh` (current), `config.py`,
and the one-off `check_*.py` / `migrate_*.py` / `create_*_table.py` maintenance
scripts, which are occasionally still useful against a live database.
