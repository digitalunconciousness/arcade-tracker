# Arcade Tracker — Copilot Instructions

## Running the App

```bash
python app.py          # development server (port 5000)
./run.sh               # alternative startup script
```

Copy `.env.example` to `.env` before first run. `SECRET_KEY` is required for production; the app will generate a throwaway key and warn if it is not set.

## Tests

```bash
python -m pytest                            # full suite
python -m pytest test_security_utils.py -v  # single file
```

Test files live at the **project root** (not in a `tests/` directory). There are also integration test files in `arcade-tracker/` (nested clone) but these have stale imports and are not currently runnable.

## Database Migrations

The app uses **Flask-Migrate** (Alembic) for schema management:

```bash
flask db migrate -m "description"
flask db upgrade
```

The custom scripts in `scripts/migrate_database.py` provide a separate SQLite-direct migration path used for production deployments where Alembic is not available.

## Architecture

### Application Factory

`app/__init__.py` exports `create_app()`. Extensions are singletons in `app/extensions.py` and bound via `init_app()` — never instantiated with the app directly.

### Blueprint Layout

| Blueprint | Prefix | File |
|-----------|--------|------|
| `auth_bp` | `/auth` | `app/routes/auth.py` |
| `dashboard_bp` | `/` | `app/routes/dashboard.py` |
| `games_bp` | `/games` | `app/routes/games.py` |
| `maintenance_bp` | `/maintenance` | `app/routes/maintenance.py` |
| `inventory_bp` | `/inventory` | `app/routes/inventory.py` |
| `reports_bp` | `/reports` | `app/routes/reports.py` |
| `admin_bp` | `/admin` | `app/routes/admin.py` |
| `skeeball_bp` | `/skeeball` | `app/routes/skeeball.py` |

Blueprints are registered dynamically via `importlib` — a failed import is logged as a warning rather than crashing startup.

### Templates and Static Files

`templates/` and `static/` are at the **project root**, not inside `app/`. The factory explicitly sets `template_folder` and `static_folder` to point up one level from the package.

### Models and Forms — Single Import Path

All models and forms are re-exported from their package `__init__.py` so callers always use the short path:

```python
from app.models import User, Game, PlayRecord, MaintenanceRecord
from app.forms import LoginForm, InventoryItemForm
```

Never import directly from `app.models.user` etc. in new code.

### Database

SQLite stored at `instance/arcade.db`. Key tables: `user`, `game`, `play_records`, `maintenance_record`, `work_logs`, `inventory_item`, `stock_history`.

## Role-Based Access Control

Four roles in ascending order: `readonly (1)` → `operator (2)` → `manager (3)` → `admin (4)`.

`User.has_role(role)` checks `>=` so higher roles satisfy lower requirements.

Use the decorators from `app/utils/decorators.py` — always stack after `@login_required`:

```python
@login_required
@requires_role("manager")
def my_view():
    ...

# Shorthand equivalents:
@manager_required
@admin_required
```

## CSRF

`WTF_CSRF_CHECK_DEFAULT = False` — CSRF is **not** enforced globally. Routes must opt in:

```python
csrf.protect()           # call manually inside a view
# or decorate the blueprint/view with @csrf.protect
```

API endpoints that must skip CSRF use `@csrf.exempt`.

## Security Events

Use `log_security_event()` from `app/security/utils.py` to record security-relevant actions (failed logins, permission denials, etc.). `logout()` already calls this; other sensitive actions should too.

## Skeeball Integration

The Flask app does **not** run GPIO directly. It proxies to a Raspberry Pi stats API:

```
GPIO sensors → skeeball_main.py → skeeball_state.json
  → state_sync.py → realtime_state.json
  → stats_api_server.py (Pi port 5002)
  → Flask app/routes/skeeball.py (fetch_from_raspberry_pi())
  → Web UI
```

Configure the Pi connection via environment variables:

```
RPI_STATS_HOST=<pi-ip>   # default: localhost
RPI_STATS_PORT=5002
```

`get_lane_manager()` in `app/routes/skeeball.py` is a **lazy singleton** — it instantiates `LaneManager` on first call and caches it. The `skeeball/` package (root-level) contains the Pi-side lane management code; `rpi_skeeball/` contains the standalone Pi firmware.

## File Uploads

- General uploads → `uploads/`
- Maintenance photos → `static/maintenance_photos/`
- Profile pictures → `static/profile_pics/`

Use `allowed_file()` and `compress_and_save_image()` from `app/utils/helpers.py` for all upload handling. Max upload size is 50 MB (`MAX_CONTENT_LENGTH`).
