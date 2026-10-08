# Arcade Tracker: feature inventory

Generated from the code on branch `claude/ui-overhaul-8slo91`, not from the old docs. The route list is
`app.url_map` from `create_app()` (102 routes plus `/static`), and roles, templates and side effects come
from reading each view. Nothing here has been verified by a test yet: the characterization tests in Step 2
are what turn this list into fact.

**How to use this page:** strike what you don't use (`~~like this~~`, or just tell me the IDs). Everything
not struck gets a characterization test and survives the redesign. The flags in §12 are numbered so you can
answer them by ID.

## Conventions

- **Role** is the minimum role. The hierarchy is `readonly < operator < manager < admin`
  (`User.ROLE_HIERARCHY`).
  - `login` means any signed-in user, *including readonly*.
  - `public` means no login at all.
  - `device` means a bearer token for a GATBOX device (`/api/v1`).
- A role failure redirects to `/` with a flash message, not a 403. Not being logged in redirects to `/login`
  (302).
- **Form** names the WTForms class when there is one. "raw" means the view reads `request.form` directly
  with no server-side validation object.
- **CSRF today:** `WTF_CSRF_CHECK_DEFAULT = False`. Only views that call `FlaskForm.validate_on_submit()`
  are CSRF-checked: login, profile, change password, both work-order create forms, inventory add/edit/adjust.
  Every "raw" POST and every `fetch()` POST is unprotected.

---

## 1. Auth and account (`app/routes/auth.py`)

| ID | Route | Methods | Role | Template | Form | What it does |
|----|-------|---------|------|----------|------|--------------|
| A1 | `/login` | GET, POST | public | `login.html` | `LoginForm` | Case-insensitive username, lockout after repeated failures (in memory, per username, 15 min), "remember me" for 30 days, honours a safe `?next=`. Forces `/change_password` when `must_change_password` is set. |
| A2 | `/logout` | GET | login | — | — | Logs out. A GET, so any page can log you out. |
| A3 | `/setup` | GET, POST | public | `setup.html` | raw | First-run admin creation. Only works while the user table is empty. No password-strength check. |
| A4 | `/profile` | GET, POST | login | `profile.html` | `ProfileForm` | Profile picture upload to `static/profile_pics/`, re-encoded as JPEG. |
| A5 | `/change_password` | GET, POST | login | `change_password.html` | `ChangePasswordForm` | Checks the current password and strength (`check_password_strength`), then clears `must_change_password`. |

## 2. Dashboard (`app/routes/dashboard.py`)

| ID | Route | Methods | Role | Template | What it does |
|----|-------|---------|------|----------|--------------|
| D1 | `/` | GET | login | `index.html` | Totals (games, plays, revenue), 5 recent play records, 5 open work orders, 10 open low-stock alerts, and the 3 worst floor performers by revenue per day. **Side effect on GET:** runs the monthly Top 5 / Top 10 ranking update and commits it (see F-14). |

## 3. Machines, labels and the QR path (`app/routes/games.py`)

| ID | Route | Methods | Role | Template | Form | What it does |
|----|-------|---------|------|----------|------|--------------|
| G1 | `/games` | GET | login | `games_list.html` | — | Search, location and status filters; Floor and Warehouse split; open-work-order indicator. Hosts the bulk-action form (G9) and the CSV export (G10). |
| G2 | `/add_game` | GET, POST | operator | `add_game.html` | raw | Creates a Game, gives it a barcode slug from its name, takes an optional image and an optional baseline coin count (makes a PlayRecord). |
| G3 | `/game/<id>` | GET | login | `game_detail.html` | — | Machine detail: info, last 10 play records, all work orders, the latest GATBOX rail session with its verdict, and the add-baseline and delete forms. |
| G4 | `/edit_game/<id>` | GET, POST | operator | `edit_game.html` | raw | Edits every field, replaces the image, and sets or edits the baseline while no real plays exist. |
| G5 | `/record_plays/<id>` | GET, POST | operator | `record_plays.html` | raw | Coin-meter reading becomes plays (reading minus last reading) and revenue (plays × `coins_per_play`). Rejects a reading lower than the last one. Refused when `counter_status != Working`. |
| G6 | `/delete_play_record/<id>` | POST | manager | — | raw | Deletes a play record and subtracts it from the game totals. |
| G7 | `/add_baseline/<id>` | POST | operator | — | raw | Sets a baseline coin count when the machine has no play records. |
| G8 | `/delete_game/<id>` | POST | admin | — | raw | Deletes the game, its play records, its work orders and its image. |
| G9 | `/bulk_update_games` | POST | manager | — | raw | Move to Floor or Warehouse, or set Working or Not Working, for the ticked machines. |
| G10 | `/export_selected_games` | GET | manager | — | — | CSV of the ticked machines. |
| G11 | `/import_games` | GET, POST | manager | `import_games.html` | raw (file) | **Roster importer:** uploads the barcade roster JSON (`video_games` / `pinball` / `retired`); idempotent by name (`helpers.import_games_from_roster`). |
| G12 | `/scan` | GET | login | `scan.html` | GET form | Kiosk page: a focused input for a USB HID scanner, which submits to G13. |
| G13 | **`/g/<code>`** | GET | login | — (302) | — | **Printed QR labels point here. Frozen.** Looks up `Game.barcode == code`, falls back to a numeric id, then 302s to **`/maintenance/game/<id>`** (M1). An unknown code flashes and goes to `/scan`. |
| G14 | `/game/<id>/label` | GET | login | `game_label.html` | — | One printable QR label (segno SVG) encoding `<BASE_URL>/g/<barcode>`. **Writes on GET:** backfills a missing barcode. |
| G15 | `/labels` | GET | login | `label_sheet_pick.html` | GET form | Pick machines for a label sheet. |
| G16 | `/labels/sheet` | GET | login | `label_sheet.html` | — | Printable sheet, three labels per row (`?ids=1,2` or repeated `ids`). Skips machines with no barcode. |
| G17 | `/labels/coindoor` | GET | login | `coin_door_label_pick.html` | GET form plus G19's POST | Pick machines for coin-door labels; lists stale labels. |
| G18 | `/labels/coindoor/sheet` | GET | login | `coin_door_label_sheet.html` | — | Printable coin-door labels encoding `<BASE_URL>/report/<token>`. **Writes on GET:** mints missing report tokens and clears the stale flag. |
| G19 | `/game/<id>/report-token/rotate` | POST | **login** | — | raw | Retires a machine's coin-door token and marks its label stale. |

## 4. Coin-door reporting (`app/routes/report.py`): the only unauthenticated write

| ID | Route | Methods | Role | Template | Form | What it does |
|----|-------|---------|------|----------|------|--------------|
| R1 | `/report/<token>` | GET, POST | public | `coin_door_report.html` (standalone, no `base.html`) | raw + CSRF token | GET shows the machine name and its open-order count. POST files a work order (2000-character cap) and redirects back (post/redirect/get). Rate limit is 5 POSTs per hour per machine, keyed on the token. |

## 5. Maintenance and work orders (`app/routes/maintenance.py`)

| ID | Route | Methods | Role | Template | Form | What it does |
|----|-------|---------|------|----------|------|--------------|
| M1 | `/maintenance/game/<id>` | GET, POST | **operator** | `maintenance_with_inventory.html` | `MaintenanceWithInventoryForm` | **This is the page a QR scan lands on.** Creates a work order for this machine with optional parts used (stock is decremented, StockHistory is written, the low-stock alert is checked). Redirects to G3. |
| M2 | `/maintenance/general` | GET, POST | operator | `general_maintenance.html` | `MaintenanceWithInventoryForm` | Work order with no machine attached (`work_order_type`, `location_description`). |
| M3 | `/maintenance_orders` | GET | login | `maintenance_orders.html` | GET search + quick-close POST | Open and closed tabs, search across issue, technician and type. |
| M4 | `/maintenance_detail/<id>` | GET | login | `maintenance_detail.html` | photo-delete POSTs | Full work order: work logs, parts, photos, linked GATBOX traces and requests. |
| M5 | `/update_maintenance/<id>` | GET, POST | operator | `update_maintenance.html` | raw | Status, priority, fix and cost; adds a WorkLog entry; up to 10 dynamic rows of parts to **use** (decrements stock) or **request** (creates an InventoryRequest). |
| M6 | `/close_maintenance/<id>` | POST | operator | — | raw | Quick close from M3. |
| M7 | `/delete_maintenance/<id>` | POST | manager | — | raw | Deletes a work order. |
| M8 | `/download_maintenance_record/<id>` | GET | login | — (PDF) | — | ReportLab PDF of one work order. |
| M9 | `/maintenance_photos/<id>` | GET, POST | operator | `maintenance_photos.html` | `MaintenancePhotoForm` (checked by hand) | **Photo uploads:** at most 10 per order and 500 MB in total; re-encoded to JPEG at 1200px max; optional S3 copy (`USE_CLOUD_STORAGE`). |
| M10 | `/delete_maintenance_photo/<id>/<filename>` | POST | manager | — | raw | Removes a photo from the order and from disk. |
| M11 | `/maintenance_reports` | GET | manager | `maintenance_reports.html` | GET `?days=` | Counts, cost and average resolution days over a window. |
| M12 | `/export_maintenance_report` | GET | manager | — (PDF) | — | ReportLab PDF (`?type=open|closed|all&days=`). |

## 6. Inventory, requests and shipments (`app/routes/inventory.py`, prefix `/inventory`)

| ID | Route | Methods | Role | Template | Form | What it does |
|----|-------|---------|------|----------|------|--------------|
| I1 | `/inventory/` | GET | operator | `inventory_list.html` | GET search | Items, low-stock count, total value, recent requests (all for manager and up, own for operator). |
| I2 | `/inventory/add` | GET, POST | manager | `add_inventory_item.html` | `InventoryItemForm` | New item with compatible machines; the initial stock goes into StockHistory. |
| I3 | `/inventory/<id>` | GET | operator | `inventory_detail.html` | delete POST | Item, its last 10 stock changes and its active alert. |
| I4 | `/inventory/<id>/edit` | GET, POST | manager | `edit_inventory_item.html` | `InventoryItemForm` | Edit; a stock change becomes an "adjusted" StockHistory entry. |
| I5 | `/inventory/<id>/adjust_stock` | GET, POST | operator | `adjust_stock.html` | `StockAdjustmentForm` | added, removed, used, or a direct set, with a reason. |
| I6 | `/inventory/<id>/delete` | POST | admin | — | raw | Deletes the item. |
| I7 | `/inventory/low_stock_alerts` | GET | manager | `low_stock_alerts.html` | resolve POST | Active alerts and those resolved in the last 30 days. |
| I8 | `/inventory/resolve_alert/<id>` | POST | manager | — | raw | Resolves an alert. |
| I9 | `/inventory/request` | GET, POST | operator | `request_inventory.html` | raw | **Inventory request:** an existing item or a free-text new one, with quantity, urgency and an optional work order. Writes a history row. |
| I10 | `/inventory/requests` | GET | operator | `inventory_requests.html` | status and delete POSTs | Pending and all (all for manager and up, own for operator). |
| I11 | `/inventory/requests/<id>` | GET | operator | `inventory_request_detail.html` | update and tracking POSTs | Request detail with its full audit history and tracking events. Operators see only their own. |
| I12 | `/inventory/requests/<id>/update` | POST | manager | — | raw | Status, notes, tracking number, vendor and ETA, each change written to history. **Received** adds stock, or creates a new item for a free-text request. |
| I13 | `/inventory/requests/<id>/delete` | POST | operator | — | raw | Operators may delete their own pending requests; managers may delete any. |
| I14 | `/inventory/requests/<id>/update_tracking` | POST | manager | — | raw | **Shipments:** refreshes carrier tracking through EasyPost (`EASYPOST_API_KEY`) and stores status, ETA and events. |

## 7. Skeeball (`app/routes/skeeball.py`, prefix `/skeeball`)

The lane manager, GPIO and revenue scheduler start lazily on the first request that touches a lane (see
§10). "Pi stats proxy" means a GET to `http://$RPI_STATS_HOST:$RPI_STATS_PORT` (default port **5002**) that
falls back to local lane state when the Pi doesn't answer. "Pi GPIO" means a POST to
`$RPI_GPIO_HOST:$RPI_GPIO_PORT` (default 5001).

| ID | Route | Methods | Role | Template | What it does |
|----|-------|---------|------|----------|--------------|
| S1 | `/skeeball/` | GET | login | `skeeball/index.html` | Lane overview; links to control, stats and logs. |
| S2 | `/skeeball/control` | GET | login | `skeeball/control.html` | Lane control panel (reset, status). |
| S3 | `/skeeball/stats` | GET | login | `skeeball/stats.html` | **Skeeball stats** per lane (and the JS polls S8/S10). |
| S4 | `/skeeball/logs` | GET | login | `skeeball/logs.html` | Client-side log viewer. |
| S5 | `/skeeball/simulator` | GET | login | `skeeball/simulator.html` | Test simulator (S15–S19). Linked only from S6. |
| S6 | `/skeeball/gpio-test` | GET | login | `skeeball/gpio_test.html` (standalone) | GPIO test page. **Not linked from anywhere.** |
| S7 | `/skeeball/api/health` | GET | **public** | JSON | Lane online flags. **Unauthenticated, and its first call starts GPIO, a polling thread and the revenue scheduler.** |
| S8 | `/skeeball/api/lanes` | GET | login | JSON | Pi stats proxy (`/api/lanes`), else local. |
| S9 | `/skeeball/api/lanes/<lane>/status` | GET | login | JSON | Pi stats proxy, else local. |
| S10 | `/skeeball/api/lanes/<lane>/stats` | GET | login | JSON | Pi stats proxy, else local. |
| S11 | `/skeeball/api/lanes/<lane>/revenue` | GET | login | JSON | Lane revenue. **No UI caller.** |
| S12 | `/skeeball/api/gpio/status` | GET | login | JSON | Mock or real GPIO. |
| S13 | `/skeeball/api/gpio/switch-mode` | POST | login | JSON | Switches mock or real GPIO. |
| S14 | `/skeeball/api/hardware/control` | POST | login | JSON | Pi GPIO forward (LEDs, solenoid), or a local reset of every lane. |
| S15–S19 | `/skeeball/api/simulator/{insert-coin,score-10,score-50,lane-track,ball-scored}` | POST | login | JSON | Simulator events. |
| S20 | `/skeeball/api/roll-outcome` | POST | login | JSON | Records a roll outcome. |
| S21 | `/skeeball/api/machine/reset` | POST | login | JSON | Resets the machine. |
| S22 | `/skeeball/api/lanes/<lane>/reset` | POST | login | JSON | Resets one lane. |
| S23 | `/skeeball/api/lanes/<lane>/trigger` | POST | login | JSON | Raw event trigger. **No UI caller.** |
| S24 | `/skeeball/api/lanes/<lane>/register-game` | POST | login | JSON | Creates or links a "Skeeball Lane N" Game. **No UI caller** (`scripts/smoke` only). |
| S25 | `/skeeball/api/lanes/<lane>/sync-revenue` | POST | login | JSON | Writes a PlayRecord from the day's coins and adds it to the totals. **No UI caller.** |
| S26 | `/skeeball/api/revenue/sync-all` | POST | login | JSON | Forces a scheduler sync. **No UI caller.** |
| S27 | `/skeeball/api/system/reboot` | POST | **login** | JSON | `sudo reboot` on a Pi (or a dev no-op with `ALLOW_DEV_REBOOT`). **No UI caller.** |

## 8. GATBOX rail history (`app/routes/rails.py`, prefix `/rails`): read-only views of Phase 1/2 data

| ID | Route | Methods | Role | Template | What it does |
|----|-------|---------|------|----------|--------------|
| L1 | `/rails/` | GET | login | `rails_floor.html` | The last 50 sessions that arrived. |
| L2 | `/rails/machine/<slug>` | GET | login | `rails_machine.html` | One machine's sessions with a stepped window chart (Chart.js). |
| L3 | `/rails/session/<uid>` | GET | login | `rails_session.html` | One trace (Chart.js) plus up to 300 readings as rows. |

These pages are in scope for the restyle only. Their data path is Phase 1 and stays untouched.

## 9. Reports and charts (`app/routes/reports.py`)

| ID | Route | Methods | Role | Template | What it does |
|----|-------|---------|------|----------|--------------|
| P1 | `/reports` | GET | manager | `reports.html` | 30-day revenue, top and worst performers, low stock, pending requests, open orders. **Also runs the monthly ranking update on GET.** |
| P2 | `/revenue_reports` | GET | manager | `revenue_reports.html` | Revenue over `?days=` with `?location=` (see F-15). |
| P3 | `/graphs` | GET | manager | `graphs.html` | Chart.js: daily revenue, top performers, status and location mix. |
| P4 | `/export_report` | GET | manager | — (PDF) | Full PDF with matplotlib charts. |
| P5 | `/export_report_debug` | GET | manager | — (PDF) | "Simplified PDF report for debugging". |
| P6 | `/export_revenue_report` | GET | manager | — (PDF) | Revenue PDF. |
| P7 | `/export_csv` | GET | manager | — (CSV) | Every game with totals and Top 5 / Top 10 counts. |

## 10. Admin, users and settings (`app/routes/admin.py`)

| ID | Route | Methods | Role | Template | What it does |
|----|-------|---------|------|----------|--------------|
| X1 | `/admin/users` | GET, POST | admin | `manage_users.html` | One POST endpoint with `action=` `toggle_active`, `reset_password`, `change_role` or `delete_user`. |
| X2 | `/admin/create_user` | GET, POST | admin | `create_user.html` | Username of 3+ characters, password of 6+ (no strength check here), role; forces a password change. |
| X3 | `/admin/storage` | GET | admin | `storage_admin.html` | Photo directory size against the 500 MB cap; button for X4. |
| X4 | `/admin/cleanup_photos` | POST | **manager** | — | Deletes photo files older than 365 days (see F-6). |
| X5 | `/backup_management` | GET | admin | `backup_management.html` | Lists `backups/arcade_backup_*.db`. |
| X6 | `/create_backup` | POST | admin | — | Runs `scripts/backup_database.py` (SQLite). |
| X7 | `/restore_backup` | POST | admin | — | Runs `scripts/restore_database.py` (SQLite). |
| X8 | `/download_backup/<filename>` | GET | admin | — | Sends a backup file. |
| X9 | `/delete_backup` | POST | admin | — | Deletes a backup file. |

There is no settings page. Configuration lives in `.env` (see `.env.example`).

## 11. Machine API, background jobs, integrations and scripts

### `/api/v1` (Phase 1 hub; stays untouched)

| ID | Route | Methods | Auth |
|----|-------|---------|------|
| V1 | `/api/v1/health` | GET | public |
| V2 | `/api/v1/ingest` | POST | device bearer token, 120/min |
| V3 | `/api/v1/roster` | GET | device, 60/min |
| V4 | `/api/v1/machines/<slug>/orders` | GET | device, 60/min |

CSRF-exempt by design. These are covered by `tests/test_api_v1_contract.py` and the `contract/` checksums,
and the redesign won't touch them.

### Background jobs (all in-process threads, started lazily by the skeeball blueprint)

- **LaneManager polling thread** (`skeeball/lane_manager.py`) and **serial bridge** (`skeeball/serial_bridge.py`).
- **RevenueScheduler** (`skeeball/revenue_scheduler.py`): a daily thread that writes lane revenue as PlayRecords.
- **Monthly ranking update:** not a job. It piggybacks on GET `/` and GET `/reports`.
- **Cron (outside the app):**
  - `scripts/daily_backup.sh` with `setup_daily_backup.sh` and `setup_backup_cron.sh` (SQLite)
  - `scripts/auto-update.sh` with `setup-auto-update-cron.sh`, which pulls from git and rebuilds a container
    under `/opt/arcade-tracker`

### Integrations

| Integration | Where | Config |
|-------------|-------|--------|
| Skeeball Pi stats API (:5002) | S8–S10 `fetch_from_raspberry_pi` | `RPI_STATS_HOST`, `RPI_STATS_PORT` |
| Skeeball Pi GPIO API (:5001) | S14 | `RPI_GPIO_HOST`, `RPI_GPIO_PORT` |
| Pi-side programs | `rpi_skeeball/` (stats API server, GPIO API server, installer); not part of the web app | — |
| EasyPost shipment tracking | I14 | `EASYPOST_API_KEY` |
| AWS S3 photo copy | M9 `_upload_to_cloud` | `USE_CLOUD_STORAGE`, `AWS_*` |
| Roster | G11 (upload), `scripts/make_roster_map.py` and `apply_roster_map.py` (barcode = roster slug), V3 | — |
| QR labels | G13–G18, `segno` | `BASE_URL` |
| Public exposure | Code comments and `deploy/RUNBOOK.md` describe a **Cloudflare tunnel**; `scripts/setup_autostart.sh` installs an **ngrok** unit whose file isn't in the repo (see F-25) | — |
| PWA | `static/manifest.json`, `static/service-worker.js` (cache `arcade-tracker-v1`) | — |

### CLI scripts (`scripts/`)

`create_admin.py`, `create_device.py`, `check_schema.py`, `contract_checksums.py`, `backup_database.py`,
`restore_database.py`, `restore_from_sqlite.py`, `make_roster_map.py`, `apply_roster_map.py`, and `smoke/`
(checks against a running server).

---

## 12. Flags: dead, duplicated, unreachable, broken

Each flag is a claim from reading the code. Every one gets a test that proves or disproves it before
anything is changed.

### Dead or orphaned (proposed: delete when the matching page migrates)

- **F-1 Orphan templates (13):** `edit_maintenance.html`, `games.html`, `games_separated.html` and the
  `games_table.html` it includes, `maintenance.html`, `view_maintenance.html`,
  `update_maintenance_with_inventory.html`, `register.html`, `partials/_maintenance_table.html`,
  `partials/maintenance_table.html`, plus three non-templates in `templates/`: `maintenance_detail.py` (which
  calls a `url_for('maintenance_orders')` endpoint that doesn't exist), `responsive.css` and
  `responsive.css.txt`.
- **F-2 Dead Python:**
  - `RegisterForm` (no `/register` route).
  - `admin_required` and `manager_required` decorators (unused).
  - `app/security/middleware.py` and `app/security/config.py` (never imported), so `setup_security_logging`
    never runs.
  - `helpers.encrypt_file` / `decrypt_file`; `security.utils.safe_path_join`, `validate_file_upload` and
    `sanitize_filename` (defined, never called; the code that needs them doesn't use them).
  - `reports._update_top_rankings` (a no-op).
  - Unused imports across the route modules.
- **F-3 Duplicate code:**
  - Six root-level modules are byte-identical copies of `skeeball/*`: `game_logic`, `input_manager`,
    `lane_controller`, `lane_manager`, `serial_bridge` and `revenue_scheduler`. The app imports the package
    copy first.
  - The monthly ranking update exists twice (`dashboard._update_monthly_rankings_if_due` and
    `reports.update_monthly_rankings_if_due`).
  - `_check_low_stock_alert` exists twice (maintenance and inventory).
  - The work-order-with-parts logic is copied three times (M1, M2, M5).
- **F-4 Root-level clutter (not imported):**
  - Python: `security_config.py`, `load_env.py`, `create_tables.py`, `create_docs_pdf.py`,
    `generate_documentation.py`, `generate_icons.py`, `remove_emojis.py`, `create_iso_backup.py`.
  - Container files: `Dockerfile` and `docker-compose.yml` (the deployment is a systemd unit).
  - About 30 historical `*.md` files and two PDFs.

  I'd move them to `docs/history/`, not delete them. Say if you want any gone outright.
- **F-5 Debug leftovers:** `print("DEBUG: …")` dumps of full form data, including the CSRF token, in M9 and
  I2. The "debug" PDF route P5 is linked from no page (reachable by URL only).

### Broken or wrong (needs a decision or a fix)

- **F-6 Photo cleanup deletes live photos.** X4 removes every file older than a year without checking whether
  a work order still references it. The order keeps the filename, and the image 404s. It's manager-reachable.
- **F-7 Game images never display.** G2 and G4 save to `uploads/`, but the templates load
  `static/uploads/<file>`, and nothing serves `uploads/`.
- **F-8 Failed image saves still count.** `compress_and_save_image` returns `False` on a non-image, but M9
  and A4 ignore that and attach the filename anyway, which produces broken photos. Files are always JPEG but
  keep their original extension (`.png`, `.gif`).
- **F-9 A "Received" request can add stock twice.** I12 adds stock whenever the submitted status is
  *Received*, not only on the change to it, so re-saving notes on a received request adds stock again. A
  POST without `status` sets the status to `None`.
- **F-10 Deleting a game orphans rows.** G8 uses bulk `query.delete()`, which skips the ORM cascades, so the
  work logs, session tags, part usage and requests of those orders are left orphaned or hit FK errors on
  PostgreSQL. Deleting a user with history (X1) likely fails the same way.
- **F-11 The backups page can't back up production.** X5–X9 are SQLite-only (`arcade.db`), but production
  is PostgreSQL (`deploy/RUNBOOK.md` uses `pg_dump`). The page shows nothing useful and "Create backup" fails
  or backs up a stale file. `scripts/daily_backup.sh` has the same problem.
- **F-12 The 500 errors I can see:**
  - G5 with a bad or empty `date` field.
  - G4 with a non-numeric year.
  - The PDF exports when a description contains text that looks like a ReportLab tag, such as an
    unclosed `<b>` or a `<br>`. Plain `<` and `&` are fine; checked by `test_flags.py`.
  - The skeeball DB init runs `sqlite_master`, which fails on PostgreSQL (the error is swallowed, and the
    lane is never linked).
- **F-13 M3 mutates ORM objects** to strip newlines for its inline JavaScript. That's harmless today because
  the request never commits, but it's one autoflush away from rewriting machine names.
- **F-14 Writes on GET:**
  - `/` and `/reports` commit the monthly rankings.
  - G14 mints a barcode.
  - G18 mints report tokens.
  - S7, an unauthenticated GET, starts threads and creates a Game row.
- **F-15 The P2 location filter can only return nothing.** The query is already Floor-only, so any other
  location gives an empty result.

### Access control (security pass, Step 5)

- **F-16 `/g/<code>` requires operator.** It redirects to M1, which is operator-only, so a **readonly**
  user who scans a QR label gets "permission denied" on the dashboard. Decide what readonly should see on the
  machine page.
- **F-17 Any signed-in user, readonly included, can:** reboot the skeeball Pi (S27), drive its GPIO (S14),
  switch GPIO mode, write revenue (S25, S26), reset lanes, rotate coin-door tokens (G19), and mint tokens by
  printing (G18).
- **F-18 Path traversal in backups.** X7 and X9 join a form value onto `backups/` with no check, so
  `../instance/arcade.db` or `../.env` can be restored over or deleted. Combined with CSRF being off, a
  forged POST to a signed-in admin could delete the live SQLite file. X8 checks the prefix but not for `..`.
  M10 deletes any filename in the photo folder, not only that order's photos.
- **F-19 A fixed reset password.** X1 `reset_password` sets every reset account to `Arcade123!` and shows it
  in a flash message.
- **F-20 Unauthenticated skeeball GETs:**
  - Only S7 `/skeeball/api/health` is unauthenticated in the current code. S8–S10 are behind login.
  - S7 should stay public only if something outside polls it, and then without the side effects.
  - The brief mentions several unauthenticated GETs; if production differs from this branch, tell me.
- **F-21 CSRF:**
  - Raw POSTs with no token in their template: `coin_door_label_pick.html` (G19), `inventory_detail.html`
    (I6), `low_stock_alerts.html` (I8), `storage_admin.html` (X4), and one of the two forms in
    `maintenance_photos.html`.
  - None of the 20+ skeeball `fetch()` POSTs send a token.
  - A2 logout is a GET.
- **F-22 Cookies.** `SESSION_COOKIE_SECURE` and `REMEMBER_COOKIE_SECURE` are `False` while the site is public
  over HTTPS. With no `SECRET_KEY`, a random key is generated on every restart, which logs everyone out.
- **F-23 Weak login protection.** Lockout is per username and in memory, so anyone can lock out a known
  user, and there is no IP rate limit on `/login`. Info-level security events (`LOGIN_SUCCESS`,
  `LOGIN_FAILED`) are dropped because the app logger stays at WARNING (see F-2 for why).
- **F-24 Uploads are checked by extension only.** Pillow re-encoding is the real check, but its failure is
  ignored (F-8). There's no size check per file, only the 50 MB request cap.

### Unreachable or unclear

- **F-25 Two tunnel setups.** `scripts/setup_autostart.sh` installs `arcade-tracker-ngrok.service`, which
  doesn't exist in the repo. The code and runbook say Cloudflare tunnel. Is ngrok retired? If so, the script
  goes.
- **F-26 Skeeball pages nothing links to:**
  - S6 `gpio-test` is linked from nowhere.
  - S5 `simulator` is linked only from S6.
  - S11 and S23–S27 have no UI caller.

  Keep them, hide them behind admin, or strike?
- **F-27 The light theme toggle in `base.html`** goes away, per your answer.
- **F-28 S3 is the stats page in your brief, but it shows local lane counters.** The Pi :5002 proxy feeds
  S8–S10, which S3's JavaScript polls.

### Found while writing the characterization tests

- **F-29 A rail session with partial figures is a 500.** `rails_session.html` formats `powered_min` and
  `powered_max` whenever `powered_mean` is set, so a session that has a mean but no range crashes the page.
- **F-30 User text inside inline JavaScript.** `inventory_request_detail.html` (and the newline-stripping
  in M3, F-13) put item names and notes inside `onclick="…('{{ … }}')"`. Jinja's escaping is decoded back
  by the HTML parser before the JavaScript runs, so a quote in an item name breaks the button, and a
  crafted one runs script.
- **F-31 What a page offers disagrees with what the route allows.**
  - The nav shows "Add Game" only to managers, but G2 accepts operators.
  - The machine page shows "Record Plays" and "Edit" only to managers, but G4 and G5 accept operators.
  - "Rail History" is in the managers' nav only, but L1 accepts any signed-in user.
  - "Add Maintenance" is shown to readonly users, who are then refused.

  `test_visibility.py` pins today's behaviour as a snapshot. **Decision needed:** the redesign should show
  each role exactly what its routes allow.
- **F-32 Zero stock is rejected.** `DataRequired` on `stock_quantity` and `minimum_stock` treats 0 as
  missing, so an item with no stock can't be added or edited down to 0.
- **F-33 Fields that are never saved.** `InventoryItemForm` has category, location and image fields that
  the views never save.
- **F-34 "Download backup" can never work.** X8 checks `backups/<f>` relative to the working directory,
  but `send_file` resolves a relative path against `app.root_path` (the `app/` package), so it raises and
  returns a 500.

- **F-35 The dashboard's low-stock table is blank.** `index.html` reads `item.current_stock` and
  `item.min_stock`; the fields are `stock_quantity` and `minimum_stock`, and Jinja renders a missing
  attribute as empty. Found in the baseline screenshots.

- **F-36 First-run setup is a 500.** `setup.html` renders `form.hidden_tag()` and form fields, but the
  `/setup` view never passes a form, so `GET /setup` on an empty database crashes. A fresh install can
  only get its first admin from `scripts/create_admin.py`.
- **F-37 The PWA manifest names the real venue.** `static/manifest.json` carried the business's name in
  a public repository. It is renamed to "Arcade Tracker" in the base-shell step; the old value remains in
  git history.

---

## 13. Owner decisions (2026-10-08)

1. **Struck:** all of skeeball (S1–S27, the lane manager, GPIO, the revenue scheduler and the root-level
   copies, F-3) and P5 (the debug PDF). Skeeball is retired in its own commit after the safety net is in;
   `deploy/deploy.sh` then has to poll `/api/v1/health` instead of `/skeeball/api/health`. Everything else
   stays and is covered by `tests/characterization/`.
2. **Coin-door reporting stays as is:** anyone holding the coin-door key can file a work order with no
   login through the label inside the door (R1, G17–G19). For F-16 (a readonly user scanning the outside
   label), the default is a read-only machine page for readonly users and the work-order form for operators
   and up. Same `/g/<barcode>` URL, same barcodes.
3. **ngrok is retired.** `scripts/setup_autostart.sh`, which installed the missing ngrok unit, moved to
   `docs/history/` on 2026-10-08. The Cloudflare tunnel is the only public path.
4. **Skeeball:** retired on 2026-10-08 (see 1 and `docs/history/skeeball/README.md`).
5. **In-app backups stay.** The path traversal (F-18) and the download (F-34) get fixed in Step 5.
   PostgreSQL support (F-11) is a separate, later change.
