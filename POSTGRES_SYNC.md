# Homelab Postgres Sync

The app itself always runs against local SQLite at catbox — that's what
`DATABASE_URL` points to by default (`app/__init__.py`), and it stays that
way. Catbox's internet connection isn't reliable enough to be a hard
dependency for every request the app makes, so Postgres is **not** the live
database the app talks to.

Instead, `scripts/sync_to_postgres.py` is a one-way mirror: it upserts every
row from the local SQLite DB into a Postgres instance on your homelab,
whenever it's run and the network happens to be up. If catbox is offline, the
sync just fails and retries on its next scheduled run — nothing is lost,
since it re-reads current SQLite state each time rather than diffing/queuing
individual changes.

## One-time setup

1. On the homelab box, create a database and user:
   ```sql
   CREATE DATABASE arcade;
   CREATE USER arcade WITH PASSWORD 'change-me';
   GRANT ALL PRIVILEGES ON DATABASE arcade TO arcade;
   ```
2. On catbox, add to `.env`:
   ```
   POSTGRES_SYNC_URL=postgresql://arcade:change-me@homelab-host:5432/arcade
   ```
3. Install the Postgres driver (already in `requirements.txt`):
   ```bash
   pip install -r requirements.txt
   ```
4. Run it once by hand to confirm connectivity and let it create the schema:
   ```bash
   python scripts/sync_to_postgres.py
   ```
   The first run creates all tables on the Postgres side (via SQLAlchemy
   metadata, mirroring the current models) and copies every row.

## Scheduling it

Copy the unit files and enable the timer so it runs automatically every 10
minutes:

```bash
sudo cp arcade-tracker-sync.service arcade-tracker-sync.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now arcade-tracker-sync.timer
```

Check status / logs:

```bash
systemctl status arcade-tracker-sync.timer
journalctl -u arcade-tracker-sync.service -f
```

Adjust `OnUnitActiveSec` in `arcade-tracker-sync.timer` if you want it more
or less frequent.

## Notes / limitations

- This is a **mirror for backup and reporting**, not live shared state.
  Don't run reports against the homelab copy expecting it to be perfectly
  current — it's as fresh as the last successful sync.
- Every run re-syncs the full DB (upsert by primary key). For an arcade this
  size that's cheap and simple; it avoids needing change-tracking columns or
  a write-queue.
- If you ever add a feature that needs catbox and home to see the *same*
  live data in real time (not just a periodic mirror), that's a different,
  bigger architecture (Postgres becomes the primary DB, and every write path
  at catbox needs an offline queue-and-replay layer). Not needed today.
