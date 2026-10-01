# Server runbook

Everything here runs **on the server** (the arcade-tracker LXC) as root. The
repository is at `/opt/arcade-tracker`; the virtualenv it uses is deliberately
*outside* that directory.

## Routine deploy

```bash
sudo /opt/arcade-tracker/deploy/deploy.sh --check    # preflight, changes nothing
sudo /opt/arcade-tracker/deploy/deploy.sh
```

It backs the database up with `pg_dump` before touching anything, refuses to
continue if the dump is too small to restore from, and stops at the first
failure. If the health check fails it prints the exact rollback commands.

## One-time cut-over

Do this **once**, in this order.

The order is load-bearing for two reasons. The pull is the commit that untracks
`venv/`, so the service has to be running from the external virtualenv *before* it
happens, or the deploy deletes the interpreter out from under itself. And the new
unit and `requirements.txt` only arrive *with* that pull — so they are read
straight out of the fetched objects first, which changes nothing in the working
tree.

```bash
# 1. Fetch, but do not touch the working tree. The running service is unaffected.
cd /opt/arcade-tracker
sudo git fetch origin master
sudo git log --oneline HEAD..origin/master        # what is about to land

# 2. Read the new files out of the fetched commit without checking anything out.
sudo git show origin/master:requirements.txt > /tmp/requirements.txt
sudo git show origin/master:arcade-tracker.service > /tmp/arcade-tracker.service
sudo git show origin/master:deploy/listen.conf.example > /tmp/listen.conf

# 3. The service account, and only the paths it must write.
#
#    Do NOT chown the whole checkout. Two reasons: git refuses to work in a
#    repository owned by another user ("detected dubious ownership"), which breaks
#    the pull below and every git call in deploy.sh; and a web service should not
#    be able to rewrite the code it is executing. The code stays root-owned and
#    the service user owns only what it writes -- the same paths the unit lists in
#    ReadWritePaths.
sudo adduser --system --group --no-create-home --home /opt/arcade-tracker arcade-tracker

sudo install -d -o arcade-tracker -g arcade-tracker -m 755 \
  /opt/arcade-tracker/instance \
  /opt/arcade-tracker/uploads \
  /opt/arcade-tracker/logs \
  /opt/arcade-tracker/static/maintenance_photos \
  /opt/arcade-tracker/static/profile_pics
sudo chown -R arcade-tracker:arcade-tracker \
  /opt/arcade-tracker/instance \
  /opt/arcade-tracker/uploads \
  /opt/arcade-tracker/logs \
  /opt/arcade-tracker/static/maintenance_photos \
  /opt/arcade-tracker/static/profile_pics

# .env holds DATABASE_URL and SECRET_KEY: root owns it, the service only reads it.
sudo chown root:arcade-tracker /opt/arcade-tracker/.env
sudo chmod 640 /opt/arcade-tracker/.env

# 4. The external virtualenv, from the new pinned requirements.
sudo apt-get update && sudo apt-get install -y python3-venv postgresql-client
sudo python3 -m venv /opt/arcade-tracker-venv
sudo /opt/arcade-tracker-venv/bin/pip install -U pip
sudo /opt/arcade-tracker-venv/bin/pip install -r /tmp/requirements.txt

# 5. Prove it can reach the database BEFORE switching the unit over. If this
#    fails, stop: nothing has changed yet and the old service is still running.
sudo -u arcade-tracker bash -c 'set -a; . /opt/arcade-tracker/.env; set +a; \
  /opt/arcade-tracker-venv/bin/python -c "
import sqlalchemy as sa, os
e = sa.create_engine(os.environ[\"DATABASE_URL\"])
with e.connect() as c: print(\"connected:\", c.execute(sa.text(\"select version()\")).scalar()[:40])
"'

# 6. The listen addresses. Loopback is what the tunnel uses; add this host's LAN
#    address so GATBOX can reach the hub directly instead of going out to
#    Cloudflare and back. Never 0.0.0.0.
sudo install -d -m 755 /etc/arcade-tracker
sudo cp /tmp/listen.conf /etc/arcade-tracker/listen.conf
sudo $EDITOR /etc/arcade-tracker/listen.conf

# 7. Switch the unit over.
sudo cp /tmp/arcade-tracker.service /etc/systemd/system/arcade-tracker.service
sudo systemctl daemon-reload
sudo systemctl restart arcade-tracker

# 8. Verify BEFORE pulling.
systemctl --no-pager status arcade-tracker
curl -fsS http://127.0.0.1:5000/ >/dev/null && echo "  serving OK"
ss -tlnp | grep ':5000'      # expect 127.0.0.1 and the LAN address, NOT 0.0.0.0
# And load the site in a browser, through the tunnel, before going further.

# 9. The old virtualenv is now dead weight, and it is the reason the tree is
#    dirty: it was rebuilt in place with Python 3.11 over a committed 3.12 one,
#    and git will not delete locally-modified files.
sudo rm -rf /opt/arcade-tracker/venv
sudo git -C /opt/arcade-tracker status --porcelain     # expect only the two untracked files below

# 10. Now pull.
sudo git -C /opt/arcade-tracker pull --ff-only origin master
sudo systemctl restart arcade-tracker
curl -fsS http://127.0.0.1:5000/ >/dev/null && echo "  serving OK"

# 11. From here on, deploys are one command.
sudo /opt/arcade-tracker/deploy/deploy.sh --check
```

Two untracked files on the server, `create_admin_fix.py` and
`requirements_server.txt`, are both folded into the repository now
(`scripts/create_admin.py`, and the `requirements.txt` / `requirements-pi.txt`
split — which keeps `segno`, that `requirements_server.txt` had dropped even
though the QR label route imports it). Compare them, then delete them.

## If you already chowned the whole checkout

```bash
# Put the code back under root and leave only the writable paths with the service.
sudo chown -R root:root /opt/arcade-tracker
sudo chown root:arcade-tracker /opt/arcade-tracker/.env && sudo chmod 640 /opt/arcade-tracker/.env
sudo chown -R arcade-tracker:arcade-tracker \
  /opt/arcade-tracker/instance /opt/arcade-tracker/uploads /opt/arcade-tracker/logs \
  /opt/arcade-tracker/static/maintenance_photos /opt/arcade-tracker/static/profile_pics

# Confirm git is happy again as root.
sudo git -C /opt/arcade-tracker status --porcelain
```

Only if you would rather keep the checkout owned by the service user, tell git so
explicitly instead — but prefer the above, which also stops the web service being
able to rewrite its own code:

```bash
sudo git config --global --add safe.directory /opt/arcade-tracker
```

## Rollback

```bash
sudo git -C /opt/arcade-tracker reset --hard <previous-sha>
sudo -u arcade-tracker bash -c 'set -a; . /opt/arcade-tracker/.env; set +a; \
  gunzip -c /var/backups/arcade-tracker/arcade_tracker-<stamp>.sql.gz | psql "$DATABASE_URL"'
sudo systemctl restart arcade-tracker
```

`deploy.sh` prints the two values to substitute when it fails.

## Notes

- **PostgreSQL has no `alembic_version` row** until it is stamped: its schema was
  built by `db.create_all()`, so every column the migrations add already exists
  and `flask db upgrade` would fail on duplicates. Stamp it once (see the restore
  runbook) before the first `deploy.sh`.
- `deploy.sh`'s liveness gate is `/`, the thinnest path that proves the app is
  serving. It probes `/skeeball/api/health` afterwards and only warns: that route
  reaches the lane manager and so gpiozero, and a dependency problem there should
  not fail a deploy that is otherwise fine.
- `/skeeball/api/health` is the one route with no login. Do not add a session
  requirement to it.
- The migrations cannot build a schema from nothing — none of them creates the
  base tables. A brand-new database is made with `create_all` and then
  `flask db stamp head`, not `flask db upgrade`.
