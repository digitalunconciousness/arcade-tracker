# Server runbook

Everything here runs **on the server** (the arcade-tracker LXC) **as root**.
`pct enter 131` from the Proxmox host lands you as root, and the container has no
`sudo` installed, so the commands below carry no `sudo` prefix. If you reach the
box some other way as a non-root user, prefix each one yourself.

The repository is at `/opt/arcade-tracker`; the virtualenv it uses is deliberately
*outside* that directory.

## Routine deploy

```bash
/opt/arcade-tracker/deploy/deploy.sh --check    # preflight, changes nothing
/opt/arcade-tracker/deploy/deploy.sh
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
git fetch origin master
git log --oneline HEAD..origin/master        # what is about to land

# 2. Read the new files out of the fetched commit without checking anything out.
git show origin/master:requirements.txt > /tmp/requirements.txt
git show origin/master:arcade-tracker.service > /tmp/arcade-tracker.service
git show origin/master:deploy/listen.conf.example > /tmp/listen.conf

# 3. The service account, and only the paths it must write.
#
#    Do NOT chown the whole checkout. Two reasons: git refuses to work in a
#    repository owned by another user ("detected dubious ownership"), which breaks
#    the pull below and every git call in deploy.sh; and a web service should not
#    be able to rewrite the code it is executing. The code stays root-owned and
#    the service user owns only what it writes -- the same paths the unit lists in
#    ReadWritePaths.
adduser --system --group --no-create-home --home /opt/arcade-tracker arcade-tracker

# All six that app/__init__.py:_create_directories creates at startup. They must
# exist, be writable by the service user, AND be listed in the unit's
# ReadWritePaths -- ProtectSystem=strict makes everything else read-only.
for d in instance uploads backups logs static/maintenance_photos static/profile_pics; do
  install -d -o arcade-tracker -g arcade-tracker -m 755 "/opt/arcade-tracker/$d"
  chown -R arcade-tracker:arcade-tracker "/opt/arcade-tracker/$d"
done

# .env holds DATABASE_URL and SECRET_KEY: root owns it, the service only reads it.
chown root:arcade-tracker /opt/arcade-tracker/.env
chmod 640 /opt/arcade-tracker/.env

# 4. The external virtualenv, from the new pinned requirements.
apt-get update && sudo apt-get install -y python3-venv postgresql-client
python3 -m venv /opt/arcade-tracker-venv
/opt/arcade-tracker-venv/bin/pip install -U pip
/opt/arcade-tracker-venv/bin/pip install -r /tmp/requirements.txt

# 5. Prove it can reach the database BEFORE switching the unit over. If this
#    fails, stop: nothing has changed yet and the old service is still running.
cat > /tmp/dbcheck.py <<'DBCHECK'
import os, sqlalchemy as sa
url = os.environ["DATABASE_URL"]
print("target  :", url.split("@")[-1])          # no credentials
engine = sa.create_engine(url)
with engine.connect() as c:
    print("server  :", c.execute(sa.text("select version()")).scalar()[:40])
    print("games   :", c.execute(sa.text("select count(*) from game")).scalar())
    print("maint   :", c.execute(sa.text("select count(*) from maintenance_record")).scalar())
    print("users   :", c.execute(sa.text('select count(*) from "user"')).scalar())
DBCHECK
chmod 644 /tmp/dbcheck.py
runuser -u arcade-tracker -- bash -c 'set -a; . /opt/arcade-tracker/.env; set +a; \
  exec /opt/arcade-tracker-venv/bin/python /tmp/dbcheck.py'

# 6. The listen addresses. Loopback is what the tunnel uses; add this host's LAN
#    address so GATBOX can reach the hub directly instead of going out to
#    Cloudflare and back. Never 0.0.0.0.
install -d -m 755 /etc/arcade-tracker
cp /tmp/listen.conf /etc/arcade-tracker/listen.conf
$EDITOR /etc/arcade-tracker/listen.conf

# 7. Switch the unit over.
cp /tmp/arcade-tracker.service /etc/systemd/system/arcade-tracker.service
systemctl daemon-reload
systemctl restart arcade-tracker

# 8. Verify BEFORE pulling.
systemctl --no-pager status arcade-tracker
# Wait for it to bind. `systemctl restart` returns as soon as the process is
# forked, and waitress needs a moment to import the application, so curling
# immediately reports "Couldn't connect" on a service that is perfectly fine.
for i in $(seq 20); do
  curl -fsS --max-time 2 http://127.0.0.1:5000/ >/dev/null 2>&1 && { echo "  serving OK"; break; }
  sleep 1
done
ss -tlnp | grep ':5000'      # expect 127.0.0.1 and the LAN address, NOT 0.0.0.0
# And load the site in a browser, through the tunnel, before going further.

# 9. The old virtualenv is now dead weight, and it is the reason the tree is
#    dirty: it was rebuilt in place with Python 3.11 over a committed 3.12 one,
#    and git will not delete locally-modified files.
rm -rf /opt/arcade-tracker/venv
git -C /opt/arcade-tracker status --porcelain     # expect only the two untracked files below

# 10. Now pull.
git -C /opt/arcade-tracker pull --ff-only origin master
systemctl restart arcade-tracker
# Wait for it to bind. `systemctl restart` returns as soon as the process is
# forked, and waitress needs a moment to import the application, so curling
# immediately reports "Couldn't connect" on a service that is perfectly fine.
for i in $(seq 20); do
  curl -fsS --max-time 2 http://127.0.0.1:5000/ >/dev/null 2>&1 && { echo "  serving OK"; break; }
  sleep 1
done

# 11. From here on, deploys are one command.
/opt/arcade-tracker/deploy/deploy.sh --check
```

Two untracked files on the server, `create_admin_fix.py` and
`requirements_server.txt`, are both folded into the repository now
(`scripts/create_admin.py`, and the `requirements.txt` / `requirements-pi.txt`
split — which keeps `segno`, that `requirements_server.txt` had dropped even
though the QR label route imports it). Compare them, then delete them.

## If you already chowned the whole checkout

```bash
# Put the code back under root and leave only the writable paths with the service.
chown -R root:root /opt/arcade-tracker
chown root:arcade-tracker /opt/arcade-tracker/.env && sudo chmod 640 /opt/arcade-tracker/.env
for d in instance uploads backups logs static/maintenance_photos static/profile_pics; do
  install -d -o arcade-tracker -g arcade-tracker -m 755 "/opt/arcade-tracker/$d"
  chown -R arcade-tracker:arcade-tracker "/opt/arcade-tracker/$d"
done

# Confirm git is happy again as root.
git -C /opt/arcade-tracker status --porcelain
```

Only if you would rather keep the checkout owned by the service user, tell git so
explicitly instead — but prefer the above, which also stops the web service being
able to rewrite its own code:

```bash
git config --global --add safe.directory /opt/arcade-tracker
```

## Rollback

```bash
git -C /opt/arcade-tracker reset --hard <previous-sha>
runuser -u arcade-tracker -- bash -c 'set -a; . /opt/arcade-tracker/.env; set +a; \
  gunzip -c /var/backups/arcade-tracker/arcade_tracker-<stamp>.sql.gz | psql "$DATABASE_URL"'
systemctl restart arcade-tracker
```

`deploy.sh` prints the two values to substitute when it fails.

## Notes

- **Never `flask db stamp head` on a database you have not checked.** Stamping
  marks migrations as applied *without running them*. A database built by
  `db.create_all()` at some point in the past is stamped at nothing, but its
  schema is only as new as the models were that day — so `stamp head` can claim a
  column exists that does not, `db upgrade` becomes a no-op, and the first page to
  touch that column raises `UndefinedColumn`. That is exactly what happened on
  2026-10-01: the tables were all present, `game.barcode` was not.

      python scripts/check_schema.py     # compares live schema to the models

  It names every missing table and column, says which revision introduced each,
  and prints the `stamp` + `upgrade` pair that repairs it. `deploy.sh` runs it
  after migrating and refuses to restart the service if anything is still missing.
- `deploy.sh`'s liveness gate is `/`, the thinnest path that proves the app is
  serving. It probes `/skeeball/api/health` afterwards and only warns: that route
  reaches the lane manager and so gpiozero, and a dependency problem there should
  not fail a deploy that is otherwise fine.
- `/skeeball/api/health` is the one route with no login. Do not add a session
  requirement to it.
- **Never curl straight after `systemctl restart`.** Type=simple means the restart
  returns as soon as the process is forked; waitress binds a moment later. Wait for
  readiness in a loop, as above. `deploy.sh` already does this (ten attempts, two
  seconds apart).
- **The client must be >= the server.** `deploy.sh --check` verifies it and prints
  the PGDG install commands if not. The server is PostgreSQL 17; Debian bookworm
  ships client 15, which `pg_dump` refuses to use against it.
- The migrations cannot build a schema from nothing — none of them creates the
  base tables. A brand-new database is made with `create_all` and then
  `flask db stamp head`, not `flask db upgrade`.
