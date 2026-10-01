#!/usr/bin/env bash
# Deploy arcade-tracker on the server. Backs the database up first, then pulls,
# installs, migrates, restarts and checks that the site answers. Stops at the
# first failure and never carries on past a bad step.
#
#   deploy/deploy.sh            # deploy          (run as root)
#   deploy/deploy.sh --check    # preflight only: change nothing
#
# The database is PostgreSQL on another host, so the backup is a pg_dump, not a
# file copy. DATABASE_URL comes from .env and is never printed.
set -euo pipefail

REPO=${ARCADE_REPO:-/opt/arcade-tracker}
VENV=${ARCADE_VENV:-/opt/arcade-tracker-venv}
BACKUPS=${ARCADE_BACKUPS:-/var/backups/arcade-tracker}
SERVICE=${ARCADE_SERVICE:-arcade-tracker}
# Liveness gate: the thinnest path that proves the app is serving. It used to be
# /skeeball/api/health, which reaches the lane manager and so gpiozero -- a
# dependency problem there would have failed every deploy for a reason that has
# nothing to do with whether the site is up.
HEALTH=${ARCADE_HEALTH:-http://127.0.0.1:5000/}
# Probed after the gate and reported, never fatal.
HEALTH_SUBSYSTEM=${ARCADE_HEALTH_SUBSYSTEM:-http://127.0.0.1:5000/skeeball/api/health}
BRANCH=${ARCADE_BRANCH:-master}
KEEP=${ARCADE_KEEP:-14}

check_only=0
[ "${1:-}" = "--check" ] && check_only=1

step() { printf '\n==> %s\n' "$*"; }
die()  { printf '\nFAILED: %s\n' "$*" >&2; exit 1; }

# --- preflight ---------------------------------------------------------------
step "Preflight"
[ "$(id -u)" = 0 ] || die "run as root (the container has no sudo; pct enter lands you as root)"
[ -d "$REPO/.git" ] || die "$REPO is not a git checkout"
[ -f "$REPO/.env" ] || die "$REPO/.env is missing (DATABASE_URL, SECRET_KEY)"
[ -x "$VENV/bin/python" ] || die "no virtualenv at $VENV -- build it first (see the cut-over runbook)"
command -v pg_dump >/dev/null || die "pg_dump not found: apt-get install postgresql-client"
command -v curl >/dev/null || die "curl not found: apt-get install curl"
systemctl list-unit-files "$SERVICE.service" >/dev/null 2>&1 || die "no $SERVICE.service installed"

cd "$REPO"
# A dirty tree means --ff-only will refuse, or will quietly keep someone's edit.
# Better to stop here and let a human decide.
if [ -n "$(git status --porcelain)" ]; then
    git status --short | sed 's/^/    /'
    die "the working tree has local changes; commit, stash or discard them first"
fi
current=$(git rev-parse --abbrev-ref HEAD)
[ "$current" = "$BRANCH" ] || die "on branch '$current', expected '$BRANCH' (set ARCADE_BRANCH to override)"

# shellcheck disable=SC1091
set -a; . "$REPO/.env"; set +a
[ -n "${DATABASE_URL:-}" ] || die "DATABASE_URL is not set in .env"
# Never print the URL: it carries the password.
printf '    database host : %s\n' "${DATABASE_URL##*@}"
printf '    repo          : %s (%s, %s)\n' "$REPO" "$current" "$(git rev-parse --short HEAD)"
printf '    venv          : %s (%s)\n' "$VENV" "$("$VENV/bin/python" -V)"
pg_dump --version | sed 's/^/    pg_dump       : /'
printf '    health        : %s\n' "$HEALTH"

if [ "$check_only" = 1 ]; then
    step "Preflight only (--check): nothing was changed."
    exit 0
fi

# --- 1. back the database up -------------------------------------------------
step "Backing the database up"
mkdir -p "$BACKUPS"; chmod 700 "$BACKUPS"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
dump="$BACKUPS/arcade_tracker-$stamp.sql.gz"
# --clean --if-exists so the dump can be replayed over an existing database.
pg_dump --clean --if-exists --no-owner --no-privileges "$DATABASE_URL" | gzip -9 > "$dump" \
    || die "pg_dump failed; nothing has changed yet"
size=$(stat -c %s "$dump")
# A dump of a populated database is far bigger than this; a few hundred bytes
# means pg_dump "succeeded" against nothing useful.
[ "$size" -gt 2048 ] || die "the dump is only $size bytes -- refusing to deploy over a database we cannot restore ($dump)"
printf '    %s (%s bytes)\n' "$dump" "$size"
chmod 600 "$dump"

# --- 2. pull ------------------------------------------------------------------
step "Pulling $BRANCH"
before=$(git rev-parse HEAD)
git pull --ff-only origin "$BRANCH" || die "git pull --ff-only refused; the branches have diverged"
after=$(git rev-parse HEAD)
if [ "$before" = "$after" ]; then
    printf '    already up to date (%s)\n' "$(git rev-parse --short HEAD)"
else
    git --no-pager log --oneline "$before..$after" | sed 's/^/    /'
fi

# --- 3. dependencies ----------------------------------------------------------
step "Installing dependencies into $VENV"
"$VENV/bin/python" -m pip install --quiet --disable-pip-version-check -r requirements.txt \
    || die "pip install failed"
# The driver is the thing most likely to be missing or mismatched; prove it imports.
"$VENV/bin/python" -c "import sqlalchemy, psycopg2; print('    SQLAlchemy', sqlalchemy.__version__, 'psycopg2', psycopg2.__version__.split()[0])" \
    || die "the database driver does not import; the application cannot reach PostgreSQL"

# --- 4. migrate ---------------------------------------------------------------
step "Applying migrations"
( cd "$REPO" && "$VENV/bin/flask" --app run:app db upgrade ) || die "flask db upgrade failed; the database may be half-migrated -- restore from $dump"

# --- 5. restart ---------------------------------------------------------------
step "Restarting $SERVICE"
systemctl restart "$SERVICE" || die "systemctl restart failed; see journalctl -u $SERVICE"

# --- 6. health ----------------------------------------------------------------
step "Health check"
ok=0
for i in 1 2 3 4 5 6 7 8 9 10; do
    if curl -fsS --max-time 5 "$HEALTH" >/dev/null 2>&1; then ok=1; break; fi
    sleep 2
    printf '    waiting (%s/10)\n' "$i"
done
if [ "$ok" != 1 ]; then
    printf '\n'
    systemctl --no-pager --lines=20 status "$SERVICE" || true
    printf '\nTo roll back:\n'
    printf '  git -C %s reset --hard %s\n' "$REPO" "$before"
    printf '  gunzip -c %s | psql "$DATABASE_URL"\n' "$dump"
    printf '  systemctl restart %s\n' "$SERVICE"
    die "the service did not answer $HEALTH"
fi
printf '    answered OK\n'

# --- 7. prune old dumps -------------------------------------------------------
step "Keeping the newest $KEEP dumps"
ls -1t "$BACKUPS"/arcade_tracker-*.sql.gz 2>/dev/null | tail -n +$((KEEP + 1)) | while read -r old; do
    rm -f -- "$old"; printf '    removed %s\n' "$(basename "$old")"
done

step "Deployed $(git rev-parse --short HEAD) and the site answers."
