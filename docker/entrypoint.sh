#!/bin/sh
# What the container runs:
#   web      prepare the database, then serve the app on port 5000 with waitress (the default)
#   alerts   send pending alerts every minute (the systemd timer's job on a server)
#   anything else is run as given, for example: docker compose run --rm cabcrawl python scripts/create_admin.py
set -e

case "${1:-web}" in
  web)
    python docker/prepare_db.py
    # Behind a reverse proxy, set TRUSTED_PROXY to its address so cookies are Secure over HTTPS.
    if [ -n "$TRUSTED_PROXY" ]; then
      set -- --trusted-proxy="$TRUSTED_PROXY" --trusted-proxy-headers=x-forwarded-proto
    else
      set --
    fi
    exec waitress-serve --listen=0.0.0.0:5000 "$@" --call app:create_app
    ;;
  alerts)
    while true; do
      python scripts/send_alerts.py || echo "send_alerts.py failed; trying again in a minute" >&2
      sleep 60
    done
    ;;
  *)
    exec "$@"
    ;;
esac
