#!/usr/bin/env python3
"""Issue, list, rotate and disable the tokens machine clients use to push data.

A device is not a user: it has no session, no role, and reaches nothing a person sees. It
authenticates to the ``api_v1`` blueprint with a bearer token and that is all.

    python scripts/create_device.py --name gatbox-01
    python scripts/create_device.py --list
    python scripts/create_device.py --rotate gatbox-01
    python scripts/create_device.py --disable gatbox-01
    python scripts/create_device.py --enable gatbox-01

Run it from the repository root with the application's environment loaded, so DATABASE_URL
points at the real database:

    set -a && . ./.env && set +a && /opt/arcade-tracker-venv/bin/python \\
        scripts/create_device.py --name gatbox-01

**The token is shown once.** Only a hash of it is stored, so nothing here or in the
database can recover it afterwards -- which is the point: a leaked database does not leak a
working token. Lose it and rotate.
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app                      # noqa: E402
from app.extensions import db                   # noqa: E402
from app.models import Device                   # noqa: E402

NAME_MAX = 60


def _show_token(device: Device, token: str, what: str) -> None:
    print(f"\n{what}: {device.name}")
    print(f"  public id : {device.public_id}")
    print(f"  token     : {token}")
    print("\nThis is the only time the token is shown. Put it on the device now.")
    print("On the Pi it belongs in /etc/gatbox/hub.conf, mode 600, root-owned —")
    print("gatbox-sync reads it from there through LoadCredential.")


def _list(all_devices: list[Device]) -> int:
    if not all_devices:
        print("no devices yet; create one with --name")
        return 0
    width = max(len(d.name) for d in all_devices)
    print(f"{'name'.ljust(width)}  public id     state     last seen")
    for d in sorted(all_devices, key=lambda d: d.name):
        seen = d.last_seen.strftime("%Y-%m-%d %H:%M:%SZ") if d.last_seen else "never"
        state = "enabled" if d.enabled else "DISABLED"
        print(f"{d.name.ljust(width)}  {d.public_id}  {state:9} {seen}"
              + (f"  from {d.last_ip}" if d.last_ip else ""))
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--name", help="create a device with this name and issue a token")
    group.add_argument("--list", action="store_true", help="show the devices that exist")
    group.add_argument("--rotate", metavar="NAME", help="issue a new token, invalidating the old")
    group.add_argument("--disable", metavar="NAME", help="refuse this device's token")
    group.add_argument("--enable", metavar="NAME", help="accept it again")
    p.add_argument("--notes", help="what and where this device is")
    args = p.parse_args()

    app = create_app()
    with app.app_context():
        uri = app.config["SQLALCHEMY_DATABASE_URI"]
        print("database:", uri.split("@")[-1] if "@" in uri else uri)

        if args.list:
            return _list(Device.query.all())

        if args.name:
            name = args.name.strip()
            if not name or len(name) > NAME_MAX:
                print(f"name: 1 to {NAME_MAX} characters", file=sys.stderr)
                return 2
            if Device.query.filter_by(name=name).first():
                print(f"a device named {name!r} already exists; "
                      f"use --rotate to issue it a new token", file=sys.stderr)
                return 1
            device = Device(name=name, notes=args.notes)
            token = device.issue_token()
            db.session.add(device)
            db.session.commit()
            _show_token(device, token, "created")
            return 0

        target = args.rotate or args.disable or args.enable
        device = Device.query.filter_by(name=target).first()
        if device is None:
            print(f"no device named {target!r}; --list shows what exists", file=sys.stderr)
            return 1

        if args.rotate:
            token = device.issue_token()
            db.session.commit()
            _show_token(device, token, "rotated")
            print("\nThe previous token stops working immediately.")
            return 0

        device.enabled = bool(args.enable)
        db.session.commit()
        print(f"\n{device.name}: {'enabled' if device.enabled else 'disabled'}")
        if not device.enabled:
            print("Its token is refused until re-enabled. The token itself is unchanged,")
            print("so --enable restores it; use --rotate if it leaked.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
