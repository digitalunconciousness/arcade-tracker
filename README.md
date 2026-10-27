# Cabcrawl runs the arcade floor: machines, work orders, parts and the coin meters.

**CABCRAWL** · GATBOX tests the board. Cabcrawl runs the floor.

Cabcrawl is a web app for the people who keep an arcade running: where every machine is, what's
broken and who's fixing it, which parts are on the shelf, and what each cabinet earns. It's built
to be used on a phone at the cabinet as much as at a desk. It was called Arcade Tracker until
October 2026.

![The dashboard](docs/wiki/images/dashboard.png)

## What it does

- **Machines**: the floor and the warehouse, a page per cabinet, QR labels on every cabinet, coin
  meter rounds, and a rotation planner that suggests which games to swap.
- **Work orders**: problems reported by staff, or by anyone at the coin door without signing in;
  work logs, photos, parts used, and maintenance tasks that open orders when they come due.
- **Inventory**: parts and the places they're kept, labels, counts, requests, a shopping list,
  purchase orders, suppliers and serial-numbered units.
- **Rail history**: the power-rail readings [GATBOX](#gatbox) sends from the bench.
- **Reports**: plays and token value, maintenance, graphs, PDFs and CSV.
- **Alerts** to phones through ntfy, and to Discord.
- **Roles**: read-only, operator, manager and admin, each offered only what it can use.

The [wiki](https://github.com/digitalunconciousness/cabcrawl/wiki) is the user guide, with a page
and screenshots for each of these. Its source is in [`docs/wiki/`](docs/wiki/).

## Run it locally

You need Python 3.11 or newer.

```bash
git clone https://github.com/digitalunconciousness/cabcrawl.git
cd cabcrawl
python3 -m venv venv && . venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# In .env, set SECRET_KEY to 32 or more random characters:
#   python3 -c "import secrets; print(secrets.token_urlsafe(48))"
# Without DATABASE_URL, the database is arcade.db (SQLite) in this folder.
set -a && . ./.env && set +a

# A new database: create the tables, then mark it as up to date with the migrations.
python -c "from app import create_app; from app.extensions import db; app = create_app(); app.app_context().push(); db.create_all()"
flask --app run:app db stamp head

python run.py          # http://localhost:5000
```

Open `/setup` to create the first admin account. After pulling a newer version, run
`flask --app run:app db upgrade`. Every setting is described on the wiki's
[Configuration](https://github.com/digitalunconciousness/cabcrawl/wiki/Configuration) page.

## Run it for real

Production runs Cabcrawl with PostgreSQL, under systemd, behind a Cloudflare tunnel.
[`deploy/RUNBOOK.md`](deploy/RUNBOOK.md) covers installing it, deploying updates
(`deploy/deploy.sh` backs up the database first), backups and restores, and what to check when
something goes wrong.

## GATBOX

GATBOX is a bench tool that tests a board's power rails. Connected to Cabcrawl as a device, it
sends each session's readings and can open work orders; Cabcrawl gives it the machine roster.
The API it uses, `/api/v1`, is specified in [`contract/v1/`](contract/v1/) and checked by tests.
Cabcrawl works without it.

## Working on the code

- [`CLAUDE.md`](CLAUDE.md): the rules every change follows, the commands, and how the code is
  put together. Read it first, whoever or whatever you are.
- [`docs/REDESIGN.md`](docs/REDESIGN.md): the design system and how to add a page.
- [`docs/FEATURES.md`](docs/FEATURES.md): every route, and known issues and decisions (F-1, F-2...).
- [`CHANGELOG.md`](CHANGELOG.md): what changed in each release.

```bash
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest
```

## License

Cabcrawl is free software: you can redistribute it and/or modify it under the terms of the
GNU Affero General Public License, version 3 ([`LICENSE`](LICENSE)). If you run a modified copy
as a website, its users can get your source: the footer of every page links to it, and
`SOURCE_URL` sets where.
