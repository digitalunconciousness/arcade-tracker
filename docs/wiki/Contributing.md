# Contributing

Issues and pull requests are welcome.

## Before you open a pull request

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest                      # the whole suite, on SQLite
ruff check <the files you changed>
```

- Keep a change small and about one thing.
- Add a test that fails without your change.
- Pages are built from the macros in `templates/ui.html`; every component is shown at
  `/styleguide` (admins).
- No inline scripts or `onclick`: the content security policy refuses them.
- Every stock change goes through `app/services/stock_places.py`.
- A database change needs an Alembic migration that upgrades and downgrades cleanly.

## Things that must not change

- **Printed labels**: `/g/<barcode>`, `/p/`, `/i/` and `/u/` addresses, and the codes they carry.
  They're on cabinets and shelves already.
- **The GATBOX API** (`/api/v1`, `contract/v1/`) and the skeeball API.
- Any other URL change needs a redirect from the old address.

## This wiki

The wiki is published from `docs/wiki/` in the repository. To change a page, edit it there in a
pull request; edits made on the wiki itself are overwritten.

## Test data

Use invented names in tests and screenshots: no real arcade, machine roster, staff names,
addresses or tokens. `tests/characterization/seed.py` builds a synthetic arcade, and
`tests/screenshots/take.py` takes screenshots of every page from it.
