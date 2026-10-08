# Skeeball (retired 2026-10-08)

The skeeball lanes were struck from the tracker by the owner on 2026-10-08
(`docs/FEATURES.md` §13). This folder keeps the code for reference. Nothing here is
imported, installed or tested.

| Here | Was |
|------|-----|
| `web/skeeball_routes.py`, `web/templates/` | the `/skeeball/*` blueprint and its six pages |
| `web/check_skeeball_revenue.py` | `scripts/smoke/` check against a running server |
| `package/` | `skeeball/`: lane manager, lane controller, serial bridge, revenue scheduler |
| `gpio_init.py`, `config.py` | GPIO mock/real setup and the lane's pin map |
| `rpi_skeeball/` | the Pi-side stats API (:5002) and GPIO API (:5001) servers and their installer |
| `requirements-pi.txt`, `.env.skeeball` | the Pi's packages and settings |
| `docs/` | the skeeball and GPIO notes that were in the repository root |

The six byte-identical copies of the `package/` modules that sat in the repository root
were deleted rather than kept twice.

Retiring this did not touch the Pi or its API: the Pi-side programs in `rpi_skeeball/`
are unchanged, only no longer called. Existing `Game` rows named "Skeeball Lane N" and
their play records stay in the database as ordinary machines.
