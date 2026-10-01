# Smoke checks against a running server

These are not unit tests and pytest does not collect them: each one talks to a
live instance over HTTP (`http://localhost:5000` by default) and some prompt for
input. They were `test_features.py` and `test_skeeball_revenue.py` at the
repository root, where pytest tried to collect them and failed on a refused
connection.

    ./venv/bin/python scripts/smoke/check_endpoints.py
    ./venv/bin/python scripts/smoke/check_skeeball_revenue.py
