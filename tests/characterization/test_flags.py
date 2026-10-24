"""Known bugs from docs/FEATURES.md §12, each written as the behaviour we want.

Every test here is ``xfail(strict=True)``: it fails today, which proves the bug is real, and
the moment a fix lands it passes, which strict mode turns into a failure until the marker is
removed. So a fix cannot land silently, and a bug cannot quietly come back.

A flag with no test here is either configuration (cookie flags, logging) covered by the
Step 5 security tests, or a decision the owner has not made yet.
"""
from __future__ import annotations

import pytest


def flag(code: str, why: str):
    return pytest.mark.xfail(strict=True, reason=f"{code}: {why}")


# None open: F-15 was the last, fixed in 4.8c (tests/characterization/test_reports.py).
