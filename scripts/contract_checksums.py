#!/usr/bin/env python3
"""Check, or regenerate, the checksums of a contract directory.

    python scripts/contract_checksums.py                    # check contract/v1
    python scripts/contract_checksums.py --write             # regenerate after an edit
    python scripts/contract_checksums.py --dir path/to/v1    # check a vendored copy

The contract is owned here and vendored into GATBOX at ``docs/contract/v1/``. Two copies of
anything drift, so each repository checks its own against this list in its test suite. A
mismatch means the copies have diverged, and the fix is to decide which is right rather than
to regenerate blindly.
"""
from __future__ import annotations

import argparse
import hashlib
import pathlib
import sys

HEADER = """# sha256 of every file in this directory, CHECKSUMS itself excepted.
#
# A test in this repository and another in GATBOX check their own copy against
# this list, so the vendored copy at docs/contract/v1/ cannot drift from the
# original without something going red. Regenerate with:
#   python scripts/contract_checksums.py --write
"""


def digests(root: pathlib.Path) -> dict[str, str]:
    """path relative to *root* -> sha256, for every file but CHECKSUMS."""
    out = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "CHECKSUMS":
            out[path.relative_to(root).as_posix()] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
    return out


def stored(root: pathlib.Path) -> dict[str, str]:
    """What CHECKSUMS claims. Raises FileNotFoundError when there is none."""
    out = {}
    for line in (root / "CHECKSUMS").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        digest, _, name = line.partition("  ")
        out[name] = digest
    return out


def compare(root: pathlib.Path) -> list[str]:
    """Human-readable problems; empty means the directory matches its CHECKSUMS."""
    actual, claimed = digests(root), stored(root)
    problems = []
    for name in sorted(set(actual) | set(claimed)):
        if name not in claimed:
            problems.append(f"{name}: present but not in CHECKSUMS")
        elif name not in actual:
            problems.append(f"{name}: in CHECKSUMS but missing from {root}")
        elif actual[name] != claimed[name]:
            problems.append(f"{name}: changed since CHECKSUMS was written")
    return problems


def write(root: pathlib.Path) -> None:
    lines = [HEADER]
    for name, digest in digests(root).items():
        lines.append(f"{digest}  {name}")
    (root / "CHECKSUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--dir", default="contract/v1", help="the contract directory")
    p.add_argument("--write", action="store_true", help="regenerate CHECKSUMS")
    args = p.parse_args()

    root = pathlib.Path(args.dir)
    if not root.is_dir():
        print(f"no such directory: {root}", file=sys.stderr)
        return 2

    if args.write:
        write(root)
        print(f"wrote {root / 'CHECKSUMS'} ({len(digests(root))} files)")
        return 0

    problems = compare(root)
    if problems:
        print(f"{root} does not match its CHECKSUMS:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print(f"{root}: {len(digests(root))} files, all match")
    return 0


if __name__ == "__main__":
    sys.exit(main())
