# Dependency upgrade proposal (Step 5.7, 2026-10-25)

A proposal for the owner to approve. **Nothing here is applied yet.** If approved, it lands as one
step that changes `requirements.txt` and the two small code changes in [Code that goes with it](#code-that-goes-with-it),
with the usual tests and a deploy.

## How this was checked

- **Latest versions** from PyPI's JSON API and npm's registry, on 2026-10-25.
- **Known advisories** for every pinned version, and for the unpinned packages a deploy installs
  alongside them, from PyPI's per-release vulnerability data (the same OSV database `pip-audit`
  uses; osv.dev itself is blocked from the build environment). Chart.js via npm's advisory API.
- **Python 3.11**, which production runs (Debian bookworm), not only the 3.13 used for day-to-day
  tests. Two clean environments were built with `uv`: today's exact pins, and the proposal.
- In both: the **full test suite** (1,091 tests), and an output comparison that the suite
  doesn't make: four photo uploads through the real upload path (a phone JPEG with an EXIF
  rotation, a transparent PNG, an animated GIF, a file that isn't an image), and the four PDFs
  (full report with matplotlib charts, revenue, maintenance report, a work order) rendered to
  images and diffed.

Results: **1,091 passed in both. Photos: same results in both. PDFs: all 6 pages pixel-identical.**

## Recommended now

| Package | Pinned | Proposed | Why |
|---|---|---|---|
| **Pillow** | 12.1.1 | **13.0.0** | ~70 advisories: memory corruption, possible code execution, decompression bombs. Some fixes (a heap overflow writing JPEG comments, GIF-comment and PNG-EXIF denial of service) exist only in 13.0. Every machine photo and work-order photo staff upload goes through it. |
| **cryptography** | 46.0.5 | **remove** | Nothing imports it since 5.6 removed the unused backup-encryption helpers, and nothing depends on it. Removing it clears its 9 advisories (certificate checks, a buffer overflow, bundled OpenSSL). |
| requests | 2.32.5 | 2.34.2 | Advisory (predictable temp file in zip extraction), fixed in 2.33. Used by easypost and the smoke script. |
| Werkzeug | 3.1.7 | 3.1.9 | Advisory in `safe_join`; Windows-only, so not reachable on the server, but a patch release. |
| certifi | unpinned | `>=2026.10.19` | Advisory. `pip install -r` won't upgrade an already-installed transitive package, so production keeps whatever it first got unless asked. |
| SQLAlchemy | 2.0.49 | 2.0.55 | Six patch releases in the same 2.0 series. Stays on 2.0 (see below). |
| psycopg2-binary | 2.9.12 | 2.9.13 | Patch. |
| Flask-WTF | 1.2.2 | 1.3.0 | Minor; six months old. |
| WTForms | 3.2.1 | 3.2.2 | Patch in the same series. |
| python-dotenv | 1.2.2 | 1.2.4 | Patch. |
| reportlab | 4.4.10 | 4.5.1 | Latest 4.x; PDFs pixel-identical. |
| matplotlib | 3.10.8 | 3.10.9 | Patch; report charts pixel-identical. |
| easypost | 10.6.0 | 10.7.0 | Minor. |
| pytest (dev) | 9.0.1 | 9.1.1 | Advisory (shared `/tmp` directory, local only). |

Unchanged, already current: Flask 3.1.3, Flask-SQLAlchemy 3.1.1, Flask-Login 0.6.3, Flask-Migrate 4.1.0,
waitress 3.0.2, Flask-Limiter 4.1.1, segno 1.6.6. None of these has a known advisory.

## Code that goes with it

1. **Only decode the formats we accept (hardening).** `compress_and_save_image` calls
   `Image.open(file)`, which will parse any of Pillow's ~40 formats (TIFF, EPS, PDF, PSD, FITS...),
   whatever the file is named. That's where almost every advisory above lives. Opening with
   `formats=("JPEG", "PNG", "GIF")` refuses the rest before any parser runs, on any Pillow
   version. Checked on 12.1.1 and 13.0.0: JPEG, PNG and GIF open; so does MPO, the format some
   phone cameras write, because Pillow opens it through the JPEG plugin (listing `"MPO"` itself
   raises a `KeyError`); a TIFF or EPS renamed `.png`, and a BMP, are refused.
2. **F-42, portrait photos stored sideways.** Phones save portrait photos as landscape pixels plus
   an EXIF rotation flag. The upload code ignores the flag and the saved JPEG drops it, so upright
   photos show on their side. One line, `ImageOps.exif_transpose(img)`, fixes it. Found by the
   comparison above; the same in both versions.

## Not now

| What | Why wait |
|---|---|
| SQLAlchemy 2.1 + psycopg 3 | 2.1 changes the default PostgreSQL driver to psycopg 3, so it needs a driver change and a database-URL check of its own (see the note in `requirements.txt`). No advisory pushes it. |
| reportlab 5.x | A new major version, three days old. 4.5.1 covers us. |
| WTForms 3.3.x | Released yesterday. Revisit in a couple of weeks. |
| matplotlib 3.11 | A minor release, but it only draws the PDF charts; no reason to move yet. |
| Chart.js 3.9.1 → 4.6.1 | No advisory. Version 4 changes some options and the bundle name; worth its own small step with before/after screenshots of every chart. |
| playwright 1.63 → 1.64 (dev) | Must match the browser build it drives; do it with the next screenshot work. |
| Python 3.11 | Supported until October 2027. Moving means a Debian upgrade on the server, which is its own job. |

## If approved

One commit: `requirements.txt` as above, `cryptography` removed, the two code changes with tests (a
TIFF named `.png` is refused; a rotated phone JPEG is saved upright). The full suite on 3.11 and 3.13,
the photo and PDF comparison again, then a normal `deploy.sh`, which installs the new versions.
