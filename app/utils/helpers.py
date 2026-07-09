"""General-purpose utility functions for the Arcade Tracker application."""

from __future__ import annotations

import os
import re
import time
from pathlib import Path

ALLOWED_EXTENSIONS: set[str] = {"png", "jpg", "jpeg", "gif"}


def allowed_file(filename: str) -> bool:
    """Check whether *filename* has an allowed image extension.

    Returns:
        ``True`` when the extension (case-insensitive) is in
        :data:`ALLOWED_EXTENSIONS`, ``False`` otherwise.
    """
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def compress_and_save_image(
    file,
    file_path: str,
    max_size: tuple[int, int] = (1200, 1200),
    quality: int = 85,
) -> bool:
    """Compress and save an uploaded image file.

    Uses Pillow to resize the image so that neither dimension exceeds
    *max_size* and saves it at the given *quality* level.

    Args:
        file: A file-like object (e.g. ``request.files['photo']``).
        file_path: Destination path on disk.
        max_size: Maximum ``(width, height)`` in pixels.
        quality: JPEG quality (1–100).

    Returns:
        ``True`` on success, ``False`` on error.
    """
    try:
        from PIL import Image

        img = Image.open(file)

        # Convert RGBA/P modes to RGB for JPEG compatibility
        if img.mode in ("RGBA", "P"):
            img = img.convert("RGB")

        img.thumbnail(max_size, Image.LANCZOS)
        img.save(file_path, "JPEG", quality=quality, optimize=True)
        return True
    except Exception:
        return False


def get_directory_size(directory: str) -> float:
    """Return the total size of *directory* in megabytes.

    Walks the directory tree and sums file sizes.  Returns ``0.0`` if the
    directory does not exist.
    """
    total_bytes = 0
    dir_path = Path(directory)
    if not dir_path.is_dir():
        return 0.0
    for entry in dir_path.rglob("*"):
        if entry.is_file():
            total_bytes += entry.stat().st_size
    return total_bytes / (1024 * 1024)


def cleanup_old_photos(max_age_days: int = 365) -> int:
    """Remove maintenance photos older than *max_age_days*.

    Scans the ``static/maintenance_photos`` directory relative to the
    application root and deletes files whose modification time exceeds
    the threshold.

    Returns:
        The number of files removed.
    """
    base_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), os.pardir, os.pardir)
    )
    photos_dir = os.path.join(base_dir, "static", "maintenance_photos")

    if not os.path.isdir(photos_dir):
        return 0

    cutoff = time.time() - (max_age_days * 86400)
    removed = 0

    for filename in os.listdir(photos_dir):
        filepath = os.path.join(photos_dir, filename)
        if os.path.isfile(filepath) and os.path.getmtime(filepath) < cutoff:
            os.remove(filepath)
            removed += 1

    return removed


def slugify(text: str) -> str:
    """Return a lowercase, hyphenated slug of *text* (a-z, 0-9 and hyphens only)."""
    text = (text or "").lower().strip()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    return text.strip("-")


def generate_unique_barcode(name: str, taken: set[str]) -> str:
    """Build a stable, unique barcode slug from *name*.

    Deterministic from the game name (so a rebuilt DB regenerates the same
    labels), with a numeric suffix only when the base slug is already used by a
    different game (e.g. the video *Batman* vs the pinball *Batman*). The
    chosen slug is added to *taken* so callers can keep it unique across a batch.
    """
    base = (slugify(name) or "game")[:60]
    candidate = base
    n = 2
    while candidate in taken:
        candidate = f"{base}-{n}"
        n += 1
    taken.add(candidate)
    return candidate


def _dedupe(items: list) -> list:
    """Return *items* with duplicates removed, preserving first-seen order."""
    seen: set = set()
    out: list = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _compose_service_notes(entry: dict, platforms: dict) -> str | None:
    """Build a human-readable service block from a roster entry + its platform.

    Merges the platform's shared ``desc``/``faults``/``parts``/``pm`` with the
    entry's own ``risk``/``faults``/``parts``/``notes`` so the recovered record
    carries the maintenance intel, not just the name.
    """
    lines: list[str] = []
    plat = platforms.get(entry.get("platform")) if entry.get("platform") else None

    if plat and plat.get("desc"):
        lines.append(f"Platform: {plat['desc']}")

    risk = entry.get("risk") or []
    if risk:
        lines.append("Risk flags: " + ", ".join(risk))

    faults = _dedupe(
        list(plat.get("faults", []) if plat else []) + list(entry.get("faults") or [])
    )
    if faults:
        lines.append("Known faults: " + "; ".join(faults))

    parts = _dedupe(
        list(plat.get("parts", []) if plat else []) + list(entry.get("parts") or [])
    )
    if parts:
        lines.append("Parts: " + "; ".join(parts))

    if plat and plat.get("pm"):
        lines.append("PM: " + plat["pm"])

    if entry.get("notes"):
        lines.append("Notes: " + entry["notes"])

    return "\n".join(lines) if lines else None


def import_games_from_roster(data: dict) -> dict:
    """Import games from a barcade-roster JSON structure into the database.

    Consumes the ``catbox-barcade-roster.json`` schema: ``video_games`` /
    ``pinball`` / ``retired`` arrays plus a shared ``meta.platforms`` service
    dictionary. Idempotent — matches existing games by name (case-insensitive)
    and skips them, so re-running never creates duplicates. The caller is
    responsible for ``db.session.commit()``.

    Returns:
        ``{"added": int, "skipped": int, "errors": list[str]}``.
    """
    from app.extensions import db
    from app.models import Game

    platforms = (data.get("meta") or {}).get("platforms") or {}
    result: dict = {"added": 0, "skipped": 0, "errors": []}

    # Names already in the DB *before* this import. We only skip against these,
    # not against rows added during this run — the roster legitimately contains
    # distinct machines that share a name (e.g. a Batman video game AND a Batman
    # pinball), and both must import. Re-running stays idempotent because the
    # second run sees both already in the DB.
    existing = Game.query.all()
    names_lower = {g.name.strip().lower() for g in existing if g.name}
    taken_barcodes = {g.barcode for g in existing if g.barcode}

    # (array key, default location, default status, is_pinball)
    sections = [
        ("video_games", "Floor", "Working", False),
        ("pinball", "Floor", "Working", True),
        ("retired", "Warehouse", "Retired", False),
    ]

    for key, default_location, default_status, is_pinball in sections:
        for entry in data.get(key) or []:
            try:
                name = (entry.get("name") or "").strip()
                if not name:
                    result["errors"].append(f"{key}: entry with no name skipped")
                    continue
                if name.lower() in names_lower:
                    result["skipped"] += 1
                    continue

                game = Game(
                    name=name,
                    barcode=generate_unique_barcode(name, taken_barcodes),
                    manufacturer=(entry.get("mfr") or None),
                    location=default_location,
                    status=default_status,
                    genre="Pinball" if is_pinball else None,
                    notes=_compose_service_notes(entry, platforms),
                )
                db.session.add(game)
                result["added"] += 1
            except Exception as exc:  # noqa: BLE001 - report per-entry, keep going
                result["errors"].append(f"{entry.get('name', '?')}: {exc}")

    return result


def encrypt_file(data: bytes) -> bytes:
    """Encrypt *data* using Fernet with the application's ``BACKUP_KEY``.

    Requires :data:`flask.current_app` to be available (i.e. call inside
    a request or application context).

    Returns:
        The encrypted ciphertext bytes.
    """
    from cryptography.fernet import Fernet
    from flask import current_app

    key = current_app.config["BACKUP_KEY"]
    return Fernet(key).encrypt(data)


def decrypt_file(data: bytes) -> bytes:
    """Decrypt *data* using Fernet with the application's ``BACKUP_KEY``.

    Returns:
        The original plaintext bytes.
    """
    from cryptography.fernet import Fernet
    from flask import current_app

    key = current_app.config["BACKUP_KEY"]
    return Fernet(key).decrypt(data)
