"""General-purpose utility functions for the Arcade Tracker application."""

from __future__ import annotations

import os
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
