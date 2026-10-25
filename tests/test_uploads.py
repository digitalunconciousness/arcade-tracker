"""Uploaded photos (Step 5.7): only JPEG, PNG and GIF are decoded, and phone rotation is applied.

Every upload (machine photos, work-order photos, profile pictures) goes through
app.utils.helpers.compress_and_save_image, so testing it covers all three.
"""
from __future__ import annotations

import io

import pytest
from PIL import Image
from werkzeug.datastructures import FileStorage

from app.utils.helpers import compress_and_save_image


def encoded(fmt, size=(40, 20), **kw) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, (200, 40, 120)).save(buf, fmt, **kw)
    return buf.getvalue()


def upload(data: bytes, name: str) -> FileStorage:
    return FileStorage(io.BytesIO(data), filename=name)


def phone_mpo() -> bytes:
    """What some phone cameras write: a JPEG-based multi-picture file."""
    buf = io.BytesIO()
    Image.new("RGB", (40, 20), "red").save(buf, "MPO", save_all=True,
                                          append_images=[Image.new("RGB", (40, 20), "blue")])
    return buf.getvalue()


@pytest.mark.parametrize(("name", "data"), [
    ("photo.jpg", encoded("JPEG")),
    ("photo.png", encoded("PNG")),
    ("photo.gif", encoded("GIF")),
    ("phone.jpg", phone_mpo()),
], ids=["jpeg", "png", "gif", "phone-mpo"])
def test_the_formats_staff_upload_are_saved(tmp_path, name, data):
    out = tmp_path / "saved.jpg"
    assert compress_and_save_image(upload(data, name), str(out))
    assert Image.open(out).format == "JPEG"


@pytest.mark.parametrize(("name", "data"), [
    ("innocent.png", encoded("TIFF")),       # a TIFF wearing a .png name
    ("innocent.jpg", encoded("EPS")),
    ("innocent.png", encoded("BMP")),
    ("innocent.png", b"not an image at all"),
], ids=["tiff-as-png", "eps-as-jpg", "bmp-as-png", "not-an-image"])
def test_any_other_format_is_refused_before_it_is_parsed(tmp_path, name, data):
    """Pillow's advisories are mostly in parsers for formats nobody uploads here."""
    out = tmp_path / "saved.jpg"
    assert not compress_and_save_image(upload(data, name), str(out))
    assert not out.exists()


def test_a_portrait_phone_photo_is_saved_upright(tmp_path):
    """F-42: landscape pixels plus an EXIF 'rotate 90' flag; the flag was dropped on save."""
    exif = Image.Exif()
    exif[0x0112] = 6                                           # rotate 90 degrees clockwise
    out = tmp_path / "saved.jpg"
    assert compress_and_save_image(upload(encoded("JPEG", (400, 200), exif=exif), "p.jpg"),
                                   str(out))
    assert Image.open(out).size == (200, 400)


def test_a_disguised_file_is_refused_through_a_real_upload(client, app):
    """The machine form, end to end: a TIFF named .png is not a photo."""
    import sys

    sys.path.insert(0, "tests/characterization")
    from char_support import login
    from seed import seed_floor

    seed_floor()
    login(client, "operator")
    resp = client.post("/add_game", data={
        "name": "Galaxy Runner", "image": (io.BytesIO(encoded("TIFF")), "cab.png")},
        content_type="multipart/form-data")
    assert resp.status_code == 400 and "could not be read" in resp.get_data(as_text=True)
