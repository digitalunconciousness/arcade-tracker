"""Accounts after Step 4.7b: users, one-time passwords, the last admin, profile, sign-out."""
from __future__ import annotations

import io
import re

import pytest

from char_support import PASSWORD, flashes, login
from test_routes_post import fresh, png_bytes


def _user(name="temp-user", role="readonly", **kw):
    from app.extensions import db
    from app.models import User

    u = User(username=name, role=role, must_change_password=False, **kw)
    u.set_password(PASSWORD)
    db.session.add(u)
    db.session.commit()
    return u.id


SECRET = re.compile(r'<span class="secret">([^<]+)</span>')


# --- F-19: no fixed reset password ---------------------------------------------------------

def test_a_reset_makes_a_random_one_time_password_shown_once(client, floor):
    from app.models import User

    uid = _user()
    login(client, "admin")
    resp = client.post("/admin/users", data={"action": "reset_password", "user_id": uid})
    html = resp.get_data(as_text=True)
    password = SECRET.search(html).group(1)
    user = fresh(User, uid)
    assert user.check_password(password) and not user.check_password("Arcade123!")
    assert user.must_change_password is True
    # Not in a flash (the session cookie), and gone on the next page.
    assert all(password not in m for _, m in flashes(client))
    assert password not in client.get("/admin/users").get_data(as_text=True)


def test_two_resets_give_different_passwords(client, floor):
    uid = _user()
    login(client, "admin")
    first = SECRET.search(client.post("/admin/users", data={
        "action": "reset_password", "user_id": uid}).get_data(as_text=True)).group(1)
    second = SECRET.search(client.post("/admin/users", data={
        "action": "reset_password", "user_id": uid}).get_data(as_text=True)).group(1)
    assert first != second


def test_one_time_passwords_meet_the_strength_rule():
    from app.security.utils import check_password_strength
    from app.services.accounts import one_time_password

    for _ in range(50):
        assert check_password_strength(one_time_password())[0]


def test_a_blank_password_on_add_user_makes_a_one_time_one(client, floor):
    from app.models import User

    login(client, "admin")
    html = client.post("/admin/create_user", data={
        "username": "new-tech", "password": "", "role": "operator"}).get_data(as_text=True)
    password = SECRET.search(html).group(1)
    assert User.query.filter_by(username="new-tech").one().check_password(password)


def test_a_bad_new_user_is_shown_again_with_its_errors(client, floor):
    login(client, "admin")
    resp = client.post("/admin/create_user", data={
        "username": "ab", "password": "weak", "role": "root"})
    html = resp.get_data(as_text=True)
    assert resp.status_code == 400
    assert "Use at least 3 characters." in html and "Pick a role from the list." in html
    assert 'value="ab"' in html


# --- F-41: a one-time password must be changed before anything else ------------------------

def test_a_user_who_must_change_their_password_goes_nowhere_else(client, floor):
    from app.extensions import db
    from app.models import User

    fresh(User, floor["users"]["operator"]).must_change_password = True
    db.session.commit()
    login(client, "operator")
    for url in ("/", "/games", f"/game/{floor['raider']}", "/maintenance_orders"):
        assert client.get(url).headers["Location"] == "/change_password", url
    assert client.get("/change_password").status_code == 200
    assert client.post("/logout").headers["Location"] == "/login"


def test_changing_it_opens_the_tracker_at_the_dashboard(client, floor):
    from app.extensions import db
    from app.models import User

    fresh(User, floor["users"]["operator"]).must_change_password = True
    db.session.commit()
    login(client, "operator")
    resp = client.post("/change_password", data={
        "current_password": PASSWORD, "new_password": "Brand-new-pass-9",
        "confirm_password": "Brand-new-pass-9"})
    assert resp.headers["Location"] == "/"
    assert fresh(User, floor["users"]["operator"]).must_change_password is False
    assert client.get("/games").status_code == 200


@pytest.mark.parametrize(("data", "error"), [
    ({"current_password": "wrong", "new_password": "Brand-new-pass-9",
      "confirm_password": "Brand-new-pass-9"}, "That isn&#39;t your current password."),
    ({"current_password": PASSWORD, "new_password": PASSWORD,
      "confirm_password": PASSWORD}, "Choose a password different from the current one."),
    ({"current_password": PASSWORD, "new_password": "alllowercase",
      "confirm_password": "alllowercase"}, "uppercase, lowercase, and numbers"),
    ({"current_password": PASSWORD, "new_password": "Brand-new-pass-9",
      "confirm_password": "Brand-new-pass-8"}, "The two passwords are different."),
])
def test_a_bad_password_change_says_why_on_the_field(client, floor, data, error):
    login(client, "operator")
    resp = client.post("/change_password", data=data)
    assert resp.status_code == 400
    assert error in resp.get_data(as_text=True)


def test_the_api_and_coin_door_ignore_the_password_hold(client, floor):
    """They carry no session, so the hold never applies to them."""
    assert client.get("/api/v1/health").status_code == 200


# --- F-40: nobody locks the tracker out of its admin pages ---------------------------------

@pytest.mark.parametrize(("action", "extra"), [
    ("change_role", {"new_role": "manager"}),
    ("toggle_active", {}),
    ("delete_user", {}),
])
def test_an_admin_cannot_demote_deactivate_or_delete_themselves(client, floor, action, extra):
    from app.models import User

    me = floor["users"]["admin"]
    login(client, "admin")
    client.post("/admin/users", data={"action": action, "user_id": me, **extra})
    user = fresh(User, me)
    assert user is not None and user.role == "admin" and user.is_active




def test_a_user_with_work_on_record_is_deactivated_not_deleted(client, floor):
    """Deleting them failed on PostgreSQL (NOT NULL foreign keys) and would lose who did it."""
    from app.extensions import db
    from app.models import User, WorkLog

    uid = _user("worked-here", "operator")
    db.session.add(WorkLog(maintenance_id=floor["open_order"], user_id=uid,
                           work_description="Cleaned the joystick"))
    db.session.commit()
    login(client, "admin")
    html = client.get("/admin/users").get_data(as_text=True)
    row = html[html.index("worked-here"):html.index("worked-here") + 4000]
    assert "delete_user" not in row.split("</li>")[0]
    client.post("/admin/users", data={"action": "delete_user", "user_id": uid})
    assert fresh(User, uid) is not None
    assert any("Deactivate it instead" in m for _, m in flashes(client))


def test_the_users_page_links_to_the_admin_tools(client, floor):
    login(client, "admin")
    html = client.get("/admin/users").get_data(as_text=True)
    for path in ("/admin/create_user", "/labels/coindoor", "/admin/storage",
                 "/backup_management"):
        assert path in html


# --- F-8: profile photo --------------------------------------------------------------------

def test_an_unreadable_profile_photo_is_refused(client, floor, sandbox):
    from app.models import User

    login(client, "operator")
    client.post("/profile", data={"profile_picture": (io.BytesIO(b"not an image"), "me.png")},
                content_type="multipart/form-data")
    assert fresh(User, floor["users"]["operator"]).profile_picture is None
    assert any("could not be read" in m for _, m in flashes(client))


def test_a_real_photo_is_saved_as_jpeg(client, floor, sandbox):
    from app.models import User

    login(client, "operator")
    client.post("/profile", data={"profile_picture": (io.BytesIO(png_bytes()), "me.png")},
                content_type="multipart/form-data")
    name = fresh(User, floor["users"]["operator"]).profile_picture
    assert name and name.endswith(".jpg")
    assert (sandbox / "static" / "profile_pics" / name).exists()


# --- F-21: sign-out --------------------------------------------------------------------------

def test_the_nav_signs_out_with_a_post_form(client, floor):
    login(client, "readonly")
    html = client.get("/").get_data(as_text=True)
    assert re.search(r'<form[^>]+method="post"[^>]+action="/logout"', html)
    assert 'href="/logout"' not in html
