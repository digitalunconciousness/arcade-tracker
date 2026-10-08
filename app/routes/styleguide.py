"""The living style guide: every design-system component, in every state, on one page.

Admin-only. It renders real templates with the real stylesheets, so it is where a
component is checked (focus, contrast, the 390px layout) before a page relies on it, and
what the screenshot tool captures to show the design system itself.
"""
from __future__ import annotations

from flask import Blueprint, render_template
from flask_login import login_required
from wtforms import Form, IntegerField, SelectField, StringField, TextAreaField
from wtforms.validators import DataRequired, Optional

from app.ui import TONES
from app.utils.decorators import requires_role

styleguide_bp = Blueprint("styleguide", __name__)


class _DemoForm(Form):
    """A plain WTForms form (no CSRF: it is never submitted) to show field states."""

    name = StringField("Machine name", validators=[DataRequired()])
    coins = IntegerField("Coin meter reading", validators=[DataRequired()])
    location = SelectField("Location", choices=[("Floor", "Floor"), ("Warehouse", "Warehouse")])
    notes = TextAreaField("Notes", validators=[Optional()])
    disabled = StringField("Barcode (fixed)")


@styleguide_bp.route("/styleguide")
@login_required
@requires_role("admin")
def styleguide():
    clean = _DemoForm(data={"name": "Neon Raider", "location": "Floor", "disabled": "neon-raider"})
    broken = _DemoForm(data={"name": "", "coins": None})
    broken.name.errors = ["Give the machine a name."]
    broken.coins.errors = ["Enter a whole number, at least the last reading (140)."]
    return render_template(
        "styleguide.html",
        clean=clean,
        broken=broken,
        tones=TONES,
    )
