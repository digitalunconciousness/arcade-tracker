"""Game-related forms."""

from flask_wtf import FlaskForm
from wtforms import MultipleFileField, SubmitField
from wtforms.validators import Optional


class MaintenancePhotoForm(FlaskForm):
    photos = MultipleFileField(
        "Maintenance Photos",
        validators=[Optional()],
        render_kw={"multiple": True, "accept": "image/*"},
    )
    submit = SubmitField("Upload Photos")
