"""Maintenance forms."""

from flask_wtf import FlaskForm
from wtforms import (
    FieldList,
    FloatField,
    FormField,
    IntegerField,
    SelectField,
    StringField,
    SubmitField,
    TextAreaField,
)
from wtforms.validators import DataRequired, NumberRange, Optional


class InventoryUsageForm(FlaskForm):
    """Inline sub-form for tracking inventory items used during maintenance."""

    inventory_item_id = SelectField("Item", coerce=int, validators=[Optional()])
    quantity_used = IntegerField(
        "Quantity", validators=[Optional(), NumberRange(min=1)]
    )


class MaintenanceWithInventoryForm(FlaskForm):
    """Full maintenance record with nested inventory usage rows."""

    issue_description = TextAreaField(
        "Issue Description", validators=[DataRequired()]
    )
    fix_description = TextAreaField(
        "Initial Assessment/Diagnosis", validators=[Optional()]
    )
    cost = FloatField(
        "Total Cost ($)", validators=[Optional(), NumberRange(min=0)]
    )
    technician = StringField("Technician", validators=[Optional()])
    status = SelectField(
        "Status",
        choices=[
            ("Open", "Open"),
            ("In_Progress", "In Progress"),
            ("Fixed", "Fixed"),
            ("Deferred", "Deferred"),
        ],
        validators=[DataRequired()],
    )

    # Inventory usage fields
    inventory_items = FieldList(
        FormField(InventoryUsageForm), min_entries=5, max_entries=10
    )

    submit = SubmitField("Save Maintenance Record")
