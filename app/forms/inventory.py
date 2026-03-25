"""Inventory forms."""

from flask_wtf import FlaskForm
from wtforms import (
    FileField,
    FloatField,
    IntegerField,
    SelectField,
    SelectMultipleField,
    StringField,
    SubmitField,
    TextAreaField,
)
from wtforms.validators import DataRequired, NumberRange, Optional


class InventoryItemForm(FlaskForm):
    """Create or edit an inventory item."""

    name = StringField("Item Name", validators=[DataRequired()])
    part_number = StringField("SKU / Part Number", validators=[Optional()])
    category = SelectField(
        "Category",
        choices=[
            ("", "-- Select Category --"),
            ("parts", "Parts"),
            ("supplies", "Supplies"),
            ("electronics", "Electronics"),
            ("mechanical", "Mechanical"),
            ("cosmetic", "Cosmetic"),
            ("other", "Other"),
        ],
        validators=[Optional()],
    )
    description = TextAreaField("Description", validators=[Optional()])
    stock_quantity = IntegerField(
        "Stock Quantity", validators=[DataRequired(), NumberRange(min=0)]
    )
    minimum_stock = IntegerField(
        "Minimum Stock Level",
        validators=[DataRequired(), NumberRange(min=0)],
    )
    unit_price = FloatField(
        "Unit Price ($)", validators=[Optional(), NumberRange(min=0)]
    )
    supplier = StringField("Supplier", validators=[Optional()])
    location = StringField("Storage Location", validators=[Optional()])
    compatible_games = SelectMultipleField(
        "Compatible Games", coerce=int, validators=[Optional()]
    )
    notes = TextAreaField("Notes", validators=[Optional()])
    image = FileField("Item Image", validators=[Optional()])
    submit = SubmitField("Save Item")


class StockAdjustmentForm(FlaskForm):
    """Adjust inventory stock quantity."""

    adjustment_type = SelectField(
        "Type",
        choices=[
            ("added", "Stock Added"),
            ("removed", "Stock Removed"),
            ("used", "Used in Repair"),
            ("adjusted", "Inventory Adjustment"),
            ("damaged", "Damaged / Write-off"),
            ("returned", "Returned to Supplier"),
        ],
        validators=[DataRequired()],
    )
    quantity = IntegerField("Quantity", validators=[DataRequired()])
    reason = StringField("Reason", validators=[Optional()])
    submit = SubmitField("Update Stock")
