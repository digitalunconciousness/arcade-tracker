"""Inventory forms."""

from flask_wtf import FlaskForm
from wtforms import (
    DecimalField,
    IntegerField,
    SelectField,
    SelectMultipleField,
    StringField,
    TextAreaField,
)
from wtforms.validators import (
    DataRequired,
    InputRequired,
    Length,
    NumberRange,
    Optional,
)

from app.services.inventory import ADJUSTMENTS


class InventoryItemForm(FlaskForm):
    """Create or edit an inventory item.

    The counts use InputRequired, not DataRequired, which treats 0 as missing (F-32). The
    category, location and image fields the views never saved are gone (F-33).
    """

    name = StringField("Name", validators=[DataRequired(), Length(max=200)])
    part_number = StringField("Part number", validators=[Optional(), Length(max=100)])
    description = TextAreaField("Description", validators=[Optional()])
    stock_quantity = IntegerField("In stock", validators=[InputRequired(), NumberRange(min=0)])
    minimum_stock = IntegerField("Reorder at", validators=[InputRequired(), NumberRange(min=0)])
    unit_price = DecimalField("Unit price ($)", places=2,
                              validators=[Optional(), NumberRange(min=0)])
    supplier = StringField("Supplier", validators=[Optional(), Length(max=200)])
    compatible_games = SelectMultipleField("Fits these machines", coerce=int,
                                           validators=[Optional()])
    notes = TextAreaField("Notes", validators=[Optional()])


class StockAdjustmentForm(FlaskForm):
    """Adjust inventory stock quantity."""

    adjustment_type = SelectField("What happened", choices=list(ADJUSTMENTS.items()),
                                  validators=[DataRequired()])
    quantity = IntegerField("Quantity", validators=[InputRequired(), NumberRange(min=0)])
    reason = StringField("Reason", validators=[Optional(), Length(max=200)])
