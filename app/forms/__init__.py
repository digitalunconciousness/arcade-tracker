"""Application form classes.

Re-exports every form so callers can use a single import path::

    from app.forms import LoginForm, InventoryItemForm
"""

from app.forms.auth import (
    ChangePasswordForm,
    LoginForm,
    ProfileForm,
    RegisterForm,
)
from app.forms.game import MaintenancePhotoForm
from app.forms.inventory import InventoryItemForm, StockAdjustmentForm
from app.forms.maintenance import (
    InventoryUsageForm,
    MaintenanceWithInventoryForm,
)

__all__ = [
    "LoginForm",
    "RegisterForm",
    "ChangePasswordForm",
    "ProfileForm",
    "MaintenancePhotoForm",
    "InventoryItemForm",
    "StockAdjustmentForm",
    "InventoryUsageForm",
    "MaintenanceWithInventoryForm",
]
