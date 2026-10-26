"""Reservations blueprint (inventory step 6): using or releasing parts set aside for a work
order, from the order's page. Reserving is done with the order's "Log work" form."""

from flask import Blueprint, abort, flash, redirect, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.models import PartReservation
from app.services import reservations, stock_places
from app.utils.decorators import requires_role

reservations_bp = Blueprint("reservations", __name__)


@reservations_bp.route("/maintenance/<int:record_id>/reservations/<int:res_id>/"
                       "<any(use, release):action>", methods=["POST"])
@login_required
@requires_role("operator")
def act(record_id, res_id, action):
    res = db.get_or_404(PartReservation, res_id)
    if res.order_id != record_id:
        abort(404)
    name, qty = res.item.name, res.quantity
    try:
        if action == "use":
            flash(reservations.use(res, current_user.id), "success")
        else:
            reservations.release(res)
            flash(f"Released {qty} {name}.", "success")
        db.session.commit()
    except (reservations.ReservationError, stock_places.StockError) as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return redirect(url_for("maintenance.maintenance_detail", record_id=record_id))
