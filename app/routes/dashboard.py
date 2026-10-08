"""Dashboard blueprint — home / index page."""

from flask import Blueprint, render_template
from flask_login import login_required

from app.services.dashboard import build_dashboard
from app.services.rankings import update_monthly_rankings_if_due

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
@login_required
def home():
    # Writes on GET (F-14): the monthly ranking counters are bumped by the first page view of
    # a month. Kept as it was; it is idempotent within a month.
    update_monthly_rankings_if_due()
    return render_template("index.html", d=build_dashboard())
