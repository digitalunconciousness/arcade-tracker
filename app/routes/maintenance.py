"""Maintenance blueprint — work orders, photos, reports, PDF export."""

import io
import json
import os
import uuid
import datetime as dt
from datetime import datetime, date

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import current_user, login_required
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from werkzeug.utils import secure_filename

from app.extensions import db
from app.models import (
    Game,
    InventoryItem,
    InventoryRequest,
    InventoryRequestHistory,
    LowStockAlert,
    MaintenanceInventoryUsage,
    MaintenanceRecord,
    PlayRecord,
    StockHistory,
    WorkLog,
)
from app.forms.maintenance import InventoryUsageForm, MaintenanceWithInventoryForm
from app.forms.game import MaintenancePhotoForm
from app.utils.decorators import requires_role
from app.utils.helpers import allowed_file, compress_and_save_image, get_directory_size

maintenance_bp = Blueprint("maintenance", __name__)

# ---------------------------------------------------------------------------
# Storage / cloud constants
# ---------------------------------------------------------------------------
MAX_PHOTOS_PER_RECORD = 10
MAX_TOTAL_STORAGE_MB = 500

USE_CLOUD_STORAGE = os.getenv("USE_CLOUD_STORAGE", "false").lower() == "true"
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_BUCKET_NAME = os.getenv("AWS_BUCKET_NAME", "arcade-tracker-photos")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _upload_to_cloud(file_data, filename):
    """Upload file to cloud storage (AWS S3)."""
    if not USE_CLOUD_STORAGE:
        return None
    try:
        import boto3
        from botocore.exceptions import NoCredentialsError, ClientError

        s3_client = boto3.client(
            "s3",
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name=AWS_REGION,
        )
        s3_client.put_object(
            Bucket=AWS_BUCKET_NAME,
            Key=f"maintenance_photos/{filename}",
            Body=file_data,
            ContentType="image/jpeg",
        )
        return (
            f"https://{AWS_BUCKET_NAME}.s3.{AWS_REGION}.amazonaws.com/"
            f"maintenance_photos/{filename}"
        )
    except (ImportError, Exception) as e:  # noqa: BLE001
        print(f"Cloud upload failed: {e}")
        return None


def _check_low_stock_alert(item):
    """Check if item needs a low stock alert and create one if needed."""
    if item.is_low_stock():
        existing_alert = LowStockAlert.query.filter_by(
            item_id=item.id, resolved=False
        ).first()
        if not existing_alert:
            alert = LowStockAlert(item_id=item.id, email_sent=False)
            db.session.add(alert)
            db.session.commit()
    else:
        active_alerts = LowStockAlert.query.filter_by(
            item_id=item.id, resolved=False
        ).all()
        for alert in active_alerts:
            alert.resolved = True
            alert.resolved_date = datetime.now(dt.UTC)
        if active_alerts:
            db.session.commit()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@maintenance_bp.route("/maintenance/game/<int:game_id>", methods=["GET", "POST"])
@login_required
@requires_role("operator")
def game_maintenance(game_id):
    game = Game.query.get_or_404(game_id)
    form = MaintenanceWithInventoryForm()

    # Populate inventory item choices
    inventory_items = InventoryItem.query.order_by(InventoryItem.name.asc()).all()
    item_choices = [(-1, "Select an item...")] + [
        (item.id, f"{item.name} (Stock: {item.stock_quantity})")
        for item in inventory_items
    ]

    for inventory_form in form.inventory_items:
        inventory_form.inventory_item_id.choices = item_choices

    if form.validate_on_submit():
        priority = request.form.get("priority", "Medium")

        maintenance_record = MaintenanceRecord(
            game_id=game_id,
            issue_description=form.issue_description.data,
            fix_description=form.fix_description.data,
            cost=form.cost.data if form.cost.data else None,
            technician=form.technician.data,
            status=form.status.data,
            priority=priority,
        )

        if form.status.data == "Fixed":
            maintenance_record.date_fixed = datetime.now(dt.UTC)

        db.session.add(maintenance_record)
        db.session.flush()  # Get the maintenance record ID

        # Process inventory usage
        total_inventory_cost = 0
        for inventory_form in form.inventory_items:
            item_id = inventory_form.inventory_item_id.data
            quantity = inventory_form.quantity_used.data

            if item_id and item_id != -1 and quantity and quantity > 0:
                item = InventoryItem.query.get(item_id)
                if item and item.stock_quantity >= quantity:
                    usage = MaintenanceInventoryUsage(
                        maintenance_id=maintenance_record.id,
                        item_id=item_id,
                        quantity_used=quantity,
                        unit_price_at_time=item.unit_price,
                        total_cost=quantity * item.unit_price,
                    )
                    db.session.add(usage)

                    old_quantity = item.stock_quantity
                    item.stock_quantity -= quantity

                    stock_history = StockHistory(
                        item_id=item_id,
                        change_type="used",
                        quantity_change=-quantity,
                        previous_quantity=old_quantity,
                        new_quantity=item.stock_quantity,
                        reason=f"Used in maintenance for {game.name} (Work Order #{maintenance_record.id})",
                        user_id=current_user.id,
                    )
                    db.session.add(stock_history)

                    total_inventory_cost += usage.total_cost
                    _check_low_stock_alert(item)
                elif item:
                    flash(
                        f"Insufficient stock for {item.name}. "
                        f"Available: {item.stock_quantity}, Requested: {quantity}",
                        "warning",
                    )

        # Update total cost if inventory was used
        if total_inventory_cost > 0:
            current_cost = maintenance_record.cost or 0
            maintenance_record.cost = current_cost + total_inventory_cost

        db.session.commit()

        flash(f'Maintenance record added for "{game.name}"', "success")
        if total_inventory_cost > 0:
            flash(f"Inventory items used: ${total_inventory_cost:.2f}", "info")
        return redirect(url_for("games.game_detail", game_id=game_id))

    return render_template("maintenance_with_inventory.html", form=form, game=game)


@maintenance_bp.route("/maintenance/general", methods=["GET", "POST"])
@login_required
@requires_role("operator")
def general_maintenance():
    """Create a general work order not tied to a specific game"""
    form = MaintenanceWithInventoryForm()

    # Populate inventory item choices
    inventory_items = InventoryItem.query.order_by(InventoryItem.name.asc()).all()
    item_choices = [(-1, "Select an item...")] + [
        (item.id, f"{item.name} (Stock: {item.stock_quantity})")
        for item in inventory_items
    ]

    for inventory_form in form.inventory_items:
        inventory_form.inventory_item_id.choices = item_choices

    if form.validate_on_submit():
        work_order_type = request.form.get("work_order_type", "general")
        location_description = request.form.get("location_description", "")
        priority = request.form.get("priority", "Medium")

        maintenance_record = MaintenanceRecord(
            game_id=None,
            work_order_type=work_order_type,
            location_description=location_description,
            issue_description=form.issue_description.data,
            fix_description=form.fix_description.data,
            cost=form.cost.data if form.cost.data else None,
            technician=form.technician.data,
            status=form.status.data,
            priority=priority,
        )

        if form.status.data == "Fixed":
            maintenance_record.date_fixed = datetime.now(dt.UTC)

        db.session.add(maintenance_record)
        db.session.flush()

        # Process inventory usage
        total_inventory_cost = 0
        for inventory_form in form.inventory_items:
            item_id = inventory_form.inventory_item_id.data
            quantity = inventory_form.quantity_used.data

            if item_id and item_id != -1 and quantity and quantity > 0:
                item = InventoryItem.query.get(item_id)
                if item and item.stock_quantity >= quantity:
                    usage = MaintenanceInventoryUsage(
                        maintenance_id=maintenance_record.id,
                        item_id=item_id,
                        quantity_used=quantity,
                        unit_price_at_time=item.unit_price,
                        total_cost=quantity * item.unit_price,
                    )
                    db.session.add(usage)

                    old_quantity = item.stock_quantity
                    item.stock_quantity -= quantity

                    stock_history = StockHistory(
                        item_id=item_id,
                        change_type="used",
                        quantity_change=-quantity,
                        previous_quantity=old_quantity,
                        new_quantity=item.stock_quantity,
                        reason=f"Used in {work_order_type} maintenance (Work Order #{maintenance_record.id})",
                        user_id=current_user.id,
                    )
                    db.session.add(stock_history)

                    total_inventory_cost += usage.total_cost
                    _check_low_stock_alert(item)

        if total_inventory_cost > 0:
            current_cost = maintenance_record.cost or 0
            maintenance_record.cost = current_cost + total_inventory_cost

        db.session.commit()

        flash("General work order created successfully!", "success")
        return redirect(url_for("maintenance.maintenance_orders"))

    return render_template("general_maintenance.html", form=form)


@maintenance_bp.route("/maintenance_orders")
@login_required
def maintenance_orders():
    """List all maintenance records"""
    search = request.args.get("search", "")
    query = MaintenanceRecord.query
    if search:
        query = query.filter(
            (MaintenanceRecord.issue_description.ilike(f"%{search}%"))
            | (MaintenanceRecord.technician.ilike(f"%{search}%"))
            | (MaintenanceRecord.work_order_type.ilike(f"%{search}%"))
        )
    # Sort by game name (nulls last for general maintenance), then by date
    all_records = (
        query.outerjoin(Game)
        .order_by(
            Game.name.asc().nullslast(),
            MaintenanceRecord.date_reported.desc(),
        )
        .all()
    )

    # Split records into open and closed for the tab interface
    open_records = [r for r in all_records if r.status in ["Open", "In_Progress"]]
    closed_records = [r for r in all_records if r.status in ["Fixed", "Deferred"]]

    # Clean descriptions to remove line breaks that break JavaScript
    for record in all_records:
        if record.issue_description:
            record.issue_description = record.issue_description.replace("\n", " ").replace("\r", "")
        if record.fix_description:
            record.fix_description = record.fix_description.replace("\n", " ").replace("\r", "")
        if record.game and record.game.name:
            record.game.name = record.game.name.replace("\n", " ").replace("\r", "")

    return render_template(
        "maintenance_orders.html",
        open_records=open_records,
        closed_records=closed_records,
        all_records=all_records,
        search=search,
    )


@maintenance_bp.route("/maintenance_detail/<int:record_id>")
@login_required
def maintenance_detail(record_id):
    """Detailed view of a maintenance record"""
    record = MaintenanceRecord.query.get_or_404(record_id)
    return render_template("maintenance_detail.html", record=record)


@maintenance_bp.route("/update_maintenance/<int:record_id>", methods=["GET", "POST"])
@login_required
@requires_role("operator")
def update_maintenance(record_id):
    """Detailed update page for maintenance records"""
    record = MaintenanceRecord.query.get_or_404(record_id)

    if request.method == "POST":
        # Update main record fields
        record.status = request.form.get("status", record.status)
        record.priority = request.form.get("priority", record.priority)
        record.fix_description = request.form.get("fix_description", record.fix_description)
        record.technician = request.form.get("technician", record.technician)

        # Update total cost if provided
        cost = request.form.get("cost")
        if cost:
            try:
                record.cost = float(cost)
            except ValueError:
                pass

        if record.status == "Fixed":
            record.date_fixed = datetime.now(dt.UTC)

        # Create work log entry
        work_notes = request.form.get("work_notes", "").strip()
        if work_notes:
            work_log = WorkLog(
                maintenance_id=record.id,
                user_id=current_user.id,
                work_description=work_notes,
                parts_used=request.form.get("parts_used", ""),
                time_spent=(
                    float(request.form.get("time_spent"))
                    if request.form.get("time_spent")
                    else None
                ),
                cost_incurred=(
                    float(request.form.get("work_cost"))
                    if request.form.get("work_cost")
                    else None
                ),
            )
            db.session.add(work_log)

        # Process inventory usage and requests
        total_inventory_cost = 0
        items_used = 0
        items_requested = 0

        # Process up to 10 inventory items (dynamic rows)
        for i in range(10):
            item_id_str = request.form.get(f"inventory_item_{i}")
            quantity_str = request.form.get(f"inventory_quantity_{i}")
            action = request.form.get(f"item_action_{i}")

            if item_id_str and quantity_str and action:
                try:
                    item_id = int(item_id_str)
                    quantity = int(quantity_str)

                    if item_id > 0 and quantity > 0:
                        item = InventoryItem.query.get(item_id)

                        if action == "use":
                            # Use inventory immediately
                            if item and item.stock_quantity >= quantity:
                                usage = MaintenanceInventoryUsage(
                                    maintenance_id=record.id,
                                    item_id=item_id,
                                    quantity_used=quantity,
                                    unit_price_at_time=item.unit_price,
                                    total_cost=quantity * item.unit_price,
                                )
                                db.session.add(usage)

                                old_quantity = item.stock_quantity
                                item.stock_quantity -= quantity

                                stock_history = StockHistory(
                                    item_id=item_id,
                                    change_type="used",
                                    quantity_change=-quantity,
                                    previous_quantity=old_quantity,
                                    new_quantity=item.stock_quantity,
                                    reason=f"Used in Work Order #{record.id}",
                                    user_id=current_user.id,
                                )
                                db.session.add(stock_history)

                                total_inventory_cost += usage.total_cost
                                items_used += 1
                                _check_low_stock_alert(item)
                            elif item:
                                flash(
                                    f"Insufficient stock for {item.name}. "
                                    f"Available: {item.stock_quantity}, Requested: {quantity}",
                                    "warning",
                                )

                        elif action == "request":
                            urgency = request.form.get(f"urgency_{i}", "Normal")

                            inventory_request = InventoryRequest(
                                item_id=item_id,
                                maintenance_id=record.id,
                                item_name=item.name if item else "Unknown Item",
                                quantity_requested=quantity,
                                reason=f"Needed for Work Order #{record.id}: {record.issue_description[:100]}",
                                urgency=urgency,
                                status="Pending",
                                requested_by_id=current_user.id,
                            )
                            db.session.add(inventory_request)
                            db.session.flush()

                            history = InventoryRequestHistory(
                                request_id=inventory_request.id,
                                user_id=current_user.id,
                                action="created",
                                notes="Request created from work order update",
                            )
                            db.session.add(history)
                            items_requested += 1

                except (ValueError, TypeError):
                    continue

        # Update total cost with inventory costs
        if total_inventory_cost > 0:
            if record.cost:
                record.cost += total_inventory_cost
            else:
                record.cost = total_inventory_cost

        db.session.commit()

        # Build flash message based on what was done
        messages = []
        if work_notes:
            messages.append("Work log added")
        if items_used > 0:
            messages.append(f"{items_used} item(s) used (${total_inventory_cost:.2f})")
        if items_requested > 0:
            messages.append(f"{items_requested} item(s) requested")

        if messages:
            flash(". ".join(messages) + ".", "success")
        else:
            flash(f"Maintenance record #{record.id} updated.", "success")

        return redirect(url_for("maintenance.maintenance_orders"))

    # GET request - load inventory items (convert to dict for JSON serialization)
    inventory_items_query = InventoryItem.query.order_by(InventoryItem.name.asc()).all()
    inventory_items = [
        {
            "id": item.id,
            "name": item.name,
            "description": item.description,
            "stock_quantity": item.stock_quantity,
            "unit_price": float(item.unit_price) if item.unit_price else 0,
            "minimum_stock": item.minimum_stock,
            "supplier": item.supplier,
            "part_number": item.part_number,
        }
        for item in inventory_items_query
    ]
    return render_template(
        "update_maintenance.html",
        maintenance=record,
        inventory_items=inventory_items,
    )


@maintenance_bp.route("/close_maintenance/<int:record_id>", methods=["POST"])
@login_required
@requires_role("operator")
def close_maintenance(record_id):
    """Quick close a maintenance order"""
    maintenance = MaintenanceRecord.query.get_or_404(record_id)

    maintenance.status = request.form.get("status", "Fixed")
    maintenance.fix_description = request.form.get("fix_description", "")
    cost_input = request.form.get("cost")
    if cost_input:
        try:
            maintenance.cost = float(cost_input)
        except ValueError:
            maintenance.cost = None
    maintenance.technician = request.form.get("technician", "")
    maintenance.date_fixed = datetime.now(dt.UTC)

    db.session.commit()

    game_name = maintenance.game.name if maintenance.game else "General Maintenance"
    flash(
        f'Maintenance order for "{game_name}" marked as {maintenance.status}!',
        "success",
    )
    return redirect(url_for("maintenance.maintenance_orders"))


@maintenance_bp.route("/delete_maintenance/<int:record_id>", methods=["POST"])
@login_required
@requires_role("manager")
def delete_maintenance(record_id):
    """Delete a maintenance record"""
    record = MaintenanceRecord.query.get_or_404(record_id)
    db.session.delete(record)
    db.session.commit()
    flash(f"Maintenance record #{record.id} deleted.", "warning")
    return redirect(url_for("maintenance.maintenance_orders"))


@maintenance_bp.route("/download_maintenance_record/<int:record_id>")
@login_required
def download_maintenance_record(record_id):
    """Generate and download PDF of maintenance record"""
    record = MaintenanceRecord.query.get_or_404(record_id)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Title
    title_text = f"Work Order #{record.id}"
    if record.game:
        title_text += f" - {record.game.name}"
    else:
        title_text += " - General Maintenance"
    title = Paragraph(title_text, styles["Title"])
    story.append(title)
    story.append(Spacer(1, 12))

    # Basic Info Table
    info_data = [
        ["Status:", record.status or "Open"],
        [
            "Reported:",
            (
                record.date_reported.strftime("%Y-%m-%d %H:%M")
                if record.date_reported
                else "Unknown"
            ),
        ],
    ]
    if record.date_fixed:
        info_data.append(["Fixed:", record.date_fixed.strftime("%Y-%m-%d %H:%M")])
    if record.technician:
        info_data.append(["Technician:", record.technician])
    if record.cost:
        info_data.append(["Total Cost:", f"${record.cost:.2f}"])

    info_table = Table(info_data, colWidths=[1.5 * inch, 4 * inch])
    info_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ]
        )
    )
    story.append(info_table)
    story.append(Spacer(1, 20))

    # Original Issue
    story.append(Paragraph("<b>Original Issue:</b>", styles["Heading2"]))
    story.append(
        Paragraph(record.issue_description or "No description", styles["Normal"])
    )
    story.append(Spacer(1, 12))

    # Initial Assessment
    if record.fix_description:
        story.append(Paragraph("<b>Initial Assessment:</b>", styles["Heading2"]))
        story.append(Paragraph(record.fix_description, styles["Normal"]))
        story.append(Spacer(1, 12))

    # Work Log History
    if record.work_logs:
        story.append(Paragraph("<b>Work Log History:</b>", styles["Heading2"]))
        story.append(Spacer(1, 6))

        for log in record.work_logs:
            log_header = f"{log.timestamp.strftime('%Y-%m-%d %H:%M')} - {log.user.username}"
            if log.time_spent:
                log_header += f" ({log.time_spent}h)"
            if log.cost_incurred:
                log_header += f" (${log.cost_incurred:.2f})"

            story.append(Paragraph(f"<b>{log_header}</b>", styles["Normal"]))
            story.append(Paragraph(log.work_description, styles["Normal"]))
            if log.parts_used:
                story.append(
                    Paragraph(f"<i>Parts: {log.parts_used}</i>", styles["Normal"])
                )
            story.append(Spacer(1, 8))

        story.append(Spacer(1, 12))

    # Inventory Usage
    if record.inventory_usage:
        story.append(Paragraph("<b>Inventory Used:</b>", styles["Heading2"]))
        story.append(Spacer(1, 6))

        inv_data = [["Item", "Quantity", "Cost"]]
        for usage in record.inventory_usage:
            inv_data.append(
                [
                    usage.item.name,
                    str(usage.quantity_used),
                    f"${usage.total_cost:.2f}",
                ]
            )

        inv_table = Table(inv_data, colWidths=[3 * inch, 1 * inch, 1 * inch])
        inv_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("ALIGN", (1, 0), (-1, -1), "CENTER"),
                    ("ALIGN", (2, 0), (-1, -1), "RIGHT"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ]
            )
        )
        story.append(inv_table)
        story.append(Spacer(1, 12))

    # Photos note
    photos = record.get_photos()
    if photos:
        story.append(
            Paragraph(
                f"<b>Photos:</b> {len(photos)} photo(s) attached (not included in PDF)",
                styles["Normal"],
            )
        )

    # Build PDF
    doc.build(story)
    buffer.seek(0)

    filename = f"work_order_{record.id}"
    if record.game:
        filename += f"_{record.game.name.replace(' ', '_')}"
    filename += ".pdf"

    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,
        mimetype="application/pdf",
    )


@maintenance_bp.route(
    "/maintenance_photos/<int:maintenance_id>", methods=["GET", "POST"]
)
@login_required
@requires_role("operator")
def maintenance_photos(maintenance_id):
    """Upload photos for a maintenance record"""
    maintenance = MaintenanceRecord.query.get_or_404(maintenance_id)
    form = MaintenancePhotoForm()

    if request.method == "POST":
        print(f"DEBUG: POST request received")
        print(f"DEBUG: Form data: {dict(request.form)}")
        print(f"DEBUG: Files: {dict(request.files)}")
        print(f"DEBUG: CSRF token present: {'csrf_token' in request.form}")

        # Check CSRF token manually if form validation fails
        csrf_token = request.form.get("csrf_token")
        if not csrf_token:
            flash("Security token missing. Please try again.", "error")
            return redirect(
                url_for("maintenance.maintenance_photos", maintenance_id=maintenance_id)
            )

        print(f"DEBUG: Form validation result: {form.validate_on_submit()}")
        print(f"DEBUG: Form errors: {form.errors}")

        # Get files from request (more reliable than form.photos.data)
        uploaded_files = request.files.getlist("photos")
        print(
            f"DEBUG: Raw uploaded files: "
            f"{[f.filename if f and hasattr(f, 'filename') else 'No filename' for f in uploaded_files]}"
        )
        print(
            f"DEBUG: File details: "
            f"{[(f.filename, f.content_length if hasattr(f, 'content_length') else 'No size', f.content_type if hasattr(f, 'content_type') else 'No type') for f in uploaded_files if f]}"
        )

        # Check if files have actual content
        for i, f in enumerate(uploaded_files):
            if f:
                print(
                    f"DEBUG: File {i}: filename='{f.filename}', type='{f.content_type}', "
                    f"has_data={bool(f.filename and f.filename.strip())}"
                )

        # If no files from 'photos' field, try the form field name
        if not uploaded_files or not any(
            f and f.filename and f.filename.strip() for f in uploaded_files
        ):
            uploaded_files = request.files.getlist(form.photos.name)
            print(
                f"DEBUG: Files from form field name: "
                f"{[f.filename if f and hasattr(f, 'filename') else 'No filename' for f in uploaded_files]}"
            )

        # Also try other possible field names
        if not uploaded_files or not any(
            f and f.filename and f.filename.strip() for f in uploaded_files
        ):
            all_file_fields = list(request.files.keys())
            print(f"DEBUG: All file field names in request: {all_file_fields}")
            for field_name in all_file_fields:
                files = request.files.getlist(field_name)
                print(
                    f"DEBUG: Files in '{field_name}': "
                    f"{[f.filename if f and hasattr(f, 'filename') else 'No filename' for f in files]}"
                )

        uploaded_count = 0

        # Filter out empty files and validate
        valid_files = []
        for file in uploaded_files:
            if (
                file
                and hasattr(file, "filename")
                and file.filename
                and file.filename.strip() != ""
            ):
                print(f"DEBUG: Processing file: {file.filename}")
                if allowed_file(file.filename):
                    valid_files.append(file)
                    print(f"DEBUG: File {file.filename} is valid")
                else:
                    flash(
                        f"File {file.filename} has an invalid file type. "
                        "Allowed: PNG, JPG, JPEG, GIF",
                        "warning",
                    )

        print(f"DEBUG: Valid files count: {len(valid_files)}")

        if not valid_files:
            flash(
                "No valid image files were selected for upload. "
                "Please select image files (PNG, JPG, JPEG, GIF).",
                "warning",
            )
            return redirect(
                url_for("maintenance.maintenance_photos", maintenance_id=maintenance_id)
            )

        # Check current photo count for this record
        current_photos = maintenance.get_photos()
        if len(current_photos) >= MAX_PHOTOS_PER_RECORD:
            flash(
                f"Maximum {MAX_PHOTOS_PER_RECORD} photos allowed per maintenance record.",
                "error",
            )
            return redirect(
                url_for("maintenance.maintenance_photos", maintenance_id=maintenance_id)
            )

        # Check total storage usage
        upload_dir = os.path.join(current_app.static_folder, "maintenance_photos")
        current_size_mb = get_directory_size(upload_dir)
        if current_size_mb > MAX_TOTAL_STORAGE_MB:
            flash(
                f"Storage limit ({MAX_TOTAL_STORAGE_MB}MB) reached. "
                "Please contact administrator.",
                "error",
            )
            return redirect(
                url_for("maintenance.maintenance_photos", maintenance_id=maintenance_id)
            )

        for file in valid_files:
            if len(maintenance.get_photos()) >= MAX_PHOTOS_PER_RECORD:
                break

            filename = secure_filename(file.filename)
            _name_part, ext = os.path.splitext(filename)
            unique_filename = f"maintenance_{maintenance_id}_{uuid.uuid4().hex[:8]}{ext}"

            upload_dir = os.path.join(current_app.static_folder, "maintenance_photos")
            os.makedirs(upload_dir, exist_ok=True)

            file_path = os.path.join(upload_dir, unique_filename)

            try:
                compress_and_save_image(file, file_path)

                # Upload to cloud if enabled
                cloud_url = None
                if USE_CLOUD_STORAGE:
                    with open(file_path, "rb") as compressed_file:
                        cloud_url = _upload_to_cloud(
                            compressed_file.read(), unique_filename
                        )

                maintenance.add_photo(unique_filename)
                uploaded_count += 1

                if cloud_url:
                    print(f"Photo uploaded to cloud: {cloud_url}")

            except Exception as e:  # noqa: BLE001
                flash(f"Error uploading {filename}: {str(e)}", "error")
                if os.path.exists(file_path):
                    os.remove(file_path)

        if uploaded_count > 0:
            db.session.commit()
            flash(
                f"Successfully uploaded {uploaded_count} photo(s) for maintenance record.",
                "success",
            )

        return redirect(
            url_for("maintenance.maintenance_detail", record_id=maintenance_id)
        )

    return render_template("maintenance_photos.html", maintenance=maintenance, form=form)


@maintenance_bp.route(
    "/delete_maintenance_photo/<int:maintenance_id>/<filename>", methods=["POST"]
)
@login_required
@requires_role("manager")
def delete_maintenance_photo(maintenance_id, filename):
    """Delete a photo from a maintenance record"""
    maintenance = MaintenanceRecord.query.get_or_404(maintenance_id)

    maintenance.remove_photo(filename)
    db.session.commit()

    file_path = os.path.join(
        current_app.static_folder, "maintenance_photos", filename
    )
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
            flash("Photo deleted successfully.", "success")
        except Exception as e:  # noqa: BLE001
            flash(
                f"Photo removed from record but file deletion failed: {str(e)}",
                "warning",
            )
    else:
        flash("Photo removed from record.", "success")

    return redirect(
        url_for("maintenance.maintenance_detail", record_id=maintenance_id)
    )


@maintenance_bp.route("/maintenance_reports")
@login_required
@requires_role("manager")
def maintenance_reports():
    """Generate maintenance reports with time frame filters"""
    from datetime import timedelta

    try:
        days = request.args.get("days", 30, type=int)
        if days is None or days <= 0:
            days = 30
    except (ValueError, TypeError):
        days = 30

    start_date = date.today() - timedelta(days=days)

    # Get all maintenance records in date range - USE OUTERJOIN
    all_records = (
        MaintenanceRecord.query.outerjoin(Game)
        .filter(MaintenanceRecord.date_reported >= start_date)
        .order_by(MaintenanceRecord.date_reported.desc())
        .all()
    )

    open_records = [r for r in all_records if r.status in ["Open", "In_Progress"]]
    closed_records = [r for r in all_records if r.status in ["Fixed", "Deferred"]]

    # Calculate statistics
    total_cost = sum(r.cost or 0 for r in closed_records)
    avg_resolution_days = 0
    if closed_records:
        resolution_times = []
        for r in closed_records:
            if r.date_fixed and r.date_reported:
                days_to_fix = (r.date_fixed.date() - r.date_reported.date()).days
                resolution_times.append(max(1, days_to_fix))
        if resolution_times:
            avg_resolution_days = sum(resolution_times) / len(resolution_times)

    return render_template(
        "maintenance_reports.html",
        all_records=all_records,
        open_records=open_records,
        closed_records=closed_records,
        days_filter=days,
        start_date=start_date,
        total_cost=total_cost,
        avg_resolution_days=avg_resolution_days,
    )


@maintenance_bp.route("/export_maintenance_report")
@login_required
@requires_role("manager")
def export_maintenance_report():
    """Export maintenance report as PDF"""
    import matplotlib
    matplotlib.use("Agg")
    from collections import Counter
    from datetime import timedelta

    from reportlab.platypus import Image as RLImage

    report_type = request.args.get("type", "all")
    try:
        days = request.args.get("days", 30, type=int)
        if days is None or days <= 0:
            days = 30
    except (ValueError, TypeError):
        days = 30

    start_date = date.today() - timedelta(days=days)

    # Get records based on type - USE OUTERJOIN for general facility maintenance
    if report_type == "open":
        records = (
            MaintenanceRecord.query.outerjoin(Game)
            .filter(MaintenanceRecord.status.in_(["Open", "In_Progress"]))
            .order_by(MaintenanceRecord.date_reported.desc())
            .all()
        )
        title = "Open Maintenance Orders"
    elif report_type == "closed":
        records = (
            MaintenanceRecord.query.outerjoin(Game)
            .filter(
                MaintenanceRecord.status.in_(["Fixed", "Deferred"]),
                MaintenanceRecord.date_reported >= start_date,
            )
            .order_by(MaintenanceRecord.date_reported.desc())
            .all()
        )
        title = f"Closed Maintenance Orders (Last {days} Days)"
    else:
        records = (
            MaintenanceRecord.query.outerjoin(Game)
            .filter(MaintenanceRecord.date_reported >= start_date)
            .order_by(MaintenanceRecord.date_reported.desc())
            .all()
        )
        title = f"All Maintenance Orders (Last {days} Days)"

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Title
    story.append(Paragraph(title, styles["Title"]))
    story.append(Spacer(1, 12))

    # Summary stats
    total_records = len(records)
    open_count = len([r for r in records if r.status in ["Open", "In_Progress"]])
    closed_count = len([r for r in records if r.status in ["Fixed", "Deferred"]])
    total_cost = sum(
        r.cost or 0 for r in records if r.status in ["Fixed", "Deferred"]
    )

    summary_data = [
        ["Metric", "Value"],
        ["Total Records", str(total_records)],
        ["Open Orders", str(open_count)],
        ["Closed Orders", str(closed_count)],
        ["Total Cost", f"${total_cost:.2f}"],
    ]

    summary_table = Table(summary_data)
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 14),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ]
        )
    )

    story.append(summary_table)
    story.append(Spacer(1, 20))

    # Maintenance records table
    if records:
        story.append(Paragraph("Maintenance Records", styles["Heading2"]))

        maintenance_data = [
            ["Game", "Issue", "Status", "Date", "Cost", "Work Summary"]
        ]

        for record in records[:15]:
            work_summary = "No work logged"
            if hasattr(record, "work_logs") and record.work_logs:
                latest_work = record.work_logs[-1]
                work_summary = (
                    latest_work.work_description[:35] + "..."
                    if len(latest_work.work_description) > 35
                    else latest_work.work_description
                )
            elif record.work_notes:
                work_summary = (
                    record.work_notes[:35] + "..."
                    if len(record.work_notes) > 35
                    else record.work_notes
                )
            elif record.fix_description:
                work_summary = (
                    record.fix_description[:35] + "..."
                    if len(record.fix_description) > 35
                    else record.fix_description
                )
            elif record.status in ["Open", "In_Progress"]:
                work_summary = "In progress..."

            game_name = record.game.name if record.game else "General Facility"
            game_name = game_name[:12] + "..." if len(game_name) > 12 else game_name

            maintenance_data.append(
                [
                    game_name,
                    (
                        record.issue_description[:20] + "..."
                        if len(record.issue_description) > 20
                        else record.issue_description
                    ),
                    record.status.replace("_", " "),
                    record.date_reported.strftime("%m/%d"),
                    f"${record.cost:.0f}" if record.cost else "$0",
                    work_summary,
                ]
            )

        col_widths = [90, 120, 60, 40, 40, 190]

        maintenance_table = Table(maintenance_data, colWidths=col_widths)
        maintenance_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightblue),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 10),
                    ("FONTSIZE", (0, 1), (-1, -1), 9),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                    ("TOPPADDING", (0, 1), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                    ("WORDWRAP", (0, 0), (-1, -1), True),
                ]
            )
        )

        story.append(maintenance_table)

        # Detailed work log section
        work_log_records = [
            r
            for r in records[:10]
            if hasattr(r, "work_logs") and r.work_logs
        ]
        if work_log_records:
            story.append(Spacer(1, 20))
            story.append(
                Paragraph(
                    "Detailed Work Logs (Recent Orders)", styles["Heading2"]
                )
            )

            for record in work_log_records:
                story.append(Spacer(1, 12))
                game_name_full = (
                    record.game.name if record.game else "General Facility"
                )
                story.append(
                    Paragraph(
                        f"<b>{game_name_full}</b> - Work Order #{record.id}",
                        styles["Heading3"],
                    )
                )
                story.append(
                    Paragraph(
                        f"<i>Issue: {record.issue_description[:80]}"
                        f"{'...' if len(record.issue_description) > 80 else ''}</i>",
                        styles["Normal"],
                    )
                )
                story.append(Spacer(1, 8))

                for i, work_log in enumerate(record.work_logs[-3:], 1):
                    work_text = (
                        f"<b>Entry {i}:</b> "
                        f"{work_log.timestamp.strftime('%m/%d %H:%M')} - "
                        f"{work_log.user.username}<br/>"
                    )
                    work_text += (
                        f"{work_log.work_description[:120]}"
                        f"{'...' if len(work_log.work_description) > 120 else ''}"
                    )
                    if work_log.time_spent:
                        work_text += f"<br/><i>Time: {work_log.time_spent}h</i>"
                    if work_log.cost_incurred:
                        work_text += f" <i>Cost: ${work_log.cost_incurred:.2f}</i>"

                    story.append(Paragraph(work_text, styles["Normal"]))
                    story.append(Spacer(1, 6))

    doc.build(story)
    buffer.seek(0)

    filename = f"maintenance_report_{report_type}_{days}days.pdf"
    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,
        mimetype="application/pdf",
    )
