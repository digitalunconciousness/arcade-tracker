"""Parts blueprint: categories, suppliers, a part's suppliers and photo (inventory step 2).

Managers keep the category and supplier lists and a part's suppliers and prices; anyone who
can see parts (operators) sees them, and can add a part's photo. The work is in
``app.services.parts``; these views parse the request and report.
"""

import os
import uuid

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from flask_login import current_user, login_required

from app.extensions import db
from app.models import InventoryItem, ItemSupplier, PartCategory, Supplier
from app.services import parts
from app.services.parts import PartError
from app.utils.decorators import requires_role

parts_bp = Blueprint("parts", __name__, url_prefix="/inventory")


def _part(item_id):
    return redirect(url_for("inventory.inventory_detail", item_id=item_id))


# --- categories ---------------------------------------------------------------------------

@parts_bp.route("/categories")
@login_required
@requires_role("manager")
def categories():
    return render_template("part_categories.html", categories=parts.categories())


@parts_bp.route("/categories/new", methods=["POST"])
@login_required
@requires_role("manager")
def category_new():
    try:
        category = parts.save_category(request.form.get("name"))
        db.session.commit()
        flash(f"Added {category.name}.", "success")
    except PartError as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return redirect(url_for("parts.categories"))


@parts_bp.route("/categories/<int:category_id>/edit", methods=["POST"])
@login_required
@requires_role("manager")
def category_edit(category_id):
    category = db.get_or_404(PartCategory, category_id)
    try:
        parts.save_category(request.form.get("name"), category)
        db.session.commit()
        flash(f"Renamed to {category.name}.", "success")
    except PartError as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return redirect(url_for("parts.categories"))


@parts_bp.route("/categories/<int:category_id>/delete", methods=["POST"])
@login_required
@requires_role("manager")
def category_delete(category_id):
    category = db.get_or_404(PartCategory, category_id)
    name = category.name
    count = parts.delete_category(category)
    db.session.commit()
    flash(f"Deleted {name}." + (f" {count} part{'' if count == 1 else 's'} now have no "
                                "category." if count else ""), "success")
    return redirect(url_for("parts.categories"))


# --- suppliers ----------------------------------------------------------------------------

@parts_bp.route("/suppliers")
@login_required
@requires_role("operator")
def suppliers():
    show_archived = request.args.get("archived") == "1"
    query = Supplier.query
    if not show_archived:
        query = query.filter(Supplier.archived.is_(False))
    rows = query.order_by(db.func.lower(Supplier.name)).all()
    return render_template("suppliers.html", suppliers=rows, show_archived=show_archived,
                           archived_count=Supplier.query.filter_by(archived=True).count())


@parts_bp.route("/suppliers/new", methods=["POST"])
@login_required
@requires_role("manager")
def supplier_new():
    try:
        supplier = parts.save_supplier(None, request.form)
        db.session.commit()
    except PartError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return redirect(url_for("parts.suppliers"))
    flash(f"Added {supplier.name}.", "success")
    return redirect(url_for("parts.supplier_detail", supplier_id=supplier.id))


@parts_bp.route("/suppliers/<int:supplier_id>")
@login_required
@requires_role("operator")
def supplier_detail(supplier_id):
    supplier = db.get_or_404(Supplier, supplier_id)
    links = sorted(supplier.parts, key=lambda lk: lk.item.name.lower())
    return render_template("supplier_detail.html", supplier=supplier, links=links)


@parts_bp.route("/suppliers/<int:supplier_id>/edit", methods=["POST"])
@login_required
@requires_role("manager")
def supplier_edit(supplier_id):
    supplier = db.get_or_404(Supplier, supplier_id)
    try:
        parts.save_supplier(supplier, request.form)
        db.session.commit()
        flash(f"Saved {supplier.name}.", "success")
    except PartError as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return redirect(url_for("parts.supplier_detail", supplier_id=supplier.id))


@parts_bp.route("/suppliers/<int:supplier_id>/archive", methods=["POST"])
@login_required
@requires_role("manager")
def supplier_archive(supplier_id):
    """Archive (or restore) a supplier: hidden from the lists, kept on parts and in history."""
    supplier = db.get_or_404(Supplier, supplier_id)
    supplier.archived = not supplier.archived
    db.session.commit()
    flash(f"{'Archived' if supplier.archived else 'Restored'} {supplier.name}.", "success")
    return redirect(url_for("parts.supplier_detail", supplier_id=supplier.id))


# --- a part's suppliers ---------------------------------------------------------------------

def _link(item_id, link_id):
    link = db.get_or_404(ItemSupplier, link_id)
    if link.item_id != item_id:
        from flask import abort

        abort(404)
    return link


@parts_bp.route("/<int:item_id>/suppliers/new", methods=["POST"])
@login_required
@requires_role("manager")
def link_new(item_id):
    item = db.get_or_404(InventoryItem, item_id)
    try:
        link = parts.save_link(item, request.form, current_user.id)
        db.session.commit()
        flash(f"Added {link.supplier.name}.", "success")
    except PartError as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return _part(item.id)


@parts_bp.route("/<int:item_id>/suppliers/<int:link_id>/edit", methods=["POST"])
@login_required
@requires_role("manager")
def link_edit(item_id, link_id):
    link = _link(item_id, link_id)
    try:
        parts.save_link(link.item, request.form, current_user.id, link)
        db.session.commit()
        flash(f"Saved {link.supplier.name}.", "success")
    except PartError as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return _part(item_id)


@parts_bp.route("/<int:item_id>/suppliers/<int:link_id>/prefer", methods=["POST"])
@login_required
@requires_role("manager")
def link_prefer(item_id, link_id):
    link = _link(item_id, link_id)
    parts.set_preferred(link.item, link.supplier)
    db.session.commit()
    flash(f"{link.supplier.name} is now the preferred supplier.", "success")
    return _part(item_id)


@parts_bp.route("/<int:item_id>/suppliers/<int:link_id>/remove", methods=["POST"])
@login_required
@requires_role("manager")
def link_remove(item_id, link_id):
    link = _link(item_id, link_id)
    name = link.supplier.name
    parts.remove_link(link)
    db.session.commit()
    flash(f"Removed {name} from this part.", "success")
    return _part(item_id)


# --- a part's photo -----------------------------------------------------------------------

@parts_bp.route("/<int:item_id>/photo", methods=["POST"])
@login_required
@requires_role("operator")
def photo_upload(item_id):
    """One photo per part, re-encoded as JPEG through the same checks as every upload."""
    from app.utils.helpers import allowed_file, compress_and_save_image

    item = db.get_or_404(InventoryItem, item_id)
    upload = request.files.get("photo")
    if not upload or not upload.filename:
        flash("Choose a photo first.", "error")
        return _part(item.id)
    if not allowed_file(upload.filename):
        flash("That isn't a photo. Use PNG, JPG or GIF.", "error")
        return _part(item.id)
    folder = current_app.config["UPLOAD_FOLDER"]
    os.makedirs(folder, exist_ok=True)
    name = f"part_{uuid.uuid4().hex[:12]}.jpg"
    path = os.path.join(folder, name)
    if not compress_and_save_image(upload, path):
        if os.path.exists(path):
            os.remove(path)
        flash(f"{upload.filename} could not be read as an image.", "error")
        return _part(item.id)
    old = item.photo_filename
    item.photo_filename = name
    db.session.commit()
    _remove_file(old)
    flash("Photo saved.", "success")
    return _part(item.id)


@parts_bp.route("/<int:item_id>/photo/delete", methods=["POST"])
@login_required
@requires_role("operator")
def photo_delete(item_id):
    item = db.get_or_404(InventoryItem, item_id)
    old, item.photo_filename = item.photo_filename, None
    db.session.commit()
    _remove_file(old)
    flash("Photo removed.", "success")
    return _part(item.id)


def _remove_file(name):
    if not name or not name.startswith("part_"):
        return
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], os.path.basename(name))
    if os.path.exists(path):
        os.remove(path)


@parts_bp.route("/photos/<filename>")
@login_required
def photo(filename):
    """A part's photo. Only names this blueprint made are served from the upload folder."""
    if not filename.startswith("part_") or "/" in filename or "\\" in filename:
        from flask import abort

        abort(404)
    return send_from_directory(current_app.config["UPLOAD_FOLDER"], filename)
