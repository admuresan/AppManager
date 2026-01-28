"""
Admin HTML page routes (dashboard, OCI config page).

IMPORTANT: Read `instructions/architecture` before making changes.
"""

from flask import current_app, render_template, request
from flask_login import login_required

from app.models.app_config import AppConfig

from ..blueprint import bp


@bp.route("/dashboard")
@login_required
def dashboard():
    """Admin dashboard showing all apps."""
    # Track admin IP for filtering
    try:
        from app.utils.traffic_tracker import add_admin_ip

        ip_address = request.headers.get("X-Forwarded-For", request.headers.get("X-Real-IP", request.remote_addr))
        if ip_address:
            ip_address = ip_address.split(",")[0].strip()
        else:
            ip_address = request.remote_addr or None

        if ip_address:
            add_admin_ip(current_app.instance_path, ip_address)
    except Exception:
        pass  # Don't fail if tracking fails

    apps = AppConfig.get_all()
    return render_template("admin/dashboard.html", apps=apps)


@bp.route("/oci")
@login_required
def oci_config():
    """OCI configuration page."""
    return render_template("admin/oci.html")

