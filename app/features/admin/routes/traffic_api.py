"""
Admin traffic/statistics API routes.

IMPORTANT: Read `instructions/architecture` before making changes.
"""

from flask import current_app, jsonify, request
from flask_login import login_required

from ..blueprint import bp


@bp.route("/api/traffic", methods=["GET"])
@login_required
def get_traffic_stats():
    """Get traffic statistics (visits, unique visitors, geography, per-app breakdown)."""
    try:
        from app.utils.traffic_tracker import add_admin_ip, get_traffic_stats

        ip_address = request.headers.get("X-Forwarded-For", request.headers.get("X-Real-IP", request.remote_addr))
        if ip_address:
            ip_address = ip_address.split(",")[0].strip()
        else:
            ip_address = request.remote_addr or None
        if ip_address:
            add_admin_ip(current_app.instance_path, ip_address)

        days = request.args.get("days", 30, type=int)
        if days < 1 or days > 365:
            days = 30

        include_local = request.args.get("include_local", "true").lower() == "true"

        stats = get_traffic_stats(current_app.instance_path, days=days, include_local=include_local)

        return jsonify({"success": True, "stats": stats})
    except Exception as e:
        current_app.logger.error(f"Error getting traffic stats: {str(e)}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


@bp.route("/api/admin-logins", methods=["GET"])
@login_required
def get_admin_logins():
    """Get admin login statistics."""
    try:
        from app.utils.traffic_tracker import get_admin_login_stats

        ip_address = request.headers.get("X-Forwarded-For", request.headers.get("X-Real-IP", request.remote_addr))
        if ip_address:
            ip_address = ip_address.split(",")[0].strip()
        else:
            ip_address = request.remote_addr or None

        stats = get_admin_login_stats(current_app.instance_path, current_ip=ip_address)

        return jsonify({"success": True, "logins": stats})
    except Exception as e:
        current_app.logger.error(f"Error getting admin login stats: {str(e)}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500

