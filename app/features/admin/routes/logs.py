"""
Admin log viewing routes + log API.

IMPORTANT: Read `instructions/architecture` before making changes.
"""

from pathlib import Path

from flask import current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import login_required

from app.models.app_config import AppConfig
from app.utils.app_manager import get_app_logs, get_app_logs_from_file, get_appmanager_logs_from_file

from ..blueprint import bp


@bp.route("/apps/<app_id>/logs")
@login_required
def view_logs(app_id):
    """View logs for an application."""
    try:
        app_config = AppConfig.get_by_id(app_id)
        if not app_config:
            flash("App not found", "error")
            return redirect(url_for("admin.dashboard"))

        service_name = app_config.get("service_name")
        app_name = app_config.get("name", "Unknown")

        lines = request.args.get("lines", 500, type=int)
        if lines < 1:
            lines = 100
        elif lines > 10000:
            lines = 10000

        # Prefer file first (apps started from dashboard write here); fall back to journalctl
        success, logs_or_error, oldest_ts, newest_ts = get_app_logs_from_file(
            app_id, current_app.instance_path, lines=lines
        )
        if not success and service_name:
            success, logs_or_error, oldest_ts, newest_ts = get_app_logs(service_name, lines=lines)

        return render_template(
            "admin/logs.html",
            app=app_config,
            app_name=app_name,
            service_name=service_name,
            logs=logs_or_error if success else None,
            error=logs_or_error if not success else None,
            lines=lines,
            oldest_timestamp=oldest_ts or None,
            newest_timestamp=newest_ts or None,
        )
    except Exception as e:
        current_app.logger.error(f"Error in view_logs: {str(e)}", exc_info=True)
        flash(f"Error loading logs: {str(e)}", "error")
        return redirect(url_for("admin.dashboard"))


@bp.route("/api/apps/<app_id>/logs")
@login_required
def get_logs_api(app_id):
    """API endpoint for dynamic log loading."""
    app_config = AppConfig.get_by_id(app_id)
    if not app_config:
        return jsonify({"error": "App not found"}), 404

    service_name = app_config.get("service_name")
    lines = request.args.get("lines", 500, type=int)
    since = request.args.get("since", None)
    until = request.args.get("until", None)
    direction = request.args.get("direction", "newer")

    # Prefer file first (apps started from dashboard write here); fall back to journalctl
    success, logs_or_error, oldest_ts, newest_ts = get_app_logs_from_file(
        app_id, current_app.instance_path, lines=lines
    )
    if not success and service_name:
        since_param = until if direction == "newer" and until else None
        until_param = since if direction == "older" and since else None
        success, logs_or_error, oldest_ts, newest_ts = get_app_logs(
            service_name, lines=lines, since=since_param, until=until_param
        )

    if success:
        return jsonify(
            {
                "success": True,
                "logs": logs_or_error,
                "oldest_timestamp": oldest_ts,
                "newest_timestamp": newest_ts,
                "has_more": len(logs_or_error.strip().split("\n")) >= lines if logs_or_error else False,
            }
        )

    return jsonify({"success": False, "error": logs_or_error}), 500


@bp.route("/api/logs/appmanager")
@login_required
def get_appmanager_logs():
    """Get AppManager's own logs: read from log file first, then journalctl if no file."""
    try:
        lines = request.args.get("lines", 300, type=int)
        if lines < 50:
            lines = 50
        if lines > 2000:
            lines = 2000

        instance_path = current_app.instance_path
        log_path = Path(instance_path) / "logs" / "appmanager.log"

        # Prefer log file (we always write to it when running)
        if log_path.exists():
            success, logs_or_error, oldest_ts, newest_ts = get_appmanager_logs_from_file(
                instance_path, lines=lines
            )
        else:
            success, logs_or_error, oldest_ts, newest_ts = (False, "Log file not found", None, None)

        # Fallback to journalctl only when file does not exist (e.g. systemd-only deployment)
        if not success:
            success, logs_or_error, oldest_ts, newest_ts = get_app_logs("appmanager.service", lines=lines)
        if not success and "No entries" in str(logs_or_error):
            success, logs_or_error, oldest_ts, newest_ts = get_app_logs("appmanager", lines=lines)

        if not success:
            return jsonify({"success": False, "error": logs_or_error}), 500

        return jsonify(
            {
                "success": True,
                "logs": logs_or_error,
                "oldest_timestamp": oldest_ts,
                "newest_timestamp": newest_ts,
            }
        )
    except Exception as e:
        current_app.logger.error(f"Error getting AppManager logs: {str(e)}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500



