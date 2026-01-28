"""
Admin log viewing routes + log API.

IMPORTANT: Read `instructions/architecture` before making changes.
"""

from flask import current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import login_required

from app.models.app_config import AppConfig
from app.utils.app_manager import get_app_logs

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
    if not service_name:
        return jsonify({"error": "Service name not configured"}), 400

    lines = request.args.get("lines", 500, type=int)
    since = request.args.get("since", None)
    until = request.args.get("until", None)
    direction = request.args.get("direction", "newer")

    since_param = None
    until_param = None

    if direction == "older" and since:
        until_param = since
    elif direction == "newer" and until:
        since_param = until

    success, logs_or_error, oldest_ts, newest_ts = get_app_logs(service_name, lines=lines, since=since_param, until=until_param)

    if success:
        return jsonify(
            {
                "success": True,
                "logs": logs_or_error,
                "oldest_timestamp": oldest_ts,
                "newest_timestamp": newest_ts,
                "has_more": len(logs_or_error.strip().split("\n")) >= lines,
            }
        )

    return jsonify({"success": False, "error": logs_or_error}), 500


@bp.route("/api/logs/appmanager")
@login_required
def get_appmanager_logs():
    """Get AppManager's own logs, filtered for errors and proxy issues."""
    try:
        lines = request.args.get("lines", 200, type=int)
        filter_type = request.args.get("filter", "all")  # 'all', 'error', 'proxy', 'deltabooks'

        success, logs_or_error, oldest_ts, newest_ts = get_app_logs("appmanager.service", lines=lines)

        if not success:
            return jsonify({"error": logs_or_error}), 500

        if filter_type == "error":
            filtered_lines = [line for line in logs_or_error.split("\n") if "ERROR" in line.upper() or "error" in line.lower()]
            logs_or_error = "\n".join(filtered_lines)
        elif filter_type == "proxy":
            filtered_lines = [line for line in logs_or_error.split("\n") if "proxy" in line.lower() or "proxying" in line.lower()]
            logs_or_error = "\n".join(filtered_lines)
        elif filter_type == "deltabooks":
            filtered_lines = [line for line in logs_or_error.split("\n") if "deltabooks" in line.lower() or "6002" in line]
            logs_or_error = "\n".join(filtered_lines)

        return jsonify(
            {
                "success": True,
                "logs": logs_or_error,
                "oldest_timestamp": oldest_ts,
                "newest_timestamp": newest_ts,
                "filter": filter_type,
            }
        )
    except Exception as e:
        current_app.logger.error(f"Error getting AppManager logs: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@bp.route("/api/logs/proxy-errors")
@login_required
def get_proxy_errors():
    """Get recent proxy-related errors."""
    try:
        lines = request.args.get("lines", 100, type=int)

        success, logs_or_error, oldest_ts, newest_ts = get_app_logs("appmanager.service", lines=lines * 2)

        if not success:
            return jsonify({"error": logs_or_error}), 500

        error_keywords = ["error", "exception", "traceback", "failed", "500", "proxy"]
        filtered_lines = []
        for line in logs_or_error.split("\n"):
            line_lower = line.lower()
            if any(keyword in line_lower for keyword in error_keywords):
                filtered_lines.append(line)

        logs_or_error = "\n".join(filtered_lines[-lines:])

        return jsonify({"success": True, "logs": logs_or_error, "oldest_timestamp": oldest_ts, "newest_timestamp": newest_ts})
    except Exception as e:
        current_app.logger.error(f"Error getting proxy errors: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500

