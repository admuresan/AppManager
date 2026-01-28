"""
Admin configuration API routes.

IMPORTANT: Read `instructions/architecture` before making changes.
"""

import json
from pathlib import Path

from flask import current_app, jsonify, request
from flask_login import login_required

from app.utils.app_usage_tracker import get_tracker

from ..blueprint import bp


@bp.route("/api/config/shutdown-timeout", methods=["GET"])
@login_required
def get_shutdown_timeout():
    """Get the auto-shutdown timeout in minutes."""
    try:
        tracker = get_tracker(current_app.instance_path)
        timeout = tracker.get_shutdown_timeout_minutes()
        return jsonify({"success": True, "timeout_minutes": timeout})
    except Exception as e:
        current_app.logger.error(f"Error getting shutdown timeout: {str(e)}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


@bp.route("/api/config/shutdown-timeout", methods=["POST"])
@login_required
def set_shutdown_timeout():
    """Set the auto-shutdown timeout in minutes."""
    try:
        data = request.get_json()
        timeout = data.get("timeout_minutes")

        if timeout is None:
            return jsonify({"success": False, "error": "timeout_minutes is required"}), 400

        try:
            timeout = int(timeout)
            if timeout < 1 or timeout > 1440:  # 1 minute to 24 hours
                return jsonify({"success": False, "error": "timeout_minutes must be between 1 and 1440 (24 hours)"}), 400
        except (ValueError, TypeError):
            return jsonify({"success": False, "error": "timeout_minutes must be a number"}), 400

        tracker = get_tracker(current_app.instance_path)
        tracker.set_shutdown_timeout_minutes(timeout)

        return jsonify({"success": True, "timeout_minutes": timeout, "message": f"Auto-shutdown timeout set to {timeout} minutes"})
    except Exception as e:
        current_app.logger.error(f"Error setting shutdown timeout: {str(e)}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


@bp.route("/api/config/env-vars", methods=["GET"])
@login_required
def get_env_vars():
    """Get environment variables configuration."""
    try:
        config_path = Path(current_app.instance_path) / "manager_config.json"
        env_vars = {}

        if config_path.exists():
            try:
                with open(config_path, "r") as f:
                    config = json.load(f)
                    env_vars = config.get("env_vars", {})
            except Exception as e:
                current_app.logger.warning(f"Error loading env vars: {e}")

        return jsonify({"success": True, "env_vars": env_vars})
    except Exception as e:
        current_app.logger.error(f"Error getting env vars: {str(e)}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


@bp.route("/api/config/env-vars", methods=["POST"])
@login_required
def set_env_vars():
    """Set environment variables configuration."""
    try:
        data = request.get_json()
        env_vars = data.get("env_vars", {})

        if not isinstance(env_vars, dict):
            return jsonify({"success": False, "error": "env_vars must be an object"}), 400

        config_path = Path(current_app.instance_path) / "manager_config.json"
        config = {}

        if config_path.exists():
            try:
                with open(config_path, "r") as f:
                    config = json.load(f)
            except Exception as e:
                current_app.logger.warning(f"Error loading config: {e}")

        config["env_vars"] = env_vars

        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)

        return jsonify({"success": True, "env_vars": env_vars, "message": "Environment variables updated successfully"})
    except Exception as e:
        current_app.logger.error(f"Error setting env vars: {str(e)}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500

