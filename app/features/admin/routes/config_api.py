"""
Admin configuration API routes.

IMPORTANT: Read `instructions/architecture` before making changes.
"""

import json
from pathlib import Path

from flask import current_app, jsonify, request
from flask_login import login_required

from app.utils.admin_config import get_admin_config, save_admin_config
from app.utils.app_discovery import discover_apps, get_default_app_search_folder
from app.utils.app_usage_tracker import get_tracker

from ..blueprint import bp


@bp.route("/api/config/admin", methods=["GET"])
@login_required
def get_admin_settings():
    """Get admin settings (app_search_folders, etc.)."""
    try:
        cfg = get_admin_config(current_app.instance_path)
        return jsonify({"success": True, "config": cfg})
    except Exception as e:
        current_app.logger.error(f"Error getting admin config: {str(e)}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


@bp.route("/api/config/admin", methods=["POST"])
@login_required
def set_admin_settings():
    """Update admin settings."""
    try:
        data = request.get_json() or {}
        cfg = get_admin_config(current_app.instance_path)
        if "app_search_folders" in data:
            folders = data["app_search_folders"]
            if isinstance(folders, list):
                cfg["app_search_folders"] = [str(f).strip() for f in folders if str(f).strip()]
            else:
                cfg["app_search_folders"] = []
        save_admin_config(current_app.instance_path, cfg)
        return jsonify({"success": True, "config": get_admin_config(current_app.instance_path)})
    except Exception as e:
        current_app.logger.error(f"Error setting admin config: {str(e)}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


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


@bp.route("/api/config/detect-port", methods=["GET"])
@login_required
def detect_port_from_folder():
    """Detect port from app.py in the given folder."""
    from app.utils.app_discovery import _get_port_for_folder

    folder_path = request.args.get("folder_path", "").strip()
    if not folder_path:
        return jsonify({"success": False, "error": "folder_path required"}), 400
    path = Path(folder_path).resolve()
    if not path.exists() or not path.is_dir():
        return jsonify({"success": False, "error": "Folder does not exist"}), 400
    port = _get_port_for_folder(path)
    return jsonify({"success": True, "port": port or 5000})


@bp.route("/api/config/discovered-apps", methods=["GET"])
@login_required
def get_discovered_apps():
    """Discover apps in configured search folders (folders with app.py)."""
    try:
        from app.models.app_config import AppConfig

        cfg = get_admin_config(current_app.instance_path)
        search_folders = cfg.get("app_search_folders") or []
        if not search_folders:
            default = get_default_app_search_folder(current_app.instance_path)
            search_folders = [default] if default else []

        appmanager_root = str(Path(current_app.instance_path).parent)
        exclude = [appmanager_root]

        registered = {a.get("folder_path", "").strip() for a in AppConfig.get_all() if a.get("folder_path")}
        registered = {str(Path(p).resolve()) for p in registered if p}

        discovered = discover_apps(search_folders, exclude_folders=exclude)

        search_status = []
        for folder_str in search_folders:
            folder = Path(folder_str).resolve()
            if not folder.exists():
                current_app.logger.warning("App search folder does not exist: %s", folder)
                search_status.append({"path": str(folder), "exists": False, "reason": "path does not exist"})
            elif not folder.is_dir():
                current_app.logger.warning("App search folder is not a directory: %s", folder)
                search_status.append({"path": str(folder), "exists": False, "reason": "not a directory"})
            else:
                search_status.append({"path": str(folder), "exists": True})

        folder_to_app = {}
        for a in AppConfig.get_all():
            fp = (a.get("folder_path") or "").strip()
            if fp:
                folder_to_app[str(Path(fp).resolve())] = a

        for app in discovered:
            path_key = str(Path(app["folder_path"]).resolve())
            app["already_registered"] = path_key in registered
            if app["already_registered"]:
                matched = folder_to_app.get(path_key)
                if matched:
                    app["app_id"] = matched.get("id")
                    app["service_name"] = matched.get("service_name")
                    app["auto_start"] = matched.get("auto_start", False)
                    app["slug"] = AppConfig.get_effective_slug(matched)
                    if matched.get("port") is not None:
                        app["port"] = matched["port"]

        return jsonify({"success": True, "apps": discovered, "search_folders": search_status})
    except Exception as e:
        current_app.logger.error(f"Error discovering apps: {str(e)}", exc_info=True)
        return jsonify({"success": False, "error": str(e), "apps": []}), 500

