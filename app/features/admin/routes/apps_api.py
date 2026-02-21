"""
Admin app-management API routes.

IMPORTANT: Read `instructions/architecture` before making changes.
"""

import os
import platform
import subprocess
import time
from pathlib import Path

import json
import requests
import urllib3
from flask import current_app, jsonify, request
from flask_login import login_required
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from werkzeug.utils import secure_filename

from app.models.app_config import AppConfig
from app.utils.app_manager import (
    _get_pid_by_port,
    check_port_status,
    detect_service_name_by_port,
    get_active_ports_and_services,
    start_app_linux,
    start_app_windows,
    test_app_port,
)
from ..blueprint import bp


# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@bp.route("/api/apps", methods=["GET"])
@login_required
def get_apps():
    """Get all apps (API endpoint)."""
    apps = AppConfig.get_all()
    return jsonify({"apps": apps})


@bp.route("/api/apps", methods=["POST"])
@login_required
def create_app():
    """Create a new app. Name and folder_path required. Port optional (detected from app.py)."""
    name = request.form.get("name", "").strip()
    port_str = request.form.get("port", "").strip()
    service_name = request.form.get("service_name", "").strip()
    folder_path = request.form.get("folder_path", "").strip()

    if not name:
        return jsonify({"error": "App name is required"}), 400
    if not folder_path:
        return jsonify({"error": "App folder path is required"}), 400

    # Port: use provided value or detect from folder
    if port_str:
        try:
            port = int(port_str)
        except ValueError:
            return jsonify({"error": "Port must be a number"}), 400
    else:
        from app.utils.app_discovery import _get_port_for_folder
        detected = _get_port_for_folder(Path(folder_path).resolve())
        port = detected if detected is not None else 5000

    # Port listening check: warn only, allow adding (user can Start after adding)
    is_listening = test_app_port(port)
    if not is_listening:
        current_app.logger.info("Adding app on port %s which is not yet listening", port)

    # Handle logo upload
    logo_path = None
    if "logo" in request.files:
        file = request.files["logo"]
        if file.filename:
            filename = secure_filename(file.filename)
            instance_path = Path(current_app.instance_path)
            logo_dir = instance_path / "uploads" / "logos"
            logo_dir.mkdir(parents=True, exist_ok=True)

            # Generate unique filename
            import uuid

            unique_filename = f"{uuid.uuid4()}_{filename}"
            filepath = logo_dir / unique_filename
            file.save(filepath)
            # Store path relative to instance directory (without 'uploads/' prefix since route handles it)
            logo_path = f"logos/{unique_filename}"

    try:
        app_config = AppConfig.create(
            name=name,
            port=port,
            logo=logo_path,
            service_name=service_name if service_name else None,
            serve_app=True,
            folder_path=folder_path,
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    return jsonify({"success": True, "app": app_config})


@bp.route("/api/apps/<app_id>", methods=["PUT"])
@login_required
def update_app(app_id):
    """Update an existing app."""
    # Check if this is form data (file upload) or JSON
    if request.content_type and "multipart/form-data" in request.content_type:
        data = request.form
        name = (data.get("name") or "").strip()
        port_str = str(data.get("port", "")).strip()
        service_name = (data.get("service_name") or "").strip()
        folder_path = (data.get("folder_path") or "").strip()

        # Handle logo upload if provided
        logo_path = None
        if "logo" in request.files:
            file = request.files["logo"]
            if file.filename:
                filename = secure_filename(file.filename)
                instance_path = Path(current_app.instance_path)
                logo_dir = instance_path / "uploads" / "logos"
                logo_dir.mkdir(parents=True, exist_ok=True)

                import uuid

                unique_filename = f"{uuid.uuid4()}_{filename}"
                filepath = logo_dir / unique_filename
                file.save(filepath)
                logo_path = f"uploads/logos/{unique_filename}"

        # Get existing app to preserve logo if not updating
        existing_app = AppConfig.get_by_id(app_id)
        if not existing_app:
            return jsonify({"error": "App not found"}), 404

        if port_str:
            try:
                port = int(port_str)
            except ValueError:
                return jsonify({"error": "Port must be a number"}), 400
        elif folder_path:
            from app.utils.app_discovery import _get_port_for_folder
            detected = _get_port_for_folder(Path(folder_path).resolve())
            port = detected if detected is not None else 5000
        else:
            port = existing_app.get("port", 5000)
        final_logo = logo_path if logo_path else existing_app.get("logo")
    else:
        # JSON request
        data = request.get_json(silent=True) or {}
        name = (data.get("name") or "").strip()
        service_name = (data.get("service_name") or "").strip()
        folder_path = (data.get("folder_path") or "").strip()
        final_logo = data.get("logo")
        existing_app = AppConfig.get_by_id(app_id)
        if not existing_app:
            return jsonify({"error": "App not found"}), 404
        raw_port = data.get("port")
        if raw_port is not None and raw_port != "":
            try:
                port = int(raw_port)
            except (ValueError, TypeError):
                return jsonify({"error": "Port must be a number"}), 400
        elif folder_path:
            from app.utils.app_discovery import _get_port_for_folder
            detected = _get_port_for_folder(Path(folder_path).resolve())
            port = detected if detected is not None else 5000
        else:
            port = existing_app.get("port", 5000)

    if not name:
        return jsonify({"error": "App name is required"}), 400

    if not existing_app:
        return jsonify({"error": "App not found"}), 404

    old_port = existing_app.get("port")
    port_changed = old_port != port

    try:
        app_config = AppConfig.update(
            app_id=app_id,
            name=name,
            port=port,
            logo=final_logo,
            service_name=service_name if service_name else None,
            folder_path=folder_path if folder_path else None,
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    if app_config:
        return jsonify({"success": True, "app": app_config})

    return jsonify({"error": "App not found"}), 404


@bp.route("/api/apps/<app_id>", methods=["DELETE"])
@login_required
def delete_app(app_id):
    """Delete an app."""
    app_config = AppConfig.get_by_id(app_id)
    if not app_config:
        return jsonify({"error": "App not found"}), 404

    success = AppConfig.delete(app_id)
    if success:
        return jsonify({"success": True})
    return jsonify({"error": "App not found"}), 404


@bp.route("/api/apps/<app_id>/toggle-serve", methods=["POST"])
@login_required
def toggle_serve_app(app_id):
    """Toggle the serve_app status for an app."""
    app_config = AppConfig.toggle_serve_app(app_id)
    if app_config:
        return jsonify({"success": True, "app": app_config})
    return jsonify({"error": "App not found"}), 404


def test_url(url, timeout=3, check_ssl_cert=False):
    """Test if a URL is accessible.

    Returns:
        Tuple of (connection_successful: bool, status: int or str, cert_info: dict or None, request_successful: bool)
    """
    cert_info = None
    try:
        session = requests.Session()
        retry_strategy = Retry(
            total=1,
            backoff_factor=0.1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        verify_ssl = check_ssl_cert if url.startswith("https://") else False

        response = session.get(url, timeout=timeout, verify=verify_ssl, allow_redirects=True)

        request_successful = 200 <= response.status_code < 300

        if url.startswith("https://"):
            try:
                cert_info = {"verified": verify_ssl, "subject": None, "issuer": None, "expires": None}
                try:
                    if hasattr(response.raw, "connection") and hasattr(response.raw.connection, "sock"):
                        sock = response.raw.connection.sock
                        if hasattr(sock, "getpeercert"):
                            cert = sock.getpeercert()
                            if cert:
                                cert_info["subject"] = dict(x[0] for x in cert.get("subject", []))
                                cert_info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                                cert_info["expires"] = cert.get("notAfter")
                except Exception:
                    pass

                if not cert_info.get("issuer") and response.history:
                    try:
                        for hist_resp in response.history:
                            if hasattr(hist_resp.raw, "connection") and hasattr(hist_resp.raw.connection, "sock"):
                                sock = hist_resp.raw.connection.sock
                                if hasattr(sock, "getpeercert"):
                                    cert = sock.getpeercert()
                                    if cert:
                                        cert_info["subject"] = dict(x[0] for x in cert.get("subject", []))
                                        cert_info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                                        cert_info["expires"] = cert.get("notAfter")
                                        break
                    except Exception:
                        pass
            except Exception as e:
                cert_info = {"verified": verify_ssl, "error": str(e)}

        return True, response.status_code, cert_info if cert_info else None, request_successful
    except requests.exceptions.SSLError as e:
        cert_info = {"verified": False, "error": str(e), "subject": None, "issuer": None}
        try:
            temp_session = requests.Session()
            temp_response = temp_session.get(url, timeout=timeout, verify=False, allow_redirects=True)
            if hasattr(temp_response.raw, "connection") and hasattr(temp_response.raw.connection, "sock"):
                sock = temp_response.raw.connection.sock
                if hasattr(sock, "getpeercert"):
                    cert = sock.getpeercert()
                    if cert:
                        cert_info["subject"] = dict(x[0] for x in cert.get("subject", []))
                        cert_info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                        cert_info["expires"] = cert.get("notAfter")
        except Exception:
            pass
        return True, "SSL_ERROR", cert_info, False
    except requests.exceptions.ConnectionError:
        return False, "CONNECTION_ERROR", None, False
    except requests.exceptions.Timeout:
        return False, "TIMEOUT", None, False
    except Exception as e:
        return False, str(e), None, False


@bp.route("/api/apps/<app_id>/test", methods=["POST"])
@login_required
def test_app(app_id):
    """Test if an app is listening on its HTTP port."""
    app_config = AppConfig.get_by_id(app_id)
    if not app_config:
        return jsonify({"error": "App not found"}), 404

    port = app_config["port"]
    app_slug = AppConfig._slugify(app_config["name"])
    server_address = current_app.config.get("SERVER_ADDRESS", "localhost")

    http_url = f"http://{server_address}:{port}"
    http_accessible, http_status, _, http_successful = test_url(http_url)

    if not http_accessible and server_address != "localhost":
        localhost_url = f"http://localhost:{port}"
        localhost_accessible, localhost_status, _, localhost_successful = test_url(localhost_url)
        if localhost_accessible:
            http_accessible = True
            http_status = localhost_status
            http_url = localhost_url
            http_successful = localhost_successful

    is_listening = test_app_port(port)

    return jsonify(
        {
            "success": True,
            "port": port,
            "app_slug": app_slug,
            "http": {"accessible": http_accessible, "successful": http_successful if http_accessible else False, "status": http_status, "url": http_url},
            "is_listening": is_listening,
        }
    )


@bp.route("/api/detect-service/<int:port>", methods=["GET"])
@login_required
def detect_service(port):
    """Detect systemd service name for a given port."""
    service_name = detect_service_name_by_port(port)
    if service_name:
        return jsonify({"success": True, "service_name": service_name, "port": port})
    return jsonify({"success": False, "message": "Could not detect service name for this port", "port": port})


@bp.route("/api/active-ports", methods=["GET"])
@login_required
def active_ports():
    """Get list of active ports and their service names."""
    ports = get_active_ports_and_services()
    return jsonify({"success": True, "ports": ports})


@bp.route("/api/check-port/<int:port>", methods=["GET"])
@login_required
def check_port(port):
    """Check detailed status of a specific port."""
    status = check_port_status(port)
    return jsonify({"success": True, "status": status})


@bp.route("/api/apps/<app_id>/start", methods=["POST"])
@login_required
def start_app(app_id):
    """Start an app: venv/deps (logged), detached subprocess, then check port in 2–8s and return."""
    app_config = AppConfig.get_by_id(app_id)
    if not app_config:
        return jsonify({"success": False, "error": "App not found"}), 404

    start_command = app_config.get("windows_start_command") or "python app.py"
    port = app_config.get("port")
    folder_path = (app_config.get("folder_path") or "").strip()
    instance_path = current_app.instance_path

    if platform.system() == "Windows":
        path_to_use = app_config.get("windows_path", "").strip()
        if not path_to_use:
            return jsonify({"success": False, "error": "Windows path is not configured. Edit the app and set the Windows path."}), 400
        success, message = start_app_windows(folder_path=path_to_use, start_command=start_command, port=port, app_id=app_id, instance_path=instance_path)
    else:
        if not folder_path:
            return jsonify({"success": False, "error": "App folder path is not configured. Edit the app and set the folder path."}), 400
        success, message = start_app_linux(folder_path=folder_path, start_command=start_command, port=port, app_id=app_id, instance_path=instance_path)

    if success:
        return jsonify({"success": True, "message": message})
    return jsonify({"success": False, "error": message}), 400


@bp.route("/api/apps/<app_id>/restart", methods=["POST"])
@login_required
def restart_app(app_id):
    """Restart an app (stop by port, then start via venv)."""
    try:
        app_config = AppConfig.get_by_id(app_id)
        if not app_config:
            return jsonify({"success": False, "error": "App not found"}), 404

        port = app_config.get("port")
        if port:
            pid = _get_pid_by_port(port)
            if pid:
                try:
                    os.kill(pid, 15)
                    time.sleep(2)
                except Exception:
                    pass

        start_command = app_config.get("windows_start_command") or "python app.py"
        folder_path = (app_config.get("folder_path") or "").strip()

        instance_path = current_app.instance_path
        if platform.system() == "Windows":
            path_to_use = app_config.get("windows_path", "").strip()
            if not path_to_use:
                return jsonify({"success": False, "error": "Windows path not configured"}), 400
            success, message = start_app_windows(folder_path=path_to_use, start_command=start_command, port=port, app_id=app_id, instance_path=instance_path)
        else:
            if not folder_path:
                return jsonify({"success": False, "error": "App folder path not configured"}), 400
            success, message = start_app_linux(folder_path=folder_path, start_command=start_command, port=port, app_id=app_id, instance_path=instance_path)

        if success:
            return jsonify({"success": True, "message": message})
        return jsonify({"success": False, "error": message}), 500
    except Exception as e:
        current_app.logger.error(f"Error restarting app {app_id}: {str(e)}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


@bp.route("/api/restart-appmanager", methods=["POST"])
@login_required
def restart_appmanager():
    """Restart the AppManager service."""
    try:
        restart_command = "sleep 1 && sudo systemctl restart appmanager.service"

        try:
            subprocess.Popen(
                ["sudo", "systemd-run", "--unit=appmanager-restart", "sh", "-c", restart_command],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except (FileNotFoundError, OSError):
            subprocess.Popen(
                ["nohup", "sh", "-c", restart_command],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                preexec_fn=os.setsid if hasattr(os, "setsid") else None,
            )

        return jsonify(
            {"success": True, "message": "App Manager restart initiated. You will be disconnected momentarily."}
        )
    except Exception as e:
        current_app.logger.error(f"Error initiating AppManager restart: {str(e)}", exc_info=True)
        return jsonify({"success": False, "error": f"Error initiating restart: {str(e)}"}), 500

