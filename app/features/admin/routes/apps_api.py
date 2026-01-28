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
from flask import Response, current_app, jsonify, request, stream_with_context
from flask_login import login_required
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from werkzeug.utils import secure_filename

from app.models.app_config import AppConfig
from app.utils.app_manager import (
    check_port_status,
    detect_service_name_by_port,
    get_active_ports_and_services,
    restart_app_service,
    test_app_port,
)
from app.utils.port_configuration import configure_firewall_port, configure_firewall_port_detailed
from app.utils.ssl_manager import (
    get_certificate_status_for_all_apps,
    regenerate_main_certificate,
    setup_ssl_for_app_port,
)

from ..blueprint import bp


# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@bp.route("/api/apps/<app_id>/fix-config", methods=["POST"])
@login_required
def fix_app_config(app_id):
    """Apply port config changes and return full results (non-streaming)."""
    result = None
    for event, payload in _fix_port_config_events(app_id):
        if event == "done":
            result = payload
    return jsonify(result or {"success": False, "error": "No result produced"})


@bp.route("/api/apps/<app_id>/fix-config/stream", methods=["GET"])
@login_required
def fix_app_config_stream(app_id):
    """Apply port config changes and stream progress/results as SSE."""

    def sse(event: str, payload: dict):
        return f"event: {event}\ndata: {json.dumps(payload)}\n\n"

    def generate():
        try:
            # IMPORTANT: yield events as they happen (true streaming).
            for event, payload in _fix_port_config_events(app_id):
                yield sse(event, payload)
        except Exception as e:
            yield sse("error", {"success": False, "error": str(e)})

    headers = {
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",  # nginx: disable response buffering for SSE
    }
    return Response(stream_with_context(generate()), headers=headers, mimetype="text/event-stream")

def _fix_port_config_events(app_id: str):
    """Yield (event_name, payload_dict) for Fix Port Configuration."""
    app_config = AppConfig.get_by_id(app_id)
    if not app_config:
        yield ("done", {"success": False, "error": "App not found"})
        return

    try:
        port = int(app_config.get("port"))
    except Exception:
        yield ("done", {"success": False, "error": "Invalid port"})
        return

    https_port = port + 10000

    # Host should be the configured domain (default blackgrid.ddns.net).
    host = (current_app.config.get("SERVER_DOMAIN") or "blackgrid.ddns.net").strip() or "blackgrid.ddns.net"

    yield ("meta", {"success": True, "host": host, "port": port, "https_port": https_port})

    # Apply rules with explicit structured details.
    yield ("step", {"phase": "apply", "message": f"Applying firewall/OCI rules for port {port}..."})
    port_apply = configure_firewall_port_detailed(port, action="allow")
    yield ("applied", {"phase": "apply", "target": "port", "result": port_apply})

    yield ("step", {"phase": "apply", "message": f"Applying firewall/OCI rules for HTTPS port {https_port}..."})
    https_apply = configure_firewall_port_detailed(https_port, action="allow")
    yield ("applied", {"phase": "apply", "target": "https_port", "result": https_apply})

    overall_ok = bool(port_apply.get("overall_success") and https_apply.get("overall_success"))

    # Tests
    yield ("step", {"phase": "test", "message": "Running port reachability tests..."})

    port_listening = bool(test_app_port(port))
    https_listening = bool(test_app_port(https_port))
    yield ("test", {"name": "socket_port", "port": port, "listening": port_listening})
    yield ("test", {"name": "socket_https_port", "port": https_port, "listening": https_listening})

    local_http_url = f"http://localhost:{port}/"
    local_http_accessible, local_http_status, _local_http_cert, local_http_successful = test_url(local_http_url, timeout=4)
    yield (
        "test",
        {
            "name": "local_http",
            "url": local_http_url,
            "accessible": local_http_accessible,
            "status": local_http_status,
            "successful": bool(local_http_successful),
        },
    )

    public_http_url = f"http://{host}:{port}/"
    public_http_accessible, public_http_status, _public_http_cert, public_http_successful = test_url(public_http_url, timeout=4)
    yield (
        "test",
        {
            "name": "public_http",
            "url": public_http_url,
            "accessible": public_http_accessible,
            "status": public_http_status,
            "successful": bool(public_http_successful),
        },
    )

    public_https_url = f"https://{host}:{https_port}/"
    public_https_accessible, public_https_status, public_https_cert, public_https_successful = test_url(public_https_url, timeout=6, check_ssl_cert=True)
    yield (
        "test",
        {
            "name": "public_https",
            "url": public_https_url,
            "accessible": public_https_accessible,
            "status": public_https_status,
            "successful": bool(public_https_successful),
            "certificate_info": public_https_cert,
        },
    )

    # Consider it "working" if public HTTP succeeds and HTTPS on the nginx port succeeds.
    tests_ok = bool(public_http_successful and public_https_successful)

    result = {
        "success": overall_ok,
        "details": {
            "host": host,
            "port": port,
            "https_port": https_port,
            "applied": {
                "port": port_apply,
                "https_port": https_apply,
            },
            # Back-compat fields for older UI renderers:
            "changes": {
                "port": {"raw": port_apply.get("messages", [])},
                "https_port": {"raw": https_apply.get("messages", [])},
            },
            "tests": {
                "port_listening": port_listening,
                "https_port_listening": https_listening,
                "local_http": {"url": local_http_url, "accessible": local_http_accessible, "successful": bool(local_http_successful), "status": local_http_status},
                "public_http": {"url": public_http_url, "accessible": public_http_accessible, "successful": bool(public_http_successful), "status": public_http_status},
                "public_https": {"url": public_https_url, "accessible": public_https_accessible, "successful": bool(public_https_successful), "status": public_https_status, "certificate_info": public_https_cert},
                "tests_ok": tests_ok,
            },
            "note": "If public tests fail, confirm: the app binds 0.0.0.0, the port is listening, and OCI Security List/NSG allows the port.",
        },
    }
    yield ("done", result)


@bp.route("/api/apps", methods=["GET"])
@login_required
def get_apps():
    """Get all apps (API endpoint)."""
    apps = AppConfig.get_all()
    return jsonify({"apps": apps})


@bp.route("/api/apps", methods=["POST"])
@login_required
def create_app():
    """Create a new app."""
    name = request.form.get("name")
    port = request.form.get("port")
    service_name = request.form.get("service_name", "")
    folder_path = request.form.get("folder_path", "").strip()

    if not name or not port:
        return jsonify({"error": "Name and port are required"}), 400

    try:
        port = int(port)
    except ValueError:
        return jsonify({"error": "Port must be a number"}), 400

    # Test if the port is listening before adding
    is_listening = test_app_port(port)
    if not is_listening:
        return (
            jsonify(
                {
                    "error": f"Port {port} is not listening. Please ensure the app is running on this port before adding it.",
                    "port": port,
                    "is_listening": False,
                }
            ),
            400,
        )

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
            folder_path=folder_path if folder_path else None,
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    # Configure firewall to allow HTTP port (only on server, not localhost)
    firewall_success, firewall_message = configure_firewall_port(port, action="allow")

    # Set up SSL for this app port (requires Let's Encrypt certificate)
    server_address = current_app.config.get("SERVER_ADDRESS", "localhost")
    server_domain = current_app.config.get("SERVER_DOMAIN", "blackgrid.ddns.net")
    ssl_success, ssl_message = setup_ssl_for_app_port(port, server_address, server_domain)

    # Also configure firewall for HTTPS port (port + 10000)
    https_port = port + 10000
    https_firewall_success, https_firewall_message = configure_firewall_port(https_port, action="allow")

    response_data = {"success": True, "app": app_config}
    if not firewall_success:
        response_data["firewall_warning"] = firewall_message
    if not https_firewall_success:
        response_data["https_firewall_warning"] = https_firewall_message
    if not ssl_success:
        response_data["ssl_warning"] = ssl_message
    else:
        response_data["ssl_info"] = ssl_message
        response_data["https_port"] = https_port

    return jsonify(response_data)


@bp.route("/api/apps/<app_id>", methods=["PUT"])
@login_required
def update_app(app_id):
    """Update an existing app."""
    # Check if this is form data (file upload) or JSON
    if request.content_type and "multipart/form-data" in request.content_type:
        data = request.form
        name = data.get("name")
        port = data.get("port")
        service_name = data.get("service_name", "")
        folder_path = data.get("folder_path", "").strip()

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

        final_logo = logo_path if logo_path else existing_app.get("logo")
    else:
        # JSON request
        data = request.get_json()
        name = data.get("name")
        port = data.get("port")
        service_name = data.get("service_name", "")
        folder_path = data.get("folder_path", "").strip()
        final_logo = data.get("logo")

    if not name or not port:
        return jsonify({"error": "Name and port are required"}), 400

    try:
        port = int(port)
    except ValueError:
        return jsonify({"error": "Port must be a number"}), 400

    # Get existing app to check if port changed
    existing_app = AppConfig.get_by_id(app_id)
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
        # If port changed, update firewall rules and SSL
        if port_changed:
            configure_firewall_port(port, action="allow")

        server_address = current_app.config.get("SERVER_ADDRESS", "localhost")
        server_domain = current_app.config.get("SERVER_DOMAIN", "blackgrid.ddns.net")
        ssl_success, ssl_message = setup_ssl_for_app_port(port, server_address, server_domain)

        https_port = port + 10000
        https_firewall_success, https_firewall_message = configure_firewall_port(https_port, action="allow")

        response_data = {"success": True, "app": app_config}
        if not https_firewall_success:
            response_data["https_firewall_warning"] = https_firewall_message
        if not ssl_success:
            response_data["ssl_warning"] = ssl_message
        else:
            response_data["ssl_info"] = ssl_message
            response_data["https_port"] = https_port

        return jsonify(response_data)

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
    """Test if an app is listening on direct HTTP/HTTPS ports (no masked-path proxy)."""
    app_config = AppConfig.get_by_id(app_id)
    if not app_config:
        return jsonify({"error": "App not found"}), 404

    port = app_config["port"]
    app_slug = AppConfig._slugify(app_config["name"])
    server_address = current_app.config.get("SERVER_ADDRESS", "localhost")
    server_domain = current_app.config.get("SERVER_DOMAIN", None)

    http_url = f"http://{server_address}:{port}"
    http_accessible, http_status, _, http_successful = test_url(http_url)
    http_test_url = http_url

    if not http_accessible and server_address != "localhost":
        localhost_url = f"http://localhost:{port}"
        localhost_accessible, localhost_status, _, localhost_successful = test_url(localhost_url)
        if localhost_accessible:
            http_accessible = True
            http_status = localhost_status
            http_test_url = localhost_url
            http_successful = localhost_successful

    public_host = server_domain if server_domain and server_domain != "localhost" else (request.host.split(":")[0] if request.host else server_address)
    public_http_url = f"http://{public_host}:{port}"
    public_http_accessible, public_http_status, _, public_http_successful = test_url(public_http_url)

    https_port = port + 10000
    https_host = server_domain if server_domain and server_domain != "localhost" else server_address

    https_url = f"https://{https_host}:{https_port}"
    https_accessible, https_status, https_cert_info, https_successful = test_url(https_url, check_ssl_cert=True)
    https_test_url = https_url

    if not https_accessible and server_domain and server_domain != "localhost" and server_address != "localhost":
        https_url_ip = f"https://{server_address}:{https_port}"
        https_accessible_ip, https_status_ip, https_cert_info_ip, https_successful_ip = test_url(https_url_ip, check_ssl_cert=True)
        if https_accessible_ip:
            https_accessible = True
            https_status = https_status_ip
            https_test_url = https_url_ip
            https_cert_info = https_cert_info_ip
            https_successful = https_successful_ip

    is_listening = test_app_port(port)

    from app.utils.ssl_manager import _check_file_exists, get_main_ssl_certificate, is_certificate_trusted, is_nginx_configured_for_port

    nginx_configured = is_nginx_configured_for_port(port)

    ssl_cert_status = {
        "nginx_configured": nginx_configured,
        "certificate_exists": False,
        "certificate_trusted": False,
        "certificate_path": None,
        "certificate_info": https_cert_info,
    }

    try:
        cert_file, key_file = get_main_ssl_certificate()
        cert_exists = _check_file_exists(cert_file) and _check_file_exists(key_file)
        cert_trusted = is_certificate_trusted(cert_file) if cert_exists else False

        ssl_cert_status["certificate_exists"] = cert_exists
        ssl_cert_status["certificate_trusted"] = cert_trusted
        ssl_cert_status["certificate_path"] = cert_file if cert_exists else None

        if https_cert_info:
            ssl_cert_status["certificate_info"] = https_cert_info
    except Exception as e:
        ssl_cert_status["error"] = str(e)

    return jsonify(
        {
            "success": True,
            "port": port,
            "app_slug": app_slug,
            "http": {"accessible": http_accessible, "successful": http_successful if http_accessible else False, "status": http_status, "url": http_test_url},
            "public_http": {
                "accessible": public_http_accessible,
                "successful": public_http_successful if public_http_accessible else False,
                "status": public_http_status,
                "url": public_http_url,
                "host": public_host,
            },
            "https": {
                "accessible": https_accessible,
                "successful": https_successful if https_accessible else False,
                "status": https_status,
                "url": https_test_url,
                "port": https_port,
                "nginx_configured": nginx_configured,
                "certificate_status": ssl_cert_status,
            },
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


@bp.route("/api/apps/<app_id>/restart", methods=["POST"])
@login_required
def restart_app(app_id):
    """Restart an app service."""
    try:
        app_config = AppConfig.get_by_id(app_id)
        if not app_config:
            return jsonify({"success": False, "error": "App not found"}), 404

        service_name = app_config.get("service_name", f"app-{app_config['port']}.service")
        success, message = restart_app_service(service_name)

        if success:
            return jsonify({"success": True, "message": message})
        return jsonify({"success": False, "error": message}), 500
    except Exception as e:
        current_app.logger.error(f"Error restarting app {app_id}: {str(e)}", exc_info=True)
        return jsonify({"success": False, "error": f"Error restarting app: {str(e)}"}), 500


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

