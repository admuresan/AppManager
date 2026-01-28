"""
Welcome routes.

IMPORTANT: Read `instructions/architecture` before making changes.
"""

import time
from pathlib import Path

from flask import abort, current_app, redirect, render_template, request, send_from_directory, url_for

from app.models.app_config import AppConfig

from .blueprint import bp


def get_server_address():
    """Get the server address for direct port links."""
    server_address = current_app.config.get("SERVER_ADDRESS", "localhost")

    if server_address == "localhost" and current_app.config.get("ENV") != "development":
        host = request.host.split(":")[0]
        if host and host != "127.0.0.1":
            return host

    return server_address


@bp.route("/")
def index():
    """Welcome page showing available apps."""
    apps = AppConfig.get_served_apps()
    server_address = get_server_address()

    manager_app = {"id": "manager", "name": "App Manager", "port": None, "logo": None, "is_manager": True}

    return render_template("welcome.html", apps=apps, manager_app=manager_app, server_address=server_address)


@bp.route("/media/<path:filename>")
def media_file(filename):
    """Serve media files from app/media directory."""
    media_path = Path(current_app.root_path) / "media"
    response = send_from_directory(media_path, filename)
    if filename.lower().endswith(".png"):
        response.headers["Content-Type"] = "image/png"
    return response


@bp.route("/app-icon/<app_slug>")
def app_icon(app_slug):
    """
    Serve the configured app logo for a given app slug.
    This is used for per-app favicons so browsers don't cross-cache favicons across apps.
    """
    try:
        app_config = AppConfig.get_by_slug(app_slug)
        if not app_config or not app_config.get("serve_app", True):
            abort(404)

        logo_path = app_config.get("logo")
        instance_path = Path(current_app.instance_path)

        if logo_path:
            if logo_path.startswith("uploads/"):
                file_path = instance_path / logo_path
            elif logo_path.startswith("logos/"):
                file_path = instance_path / "uploads" / logo_path
            else:
                file_path = instance_path / "uploads" / "logos" / logo_path

            if file_path.exists() and file_path.is_file():
                resp = send_from_directory(file_path.parent, file_path.name)
                resp.headers["Cache-Control"] = "no-cache"
                ext = file_path.suffix.lower()
                if ext == ".ico":
                    resp.headers["Content-Type"] = "image/x-icon"
                elif ext == ".png":
                    resp.headers["Content-Type"] = "image/png"
                elif ext in (".jpg", ".jpeg"):
                    resp.headers["Content-Type"] = "image/jpeg"
                elif ext == ".gif":
                    resp.headers["Content-Type"] = "image/gif"
                elif ext == ".svg":
                    resp.headers["Content-Type"] = "image/svg+xml"
                elif ext == ".webp":
                    resp.headers["Content-Type"] = "image/webp"
                return resp

        media_path = Path(current_app.root_path) / "media"
        resp = send_from_directory(media_path, "BlackGrid.png")
        resp.headers["Content-Type"] = "image/png"
        resp.headers["Cache-Control"] = "no-cache"
        return resp
    except Exception:
        abort(404)


@bp.route("/select/<app_id>")
def select_app(app_id):
    """Select an app to use - starts it (if needed) and redirects to https://{domain}:{port+10000}."""
    try:
        if app_id == "manager":
            return redirect(url_for("admin.dashboard"))

        app_config = AppConfig.get_by_id(app_id)
        if not app_config:
            current_app.logger.warning(f"App not found for ID: {app_id}")
            return redirect(url_for("welcome.index"))

        if not app_config.get("serve_app", True):
            current_app.logger.info(f"App {app_id} exists but is not set to be served")
            return redirect(url_for("welcome.index"))

        app_slug = AppConfig._slugify(app_config["name"])

        try:
            from app.utils.app_manager import configure_firewall_port, start_app_service, test_app_port

            app_port = int(app_config.get("port"))
            is_running = test_app_port(app_port)

            if not is_running:
                service_name = app_config.get("service_name")
                if service_name:
                    current_app.logger.info(f"App {app_config.get('name')} not running on {app_port}; starting service {service_name}")
                    start_ok, start_msg = start_app_service(service_name)
                    current_app.logger.info(f"Start service result: ok={start_ok} msg={start_msg}")

                    max_wait_s = 20
                    step_s = 0.5
                    waited = 0.0
                    while waited < max_wait_s and not test_app_port(app_port):
                        time.sleep(step_s)
                        waited += step_s
        except Exception as e:
            current_app.logger.warning(f"Error ensuring app is running: {e}")

        try:
            from app.utils.port_configuration import configure_firewall_port

            app_port = int(app_config.get("port"))
            configure_firewall_port(app_port, action="allow")
        except Exception as e:
            current_app.logger.warning(f"Error configuring firewall for app: {e}")

        server_domain = current_app.config.get("SERVER_DOMAIN") or ""
        host = (server_domain.strip() or request.host.split(":")[0]).strip()
        app_port = int(app_config.get("port"))
        https_port = app_port + 10000
        app_url = f"https://{host}:{https_port}"

        current_app.logger.debug(f"Redirecting to app: {app_url} (app_id={app_id}, app_slug={app_slug})")
        return redirect(app_url)

    except Exception as e:
        import traceback

        error_msg = f"Error in select_app route for app_id '{app_id}': {str(e)}\n{traceback.format_exc()}"
        current_app.logger.error(error_msg)
        return redirect(url_for("welcome.index"))

