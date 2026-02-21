"""
Welcome routes.

IMPORTANT: Read `instructions/architecture` before making changes.
"""

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
    """Welcome page showing only running apps (port is listening)."""
    from app.utils.app_manager import test_app_port

    served = AppConfig.get_served_apps()
    apps = [a for a in served if a.get("port") and test_app_port(int(a["port"]))]
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

