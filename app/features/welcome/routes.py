"""
Welcome routes.

IMPORTANT: Read `instructions/architecture` before making changes.
"""

import os
from pathlib import Path

from flask import abort, current_app, redirect, render_template, request, send_from_directory, url_for

from app.models.app_config import AppConfig

from .blueprint import bp


# Image extensions accepted for logo.* in app folders
LOGO_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico"}


def _get_app_root_path(app: dict) -> Path | None:
    """Resolve the app's folder path (app root). Prefer windows_path on Windows if set."""
    folder = app.get("windows_path") if os.name == "nt" else app.get("folder_path")
    if not folder:
        folder = app.get("folder_path") or app.get("windows_path")
    if not folder:
        return None
    path = Path(folder).resolve()
    return path if path.exists() and path.is_dir() else None


def _get_folder_logo_path(root: Path | None) -> Path | None:
    """Return path to logo file in folder (logo.* with image extension), or None."""
    if root is None or not root.is_dir():
        return None
    for f in root.iterdir():
        if f.is_file() and f.stem.lower() == "logo" and f.suffix.lower() in LOGO_IMAGE_EXTENSIONS:
            return f
    return None


def _app_has_folder_logo(app: dict) -> bool:
    """Return True if the app has a logo.* image in its folder (app root)."""
    root = _get_app_root_path(app)
    return _get_folder_logo_path(root) is not None


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

    # Enrich each app with slug, has_logo, and logo_url (uploaded or from app folder logo.*)
    for app in apps:
        app["slug"] = AppConfig.get_effective_slug(app)
        has_uploaded = bool(app.get("logo"))
        has_folder_logo = _app_has_folder_logo(app)
        app["has_logo"] = has_uploaded or has_folder_logo
        if has_uploaded:
            logo_fn = app["logo"].replace("uploads/", "", 1) if app["logo"].startswith("uploads/") else app["logo"]
            app["logo_url"] = url_for("admin.uploaded_file", filename=logo_fn)
        elif has_folder_logo:
            app["logo_url"] = url_for("welcome.app_icon", app_slug=app["slug"])
        else:
            app["logo_url"] = None

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
    Serve the app logo for a given app slug: uploaded logo, or logo.* from app folder.
    Used for per-app favicons and for app cards on the welcome page.
    """
    try:
        app_config = AppConfig.get_by_slug(app_slug)
        if not app_config or not app_config.get("serve_app", True):
            abort(404)

        instance_path = Path(current_app.instance_path)
        logo_path = app_config.get("logo")

        # 1) Uploaded logo from instance/uploads
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

        # 2) logo.* in app folder (any image type: logo.png, logo.svg, etc.)
        app_root = _get_app_root_path(app_config)
        if app_root is not None:
            folder_logo = _get_folder_logo_path(app_root)
            if folder_logo is not None:
                resp = send_from_directory(str(folder_logo.parent), folder_logo.name)
                ext = folder_logo.suffix.lower()
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
                else:
                    resp.headers["Content-Type"] = "image/png"
                resp.headers["Cache-Control"] = "no-cache"
                return resp

        abort(404)
    except Exception:
        abort(404)

