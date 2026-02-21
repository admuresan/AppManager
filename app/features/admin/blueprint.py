"""
Admin blueprint and route registration.

IMPORTANT: Read `instructions/architecture` before making changes.
"""

from flask import Blueprint, jsonify
from werkzeug.exceptions import RequestEntityTooLarge

bp = Blueprint("admin", __name__, url_prefix="/blackgrid/admin")


@bp.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(_e):
    """Handle 413 Request Entity Too Large errors."""
    return (
        jsonify(
            {
                "error": (
                    "File too large. Maximum file size is 20MB. "
                    "If you're using nginx, ensure client_max_body_size is set to at least 20m "
                    "in your nginx configuration."
                )
            }
        ),
        413,
    )


# Import route modules for side-effects (decorators attach to bp).
# Terminal routes (terminal_autocomplete, terminal_execute) are disabled - server terminal is off.
from .routes import (  # noqa: E402,F401
    apps_api,
    auth,
    config_api,
    logs,
    pages,
    resources_api,
    traffic_api,
    uploads,
)

