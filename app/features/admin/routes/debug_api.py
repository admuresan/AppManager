"""
Admin debug API routes.

IMPORTANT: Read `instructions/architecture` before making changes.
"""

import requests
from flask import jsonify
from flask_login import login_required

from app.models.app_config import AppConfig

from ..blueprint import bp


@bp.route("/api/debug/proxy-test/<app_slug>")
@login_required
def debug_proxy_test(app_slug):
    """Debug endpoint to test proxy connection and see detailed error information."""
    app_config = AppConfig.get_by_slug(app_slug)
    if not app_config:
        return jsonify({"error": "App not found"}), 404

    app_port = app_config["port"]
    app_name = app_config["name"]

    results = {"app_name": app_name, "app_port": app_port, "app_slug": app_slug, "direct_test": None, "proxy_test": None}

    try:
        resp = requests.get(f"http://localhost:{app_port}/", timeout=5, allow_redirects=True)
        results["direct_test"] = {"status": resp.status_code, "headers": dict(resp.headers), "content_preview": resp.text[:500] if resp.text else None}
    except Exception as e:
        results["direct_test"] = {"error": str(e)}

    try:
        headers = {"Host": f"localhost:{app_port}", "X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1", "X-Forwarded-Proto": "http"}
        resp = requests.get(f"http://localhost:{app_port}/", headers=headers, timeout=5, allow_redirects=True)
        results["proxy_test"] = {"status": resp.status_code, "headers": dict(resp.headers), "content_preview": resp.text[:500] if resp.text else None}
    except Exception as e:
        results["proxy_test"] = {"error": str(e)}

    return jsonify(results)

