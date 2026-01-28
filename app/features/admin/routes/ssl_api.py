"""
Admin SSL-related API routes.

IMPORTANT: Read `instructions/architecture` before making changes.
"""

import platform
import subprocess

from flask import current_app, jsonify, request
from flask_login import login_required

from app.models.app_config import AppConfig
from app.utils.ssl_manager import (
    _check_file_exists,
    get_certificate_status_for_all_apps,
    get_main_ssl_certificate,
    is_certificate_trusted,
    setup_letsencrypt_certificate,
    setup_ssl_for_app_port,
    regenerate_main_certificate,
)

from ..blueprint import bp


@bp.route("/api/apps/<app_id>/fix-ssl", methods=["POST"])
@login_required
def fix_app_ssl(app_id):
    """Fix SSL certificate and nginx configuration for an app."""
    app_config = AppConfig.get_by_id(app_id)
    if not app_config:
        return jsonify({"error": "App not found"}), 404

    port = app_config["port"]
    server_address = current_app.config.get("SERVER_ADDRESS", "localhost")
    server_domain = current_app.config.get("SERVER_DOMAIN", "blackgrid.ddns.net")

    # Check if main Let's Encrypt certificate exists, if not, try to set it up
    try:
        cert_file, key_file = get_main_ssl_certificate()
        cert_exists = _check_file_exists(cert_file) and _check_file_exists(key_file)
    except FileNotFoundError:
        cert_exists = False

    if not cert_exists:
        setup_success, setup_message = setup_letsencrypt_certificate(server_domain)
        if not setup_success:
            return (
                jsonify(
                    {
                        "error": f"Let's Encrypt certificate not found and could not be set up automatically. {setup_message}",
                        "suggestion": (
                            "Please set up Let's Encrypt manually by running on the server: "
                            f"sudo certbot certonly --standalone -d {server_domain} --non-interactive "
                            "--agree-tos --register-unsafely-without-email"
                        ),
                    }
                ),
                500,
            )

        try:
            cert_file, key_file = get_main_ssl_certificate()
            cert_exists = _check_file_exists(cert_file) and _check_file_exists(key_file)
        except FileNotFoundError:
            return (
                jsonify(
                    {
                        "error": "Let's Encrypt certificate setup reported success but certificate files not found. Please check certbot logs.",
                        "suggestion": (
                            "Try running manually: "
                            f"sudo certbot certonly --standalone -d {server_domain} --non-interactive "
                            "--agree-tos --register-unsafely-without-email"
                        ),
                    }
                ),
                500,
            )

    # Remove existing nginx config to force recreation
    if platform.system() == "Linux":
        site_name = f"app-port-{port}"
        try:
            subprocess.run(["sudo", "rm", "-f", f"/etc/nginx/sites-enabled/{site_name}"], timeout=5, check=False)
            subprocess.run(["sudo", "rm", "-f", f"/etc/nginx/sites-available/{site_name}"], timeout=5, check=False)
        except Exception:
            pass

    ssl_success, ssl_message = setup_ssl_for_app_port(port, server_address, server_domain)

    if not ssl_success:
        return jsonify({"error": f"Failed to fix SSL: {ssl_message}"}), 500

    cert_file, _key_file = get_main_ssl_certificate()
    cert_exists = _check_file_exists(cert_file)
    cert_trusted = is_certificate_trusted(cert_file) if cert_exists else False

    certificate_info = {"type": "Let's Encrypt" if cert_trusted else "Not trusted", "trusted": cert_trusted, "cert_path": cert_file}

    https_port = port + 10000
    message = f"SSL certificate and nginx configuration recreated for port {port}. HTTPS available on port {https_port}."

    if cert_trusted:
        message += " Using trusted Let's Encrypt certificate - browsers will trust it."
    else:
        message += " Certificate is not trusted. Please set up Let's Encrypt for trusted certificates."

    return jsonify({"success": True, "message": message, "certificate_info": certificate_info, "https_port": https_port})


@bp.route("/api/ssl/setup-letsencrypt", methods=["POST"])
@login_required
def setup_letsencrypt():
    """Set up Let's Encrypt certificate for the domain."""
    server_domain = current_app.config.get("SERVER_DOMAIN", "blackgrid.ddns.net")
    email = request.form.get("email", None)

    success, message = setup_letsencrypt_certificate(server_domain, email)

    if success:
        return jsonify({"success": True, "message": message})
    return jsonify({"error": message}), 500


@bp.route("/api/ssl/regenerate-cert", methods=["POST"])
@login_required
def regenerate_cert():
    """Set up or renew Let's Encrypt certificate for the main domain."""
    server_address = current_app.config.get("SERVER_ADDRESS", "localhost")
    server_domain = current_app.config.get("SERVER_DOMAIN", "blackgrid.ddns.net")

    success, message = regenerate_main_certificate(server_address, server_domain)

    if success:
        from app.utils.ssl_manager import update_all_app_nginx_configs_with_new_certificate

        updated_count, total_count = update_all_app_nginx_configs_with_new_certificate()
        message += f" Updated {updated_count} of {total_count} child app configs."

        return jsonify({"success": True, "message": message})
    return jsonify({"error": message}), 500


@bp.route("/api/ssl/status", methods=["GET"])
@login_required
def get_ssl_status():
    """Get SSL certificate status for all apps."""
    status = get_certificate_status_for_all_apps()
    return jsonify(status)

