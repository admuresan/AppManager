"""
Proxy routes for forwarding requests to internal apps.

IMPORTANT: Read `instructions/architecture` before making changes.
"""

from __future__ import annotations

import logging
import time
import traceback
from urllib.parse import parse_qs, urlencode

import requests
from flask import Response, current_app, jsonify, render_template, request
from urllib3.exceptions import MaxRetryError, ResponseError

from app.models.app_config import AppConfig
from app.utils.app_manager import start_app_service, test_app_port

from .blueprint import IS_PRODUCTION, MANAGER_PREFIX, bp
from .http_session import _SESSION
from .services.cookies import rewrite_cookie_header, rewrite_set_cookie_header
from .services.script_injection import rewrite_urls_in_content
from .services.trace import bg_trace_enabled, infer_expected_prefixed_url_for_unknown_slug
from .services.urls import get_manager_domain, rewrite_url

logger = logging.getLogger(__name__)


@bp.route("/<app_slug>", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
@bp.route("/<app_slug>/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
def proxy_path(app_slug: str, path: str):
    """
    Proxy requests to an app using its URL-safe name (slug).

    URL structure: {domain_name}/{app_slug}/{path}
    Proxies to: localhost:{port}/{path}
    """
    app_port = None
    app_name = app_slug

    try:
        trace = bg_trace_enabled()
        if trace:
            logger.info(
                "[BG TRACE] proxy.enter input=%s app_slug=%s path=%s qs=%s referer=%s",
                request.full_path,
                app_slug,
                path,
                request.query_string.decode(errors="ignore") if request.query_string else "",
                request.referrer or "",
            )

        if app_slug == MANAGER_PREFIX:
            # Let AppManager's own routes handle /blackgrid/*
            from flask import abort

            abort(404)

        if not IS_PRODUCTION:
            logger.debug(f"Proxy request: app_slug={app_slug}, path={path}, method={request.method}")

        try:
            app_config = AppConfig.get_by_slug(app_slug)
        except Exception as e:
            logger.error(f"Error looking up app by slug '{app_slug}': {str(e)}\n{traceback.format_exc()}")
            try:
                current_app.logger.error(f"Error looking up app by slug '{app_slug}': {str(e)}", exc_info=True)
            except Exception:
                pass
            return f"Error loading app configuration: {str(e)}", 500

        if not app_config:
            expected = infer_expected_prefixed_url_for_unknown_slug(app_slug, path)
            if expected:
                logger.warning(
                    "[BG TRACE] proxy.unknown_app input=%s expected=%s actual=%s reason=%s",
                    request.full_path,
                    expected,
                    request.path,
                    "app_slug not registered (likely missing prefix)",
                )
            else:
                logger.warning(
                    "[BG TRACE] proxy.unknown_app input=%s expected=%s actual=%s reason=%s",
                    request.full_path,
                    None,
                    request.path,
                    "app_slug not registered",
                )
            logger.warning(f"App not found for slug: {app_slug} (path was: {path})")
            return render_template("app_not_found.html"), 404

        if not app_config.get("serve_app", True):
            logger.info(f"App {app_slug} exists but is not set to be served")
            return render_template("app_not_found.html"), 404

        app_port = app_config["port"]
        app_name = app_config["name"]

        # Record app access for usage tracking
        try:
            from app.utils.app_usage_tracker import get_tracker

            tracker = get_tracker(current_app.instance_path)
            tracker.record_access(app_slug)
        except Exception as e:
            logger.warning(f"Error recording app access: {e}")

        is_running = test_app_port(app_port)

        if not is_running:
            service_name = app_config.get("service_name")
            if service_name:
                logger.info(f"App {app_name} is not running, attempting to start service {service_name}")
                success, message = start_app_service(service_name)

                if success:
                    max_wait = 30
                    wait_interval = 0.5
                    waited = 0.0
                    while waited < max_wait:
                        time.sleep(wait_interval)
                        waited += wait_interval
                        if test_app_port(app_port):
                            logger.info(f"App {app_name} started successfully after {waited:.1f}s")
                            break
                    else:
                        logger.warning(f"App {app_name} did not start within {max_wait}s")
                else:
                    logger.warning(f"Failed to start app {app_name}: {message}")

            # If app is still not running and this is a GET request, show loading page
            if not test_app_port(app_port) and request.method == "GET":
                is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest" or (
                    request.accept_mimetypes.best_match(["application/json", "text/html"]) == "application/json"
                )

                if not is_ajax:
                    return render_template("proxy/loading.html", app_name=app_name), 503

                return (
                    jsonify(
                        {
                            "error": "App is starting",
                            "message": f"{app_name} is being brought online. Please try again in a moment.",
                            "retry_after": 2,
                        }
                    ),
                    503,
                )

        target_url = f"http://localhost:{app_port}/{path}"

        # Add query string if present, stripping the processed marker (__bg_rw=1)
        if request.query_string:
            query_string = request.query_string.decode()
            query_params = parse_qs(query_string, keep_blank_values=True)
            if "__bg_rw" in query_params:
                del query_params["__bg_rw"]
            if query_params:
                query_pairs = []
                for key, values in query_params.items():
                    for value in values:
                        query_pairs.append((key, value))
                clean_query = urlencode(query_pairs)
                target_url += f"?{clean_query}"

        if trace:
            expected_public = f"/{app_slug}/{path}" if path else f"/{app_slug}"
            actual_public = request.path
            logger.info(
                "[BG TRACE] proxy.url_map input=%s expected_public=%s actual_public=%s expected_target=%s actual_target=%s",
                request.full_path,
                expected_public,
                actual_public,
                f"http://localhost:{app_port}/{path}",
                target_url,
            )

        manager_domain = get_manager_domain()

        client_ip = request.remote_addr
        if request.headers.get("X-Forwarded-For"):
            forwarded_for = request.headers.get("X-Forwarded-For").split(",")[0].strip()
            if forwarded_for:
                client_ip = forwarded_for
        elif request.headers.get("X-Real-IP"):
            client_ip = request.headers.get("X-Real-IP")

        protocol = "https" if request.is_secure else "http"

        host_header = request.host
        if ":" in host_header:
            public_port = int(host_header.split(":")[1])
        else:
            public_port = 443 if protocol == "https" else 80

        method = request.method
        headers = {}

        excluded_headers = {"host", "x-forwarded-for", "x-real-ip", "x-forwarded-proto", "x-forwarded-host", "x-forwarded-port", "x-forwarded-prefix"}

        for name, value in request.headers:
            name_lower = name.lower()
            if name_lower not in excluded_headers:
                if name_lower == "cookie":
                    value = rewrite_cookie_header(value, app_slug, add_prefix=False)
                headers[name] = value

        headers["Host"] = f"localhost:{app_port}"
        headers["X-Forwarded-For"] = client_ip
        headers["X-Real-IP"] = client_ip
        headers["X-Forwarded-Proto"] = protocol
        headers["X-Forwarded-Host"] = manager_domain
        headers["X-Forwarded-Port"] = str(public_port)
        headers["X-Forwarded-Prefix"] = f"/{app_slug}"

        upgrade_header = request.headers.get("Upgrade", "")
        connection_header = request.headers.get("Connection", "")

        if upgrade_header and upgrade_header.lower() == "websocket":
            headers["Upgrade"] = upgrade_header
            headers["Connection"] = connection_header if connection_header else "upgrade"
        elif connection_header and "upgrade" in connection_header.lower():
            headers["Connection"] = connection_header
            if upgrade_header:
                headers["Upgrade"] = upgrade_header

        data = None
        json_data = None

        content_type = headers.get("Content-Type", "").lower()
        if "application/json" in content_type:
            try:
                json_data = request.get_json(force=True)
                if "application/json" not in headers.get("Content-Type", ""):
                    headers["Content-Type"] = "application/json"
            except Exception:
                data = request.get_data()
        else:
            data = request.get_data()
        if not headers.get("Content-Type") and request.content_type:
            headers["Content-Type"] = request.content_type

        request_kwargs = {
            "method": method,
            "url": target_url,
            "headers": headers,
            "allow_redirects": False,
            "stream": True,
            "timeout": (75, 300),
        }

        if json_data is not None:
            request_kwargs["json"] = json_data
        elif data:
            request_kwargs["data"] = data

        resp = _SESSION.request(**request_kwargs)

        excluded_resp_headers = ["content-encoding", "content-length", "transfer-encoding"]
        is_websocket_upgrade = resp.status_code == 101
        if not is_websocket_upgrade:
            excluded_resp_headers.append("connection")

        response_headers = []

        set_cookie_headers = []
        try:
            if hasattr(resp.raw.headers, "getlist"):
                set_cookie_headers = resp.raw.headers.getlist("Set-Cookie")
            elif hasattr(resp.headers, "getlist"):
                set_cookie_headers = resp.headers.getlist("Set-Cookie")
            else:
                set_cookie = resp.headers.get("Set-Cookie")
                if set_cookie:
                    set_cookie_headers = [set_cookie]
        except Exception as e:
            logger.warning(f"Error reading Set-Cookie headers from {app_name} (port {app_port}): {e}")

        for set_cookie_value in set_cookie_headers:
            rewritten_set_cookie = rewrite_set_cookie_header(set_cookie_value, app_slug)
            response_headers.append(("Set-Cookie", rewritten_set_cookie))

        try:
            raw_headers = resp.raw.headers.items()
        except (AttributeError, Exception) as e:
            logger.warning(f"Error reading raw headers from {app_name} (port {app_port}): {e}")
            try:
                raw_headers = resp.headers.items()
            except Exception as e2:
                logger.error(f"Error reading headers from {app_name} (port {app_port}): {e2}")
                raw_headers = []

        for name, value in raw_headers:
            name_lower = name.lower()
            if name_lower == "set-cookie":
                continue
            if name_lower not in excluded_resp_headers:
                if name_lower == "location" and resp.status_code in (301, 302, 303, 307, 308):
                    value = rewrite_url(value, app_slug, manager_domain)
                response_headers.append((name, value))

        content_type = resp.headers.get("Content-Type", "application/octet-stream")
        is_html = "text/html" in content_type.lower()
        needs_script_injection = is_html

        MAX_INJECT_SIZE = 16 * 1024 * 1024
        content_length = resp.headers.get("Content-Length")
        should_inject_script = needs_script_injection and (content_length is None or int(content_length) <= MAX_INJECT_SIZE)

        if should_inject_script:
            try:
                content = resp.content
                if len(content) > MAX_INJECT_SIZE:
                    def generate():
                        yield content

                    return Response(generate(), status=resp.status_code, headers=response_headers, mimetype=content_type)

                content = rewrite_urls_in_content(content, app_slug, manager_domain, content_type)
                return Response(content, status=resp.status_code, headers=response_headers, mimetype=content_type)
            except Exception as e:
                logger.error(f"Error injecting script for {app_name}: {e}")

        def generate():
            try:
                for chunk in resp.iter_content(chunk_size=8192):
                    if chunk:
                        yield chunk
            except Exception as e:
                logger.error(f"Error streaming content from {app_name} (port {app_port}): {e}")
                yield b"Error streaming content"

        return Response(generate(), status=resp.status_code, headers=response_headers, mimetype=content_type)

    except requests.exceptions.ConnectionError as e:
        logger.error(f"Connection error proxying to {app_name} (port {app_port}): {e}")
        port_msg = f" on port {app_port}" if app_port else ""
        return f"App{port_msg} is not responding. Please check if the app is running.", 503
    except requests.exceptions.Timeout as e:
        logger.error(f"Timeout error proxying to {app_name} (port {app_port}): {e}")
        return "Request to app timed out.", 504
    except (ResponseError, MaxRetryError) as e:
        logger.error(f"Retry error proxying to {app_name} (port {app_port}): {e}")
        port_msg = f" on port {app_port}" if app_port else ""
        return f"Error proxying request: {str(e)}. The app{port_msg} may be returning errors.", 502
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error proxying to {app_name} (port {app_port}): {e}")
        return f"Error proxying request: {str(e)}", 502
    except Exception as e:
        error_trace = traceback.format_exc()
        logger.error(f"Unexpected error in proxy route for {app_slug} (path: {path}): {e}\n{error_trace}")
        return f"Internal proxy error: {str(e)}. Check server logs for details.", 500


@bp.route("/<app_slug>/__heartbeat__", methods=["GET", "POST"])
def heartbeat(app_slug: str):
    """Heartbeat endpoint to keep apps alive when browser tabs are open."""
    try:
        import uuid

        session_id = request.cookies.get("__app_session_id")
        if not session_id:
            session_id = str(uuid.uuid4())

        try:
            from app.utils.app_usage_tracker import get_tracker

            tracker = get_tracker(current_app.instance_path)
            tracker.register_active_tab(app_slug, session_id)
        except Exception as e:
            logger.warning(f"Error recording heartbeat: {e}")

        response = jsonify({"status": "ok", "session_id": session_id})
        response.set_cookie("__app_session_id", session_id, max_age=3600 * 24)
        return response
    except Exception as e:
        logger.error(f"Error in heartbeat endpoint: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

