"""
Reverse proxy routes for forwarding requests to internal apps

This proxy implementation is designed to work with applications using ProxyFix middleware
(e.g., Flask/Werkzeug). It sets all required X-Forwarded-* headers so that proxied apps
can generate correct URLs based on the public-facing domain and protocol.

Note: WebSocket support is limited. The requests library handles HTTP upgrade requests,
but full bidirectional WebSocket connections may require additional implementation.
For most use cases, the header passthrough should be sufficient for WebSocket upgrades.
"""
from flask import Blueprint, request, Response, current_app, render_template_string, jsonify
import requests
import os
import re
import time
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import ResponseError, MaxRetryError
from app.models.app_config import AppConfig
import logging
import traceback

bp = Blueprint('proxy', __name__)

# Special prefix for AppManager routes - should never be proxied
MANAGER_PREFIX = 'blackgrid'

# Configure logging for proxy route
logger = logging.getLogger(__name__)

# Check if we're in production (reduce debug logging for performance)
IS_PRODUCTION = os.environ.get('FLASK_ENV') == 'production' or os.environ.get('FLASK_DEBUG') == '0'

# Create a session with connection pooling for better performance
_session = requests.Session()

# Configure retry strategy
retry_strategy = Retry(
    total=1,
    backoff_factor=0.1,
    status_forcelist=[502, 503, 504],
)

# Mount adapter with connection pooling and increased timeouts for WebSocket/long-polling
adapter = HTTPAdapter(
    pool_connections=10,
    pool_maxsize=20,
    max_retries=retry_strategy
)
_session.mount("http://", adapter)
_session.mount("https://", adapter)


def get_manager_domain():
    """Get the manager domain name from config"""
    try:
        from flask import current_app
        if current_app and hasattr(current_app, 'config'):
            domain = current_app.config.get('SERVER_DOMAIN', 'blackgrid.ddns.net')
            if domain:
                return domain
    except:
        pass
    return 'blackgrid.ddns.net'


def _url_has_app_prefix(url_path, app_slug):
    """
    Check if a URL path already has the app prefix by parsing the path structure.
    This is more robust than string matching as it actually parses the URL.
    
    Args:
        url_path: URL path (e.g., '/quizia/static/css/style.css' or '/static/css/style.css')
        app_slug: App slug to check for (e.g., 'quizia')
    
    Returns:
        True if the first path segment matches app_slug, False otherwise
    """
    if not url_path or not url_path.startswith('/'):
        return False
    
    # Split path into segments, removing empty strings
    path_segments = [seg for seg in url_path.split('/') if seg]
    
    # Check if first segment matches app_slug
    if path_segments and path_segments[0] == app_slug:
        return True
    
    return False


def _prefix_cookie_name(cookie_name, app_slug):
    """
    Add app prefix to cookie name for isolation.
    
    Args:
        cookie_name: Original cookie name
        app_slug: App slug to use as prefix
    
    Returns:
        Prefixed cookie name (e.g., 'investment-calculator_myCookie')
    """
    prefix = f'{app_slug}_'
    if cookie_name.startswith(prefix):
        # Already prefixed
        return cookie_name
    return prefix + cookie_name


def _unprefix_cookie_name(cookie_name, app_slug):
    """
    Remove app prefix from cookie name.
    
    Args:
        cookie_name: Prefixed cookie name
        app_slug: App slug that was used as prefix
    
    Returns:
        Original cookie name without prefix
    """
    prefix = f'{app_slug}_'
    if cookie_name.startswith(prefix):
        return cookie_name[len(prefix):]
    return cookie_name


def _rewrite_cookie_header(cookie_header, app_slug, add_prefix=True):
    """
    Rewrite cookie header to add or remove app prefix from cookie names.
    
    Args:
        cookie_header: Cookie header value (e.g., "name1=value1; name2=value2")
        app_slug: App slug for prefix
        add_prefix: If True, add prefix. If False, remove prefix.
    
    Returns:
        Rewritten cookie header string
    """
    if not cookie_header:
        return cookie_header
    
    cookies = []
    for cookie_pair in cookie_header.split(';'):
        cookie_pair = cookie_pair.strip()
        if '=' in cookie_pair:
            name, value = cookie_pair.split('=', 1)
            name = name.strip()
            value = value.strip()
            
            if add_prefix:
                # Add prefix to cookie name
                name = _prefix_cookie_name(name, app_slug)
            else:
                # Remove prefix from cookie name (only if it has our prefix)
                name = _unprefix_cookie_name(name, app_slug)
            
            cookies.append(f'{name}={value}')
        else:
            # Cookie without value (shouldn't happen, but handle it)
            cookies.append(cookie_pair)
    
    return '; '.join(cookies)


def _rewrite_set_cookie_header(set_cookie_value, app_slug):
    """
    Rewrite Set-Cookie header to add app prefix to cookie name.
    
    Args:
        set_cookie_value: Set-Cookie header value (e.g., "name=value; Path=/; Domain=example.com")
        app_slug: App slug for prefix
    
    Returns:
        Rewritten Set-Cookie header value with prefixed cookie name
    """
    if not set_cookie_value:
        return set_cookie_value
    
    # Parse Set-Cookie header: "name=value; attribute1=value1; attribute2"
    parts = [p.strip() for p in set_cookie_value.split(';')]
    if not parts:
        return set_cookie_value
    
    # First part is name=value
    name_value = parts[0]
    if '=' not in name_value:
        return set_cookie_value
    
    name, value = name_value.split('=', 1)
    name = name.strip()
    value = value.strip()
    
    # Add prefix to cookie name
    prefixed_name = _prefix_cookie_name(name, app_slug)
    
    # Reconstruct Set-Cookie header with prefixed name
    result = f'{prefixed_name}={value}'
    if len(parts) > 1:
        result += '; ' + '; '.join(parts[1:])
    
    return result


def rewrite_url(url, app_slug, manager_domain):
    """
    Rewrite URL to include /app_slug/ prefix (f function).
    Golden rule: f(x) prepends /app_slug/ so that g(f(x)) = x where g removes the prefix.
    
    This function intelligently detects if a URL already has the prefix by parsing
    the URL structure rather than relying on string matching.
    
    Args:
        url: URL string to rewrite
        app_slug: App slug to prepend
        manager_domain: Manager domain name
    
    Returns:
        Rewritten URL string
    """
    if not url or not isinstance(url, str):
        return url
    
    # Skip special URL schemes
    if url.startswith(('data:', 'javascript:', 'mailto:', 'tel:', '#')):
        return url
    
    # Skip protocol-relative URLs (external CDNs)
    if url.startswith('//'):
        return url
    
    # Handle absolute URLs
    if url.startswith('http://') or url.startswith('https://'):
        try:
            parsed = urlparse(url)
            # Rewrite localhost:port URLs to domain/app_slug/path
            if parsed.netloc.startswith('localhost:') or parsed.netloc.startswith('127.0.0.1:'):
                # Extract port if present
                host_parts = parsed.netloc.split(':')
                if len(host_parts) == 2:
                    port = host_parts[1]
                else:
                    port = None
                
                # Build new URL with domain and app_slug prefix
                protocol = 'https' if url.startswith('https://') else 'http'
                path = parsed.path if parsed.path else '/'
                if not path.startswith('/'):
                    path = '/' + path
                
                # Check if path already has app prefix by parsing structure
                if not _url_has_app_prefix(path, app_slug):
                    new_path = f'/{app_slug}{path}'
                else:
                    # Already has prefix, use as-is
                    new_path = path
                
                new_url = f'{protocol}://{manager_domain}{new_path}'
                
                # Preserve query string and fragment
                if parsed.query:
                    new_url += f'?{parsed.query}'
                if parsed.fragment:
                    new_url += f'#{parsed.fragment}'
                
                return new_url
            else:
                # External domain - don't rewrite
                return url
        except Exception:
            # If parsing fails, return original
            return url
    
    # Handle relative URLs (starting with /)
    if url.startswith('/'):
        # Parse the URL path to check if it already has the app prefix
        # This is more robust than string matching
        if _url_has_app_prefix(url, app_slug):
            # URL already has the app prefix (app generated it with prefix)
            # Return as-is to avoid double-prefixing
            return url
        # URL doesn't have prefix, add it
        return f'/{app_slug}{url}'
    
    # Relative URLs without leading slash (like "dashboard" or "../parent")
    # These are relative to current path, prepend app_slug
    return f'/{app_slug}/{url}' if not url.startswith('/') else f'/{app_slug}{url}'


def rewrite_urls_in_content(content, app_slug, manager_domain, content_type=''):
    """
    Inject client-side URL rewriting script for JavaScript-generated URLs.
    
    IMPORTANT: We do NOT rewrite URLs in HTML/CSS content because:
    1. If the app uses ProxyFix correctly, it already generates URLs with the prefix
    2. Server-side rewriting would double-prefix URLs that already have the prefix
    3. Client-side JavaScript handles dynamic URLs created at runtime
    
    Args:
        content: Content bytes or string
        app_slug: App slug to prepend to URLs
        manager_domain: Manager domain name (unused but kept for compatibility)
        content_type: Content type (to determine if we should inject script)
    
    Returns:
        Content as bytes with client-side rewriting script injected (if HTML)
    """
    if not content:
        return content
    
    # Convert to string if bytes
    try:
        if isinstance(content, bytes):
            content_str = content.decode('utf-8', errors='ignore')
        else:
            content_str = str(content)
    except:
        return content
    
    is_html = 'text/html' in content_type.lower()
    
    # Only inject script for HTML content
    # CSS and JavaScript files are passed through unchanged
    # URLs in HTML attributes (href, src, etc.) should already be correct from ProxyFix
    if not is_html:
        return content if isinstance(content, bytes) else content_str.encode('utf-8')
    
    # NOTE: We no longer rewrite HTML/CSS URLs server-side because:
    # - Apps using ProxyFix already generate correct URLs with prefix
    # - Server-side rewriting would cause double-prefixing
    # - Client-side JavaScript handles dynamic URLs created at runtime
    
    # Inject client-side script for dynamic JavaScript URLs only
    if is_html and '<head' in content_str.lower():
        # Load and render the rewrite script template
        try:
            # Use Flask's template loader to get the template source
            template = current_app.jinja_env.get_template('proxy_rewrite_script.html')
            rewrite_script = template.render(app_slug=app_slug)
        except Exception as e:
            logger.error(f"Error loading rewrite script template: {e}")
            # Fallback: return content without script injection
            return content_str.encode('utf-8')
        
        # Insert script after <head> tag
        # IMPORTANT: Check if script is already present to prevent double-injection
        if '__APP_MANAGER_REWRITE_LOADED' not in content_str:
            head_pattern = re.compile(r'(<head[^>]*>)', re.IGNORECASE)
            if head_pattern.search(content_str):
                content_str = head_pattern.sub(rf'\1\n{rewrite_script}', content_str, count=1)
            else:
                html_pattern = re.compile(r'(<html[^>]*>)', re.IGNORECASE)
                if html_pattern.search(content_str):
                    content_str = html_pattern.sub(rf'\1\n  <head>{rewrite_script}</head>', content_str, count=1)
    
    return content_str.encode('utf-8')


@bp.route('/<app_slug>', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
@bp.route('/<app_slug>/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
def proxy_path(app_slug, path):
    """
    Proxy requests to an app using its URL-safe name (slug).
    
    URL structure: {domain_name}/{app_slug}/{path}
    Proxies to: localhost:{port}/{path}
    
    Special case: /blackgrid/ routes are NOT proxied (handled by AppManager routes)
    """
    app_port = None
    app_name = app_slug
    
    try:
        # Special case: /blackgrid/ is AppManager, don't proxy
        if app_slug == MANAGER_PREFIX:
            from flask import abort
            abort(404)  # Let AppManager routes handle it
        
        if not IS_PRODUCTION:
            logger.debug(f"Proxy request: app_slug={app_slug}, path={path}, method={request.method}")
        
        try:
            app_config = AppConfig.get_by_slug(app_slug)
        except Exception as e:
            logger.error(f"Error looking up app by slug '{app_slug}': {str(e)}\n{traceback.format_exc()}")
            try:
                current_app.logger.error(f"Error looking up app by slug '{app_slug}': {str(e)}", exc_info=True)
            except:
                pass
            return f"Error loading app configuration: {str(e)}", 500
        
        if not app_config:
            logger.warning(f"App not found for slug: {app_slug} (path was: {path})")
            from flask import render_template
            return render_template('app_not_found.html'), 404
        
        if not app_config.get('serve_app', True):
            logger.info(f"App {app_slug} exists but is not set to be served")
            from flask import render_template
            return render_template('app_not_found.html'), 404
        
        app_port = app_config['port']
        app_name = app_config['name']
        
        # Record app access for usage tracking
        try:
            from app.utils.app_usage_tracker import get_tracker
            tracker = get_tracker(current_app.instance_path)
            tracker.record_access(app_slug)
        except Exception as e:
            logger.warning(f"Error recording app access: {e}")
        
        # Check if app is running, if not start it
        from app.utils.app_manager import test_app_port, start_app_service
        is_running = test_app_port(app_port)
        
        if not is_running:
            # App is not running, try to start it
            service_name = app_config.get('service_name')
            if service_name:
                logger.info(f"App {app_name} is not running, attempting to start service {service_name}")
                success, message = start_app_service(service_name)
                
                if success:
                    # Wait for app to start (poll up to 30 seconds)
                    max_wait = 30
                    wait_interval = 0.5
                    waited = 0
                    while waited < max_wait:
                        time.sleep(wait_interval)
                        waited += wait_interval
                        if test_app_port(app_port):
                            logger.info(f"App {app_name} started successfully after {waited:.1f}s")
                            break
                    else:
                        # App didn't start in time
                        logger.warning(f"App {app_name} did not start within {max_wait}s")
                        # Continue anyway - might be starting slowly
                else:
                    logger.warning(f"Failed to start app {app_name}: {message}")
                    # Continue anyway - might already be starting or service name might be wrong
            
            # If app is still not running and this is a GET request, show loading page
            if not test_app_port(app_port) and request.method == 'GET':
                # Check if this is an AJAX request
                is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or \
                         request.accept_mimetypes.best_match(['application/json', 'text/html']) == 'application/json'
                
                if not is_ajax:
                    # Show loading page for regular browser requests
                    from flask import render_template_string
                    loading_html = """
<!DOCTYPE html>
<html>
<head>
    <title>Starting {{ app_name }}...</title>
    <meta http-equiv="refresh" content="2">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .container {
            text-align: center;
            padding: 40px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 20px;
            backdrop-filter: blur(10px);
        }
        h1 {
            margin: 0 0 20px 0;
            font-size: 2em;
        }
        .spinner {
            border: 4px solid rgba(255, 255, 255, 0.3);
            border-top: 4px solid white;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        p {
            margin: 10px 0;
            opacity: 0.9;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Starting {{ app_name }}...</h1>
        <div class="spinner"></div>
        <p>Please wait while we bring the app online.</p>
        <p style="font-size: 0.9em; opacity: 0.7;">This page will refresh automatically.</p>
    </div>
</body>
</html>
                    """
                    return render_template_string(loading_html, app_name=app_name), 503
                else:
                    # Return JSON for AJAX requests
                    return jsonify({
                        'error': 'App is starting',
                        'message': f'{app_name} is being brought online. Please try again in a moment.',
                        'retry_after': 2
                    }), 503
        
        # Build target URL - proxy to localhost:{port}/{path}
        target_url = f"http://localhost:{app_port}/{path}"
        
        # Add query string if present, stripping the processed marker (__bg_rw=1)
        if request.query_string:
            query_string = request.query_string.decode()
            # Parse query string and remove the marker
            query_params = parse_qs(query_string, keep_blank_values=True)
            # Remove the processed marker if present
            if '__bg_rw' in query_params:
                del query_params['__bg_rw']
            # Reconstruct query string without the marker
            if query_params:
                # Convert parse_qs format (list values) back to query string
                # parse_qs returns lists, but we need to handle single values
                query_pairs = []
                for key, values in query_params.items():
                    for value in values:
                        query_pairs.append((key, value))
                clean_query = urlencode(query_pairs)
                target_url += f"?{clean_query}"
        
        # Get manager domain for headers
        manager_domain = get_manager_domain()
        
        # Get client IP address (handle proxy chains)
        client_ip = request.remote_addr
        if request.headers.get('X-Forwarded-For'):
            # X-Forwarded-For can contain multiple IPs, take the first (original client)
            forwarded_for = request.headers.get('X-Forwarded-For').split(',')[0].strip()
            if forwarded_for:
                client_ip = forwarded_for
        elif request.headers.get('X-Real-IP'):
            client_ip = request.headers.get('X-Real-IP')
        
        # Determine protocol (http or https)
        # Check if request is secure (HTTPS) - Flask's ProxyFix middleware handles this
        protocol = 'https' if request.is_secure else 'http'
        
        # Determine public-facing port
        # Check if we have a port in the Host header or use standard ports
        host_header = request.host
        if ':' in host_header:
            public_port = int(host_header.split(':')[1])
        else:
            # Use standard ports based on protocol
            public_port = 443 if protocol == 'https' else 80
        
        # Forward the request with ProxyFix-compatible headers
        method = request.method
        headers = {}
        
        # Copy relevant headers from original request (excluding ones we'll set explicitly)
        excluded_headers = {
            'host', 'x-forwarded-for', 'x-real-ip', 'x-forwarded-proto', 
            'x-forwarded-host', 'x-forwarded-port', 'x-forwarded-prefix'
        }
        
        for name, value in request.headers:
            name_lower = name.lower()
            if name_lower not in excluded_headers:
                # Handle Cookie header: strip app prefix before forwarding to app
                if name_lower == 'cookie':
                    # Rewrite cookie header to remove prefix (app sees cookies without prefix)
                    value = _rewrite_cookie_header(value, app_slug, add_prefix=False)
                headers[name] = value
        
        # Set Host header to localhost:port (required for proxying to internal app)
        # Note: The Host header must be localhost:port for the internal proxy request to work.
        # The public domain is communicated via X-Forwarded-Host header below.
        headers['Host'] = f'localhost:{app_port}'
        
        # Set X-Forwarded-* headers for ProxyFix middleware
        # These tell the proxied app about the original client and public-facing setup
        # ProxyFix middleware will use these headers to generate correct URLs
        headers['X-Forwarded-For'] = client_ip
        headers['X-Real-IP'] = client_ip
        headers['X-Forwarded-Proto'] = protocol
        headers['X-Forwarded-Host'] = manager_domain  # Public domain name (not localhost)
        headers['X-Forwarded-Port'] = str(public_port)  # Public-facing port (usually 80 or 443)
        headers['X-Forwarded-Prefix'] = f'/{app_slug}'  # URL prefix for the app
        
        # Handle WebSocket upgrades
        # Pass through Upgrade and Connection headers if present
        upgrade_header = request.headers.get('Upgrade', '')
        connection_header = request.headers.get('Connection', '')
        
        if upgrade_header and upgrade_header.lower() == 'websocket':
            headers['Upgrade'] = upgrade_header
            # Connection header should be 'upgrade' or 'Upgrade' for WebSocket
            if connection_header:
                headers['Connection'] = connection_header
            else:
                # Set default Connection header for WebSocket if not provided
                headers['Connection'] = 'upgrade'
        elif connection_header and 'upgrade' in connection_header.lower():
            # Also pass through Connection: upgrade even if Upgrade header isn't websocket
            # (some clients may use different upgrade protocols)
            headers['Connection'] = connection_header
            if upgrade_header:
                headers['Upgrade'] = upgrade_header
        
        # Forward request data
        data = None
        json_data = None
        
        content_type = headers.get('Content-Type', '').lower()
        if 'application/json' in content_type:
            try:
                json_data = request.get_json(force=True)
                if 'application/json' not in headers.get('Content-Type', ''):
                    headers['Content-Type'] = 'application/json'
            except Exception:
                data = request.get_data()
        else:
            data = request.get_data()
        if not headers.get('Content-Type') and request.content_type:
            headers['Content-Type'] = request.content_type
        
        # Make request to internal app
        # Note: params are already in target_url query string, don't pass separately
        # Use increased timeouts for WebSocket and long-polling support
        request_kwargs = {
            'method': method,
            'url': target_url,  # Already includes query string
            'headers': headers,
            'allow_redirects': False,
            'stream': True,
            'timeout': (75, 300)  # (connect_timeout, read_timeout) - 75s connect, 300s read for long-polling/WebSocket
        }
        
        if json_data is not None:
            request_kwargs['json'] = json_data
        elif data:
            request_kwargs['data'] = data
        
        resp = _session.request(**request_kwargs)
        
        # Build response headers - rewrite Location headers for redirects
        # Exclude headers that should be handled by the proxy, not passed through
        # Note: Connection header is excluded except for WebSocket upgrades (101 status)
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding']
        
        # For WebSocket upgrades (101 Switching Protocols), we need to pass through Connection and Upgrade headers
        is_websocket_upgrade = resp.status_code == 101
        
        if not is_websocket_upgrade:
            # Exclude Connection header for non-WebSocket responses (let Flask handle it)
            excluded_headers.append('connection')
        
        response_headers = []
        
        # Handle Set-Cookie headers separately to support multiple Set-Cookie headers
        set_cookie_headers = []
        try:
            # Try to get all Set-Cookie headers using getlist (supports multiple values)
            if hasattr(resp.raw.headers, 'getlist'):
                set_cookie_headers = resp.raw.headers.getlist('Set-Cookie')
            elif hasattr(resp.headers, 'getlist'):
                set_cookie_headers = resp.headers.getlist('Set-Cookie')
            else:
                # Fallback: try to get single Set-Cookie header
                set_cookie = resp.headers.get('Set-Cookie')
                if set_cookie:
                    set_cookie_headers = [set_cookie]
        except Exception as e:
            logger.warning(f"Error reading Set-Cookie headers from {app_name} (port {app_port}): {e}")
        
        # Process Set-Cookie headers with prefix
        for set_cookie_value in set_cookie_headers:
            rewritten_set_cookie = _rewrite_set_cookie_header(set_cookie_value, app_slug)
            response_headers.append(('Set-Cookie', rewritten_set_cookie))
        
        # Process other headers
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
            # Skip Set-Cookie as we already processed it above
            if name_lower == 'set-cookie':
                continue
            if name_lower not in excluded_headers:
                # Rewrite Location header for redirects
                if name_lower == 'location' and resp.status_code in (301, 302, 303, 307, 308):
                    value = rewrite_url(value, app_slug, manager_domain)
                
                response_headers.append((name, value))
        
        # Check if content needs client-side script injection
        # IMPORTANT: We do NOT rewrite HTML/CSS URLs server-side because:
        # - Apps using ProxyFix already generate correct URLs with prefix
        # - Server-side rewriting would cause double-prefixing
        # - We only inject client-side JavaScript for dynamic URLs created at runtime
        content_type = resp.headers.get('Content-Type', 'application/octet-stream')
        is_html = 'text/html' in content_type.lower()
        
        # Only inject script for HTML content (for dynamic JavaScript URLs)
        # CSS and JavaScript files pass through unchanged
        needs_script_injection = is_html
        
        # Check content length - only inject script if reasonable size
        MAX_INJECT_SIZE = 16 * 1024 * 1024  # 16MB
        content_length = resp.headers.get('Content-Length')
        should_inject_script = needs_script_injection and (
            content_length is None or int(content_length) <= MAX_INJECT_SIZE
        )
        
        if should_inject_script:
            # Capture full content and inject client-side rewriting script
            try:
                content = resp.content
                
                # Double-check size
                if len(content) > MAX_INJECT_SIZE:
                    # Too large, stream as-is
                    def generate():
                        yield content
                    return Response(
                        generate(),
                        status=resp.status_code,
                        headers=response_headers,
                        mimetype=content_type
                    )
                
                # Inject client-side script for dynamic URLs (no server-side rewriting)
                content = rewrite_urls_in_content(content, app_slug, manager_domain, content_type)
                
                return Response(
                    content,
                    status=resp.status_code,
                    headers=response_headers,
                    mimetype=content_type
                )
            except Exception as e:
                logger.error(f"Error injecting script for {app_name}: {e}")
                # Fall through to streaming
                pass
        
        # Stream response content directly (for binary files or large content)
        def generate():
            try:
                for chunk in resp.iter_content(chunk_size=8192):
                    if chunk:
                        yield chunk
            except Exception as e:
                logger.error(f"Error streaming content from {app_name} (port {app_port}): {e}")
                yield b'Error streaming content'
        
        return Response(
            generate(),
            status=resp.status_code,
            headers=response_headers,
            mimetype=content_type
        )
    
    except requests.exceptions.ConnectionError as e:
        error_msg = f"Connection error proxying to {app_name} (port {app_port}): {e}"
        logger.error(error_msg)
        port_msg = f" on port {app_port}" if app_port else ""
        return f"App{port_msg} is not responding. Please check if the app is running.", 503
    except requests.exceptions.Timeout as e:
        error_msg = f"Timeout error proxying to {app_name} (port {app_port}): {e}"
        logger.error(error_msg)
        return "Request to app timed out.", 504
    except (ResponseError, MaxRetryError) as e:
        error_msg = f"Retry error proxying to {app_name} (port {app_port}): {e}"
        logger.error(error_msg)
        port_msg = f" on port {app_port}" if app_port else ""
        return f"Error proxying request: {str(e)}. The app{port_msg} may be returning errors.", 502
    except requests.exceptions.RequestException as e:
        error_msg = f"Request error proxying to {app_name} (port {app_port}): {e}"
        logger.error(error_msg)
        return f"Error proxying request: {str(e)}", 502
    except Exception as e:
        error_trace = traceback.format_exc()
        error_msg = f"Unexpected error in proxy route for {app_slug} (path: {path}): {e}\n{error_trace}"
        logger.error(error_msg)
        return f"Internal proxy error: {str(e)}. Check server logs for details.", 500


@bp.route('/<app_slug>/__heartbeat__', methods=['GET', 'POST'])
def heartbeat(app_slug):
    """
    Heartbeat endpoint to keep apps alive when browser tabs are open.
    This endpoint is called periodically by client-side JavaScript.
    """
    try:
        # Get session ID from request (use a cookie or generate one)
        import uuid
        session_id = request.cookies.get('__app_session_id')
        if not session_id:
            session_id = str(uuid.uuid4())
        
        # Record active tab
        try:
            from app.utils.app_usage_tracker import get_tracker
            tracker = get_tracker(current_app.instance_path)
            tracker.register_active_tab(app_slug, session_id)
        except Exception as e:
            logger.warning(f"Error recording heartbeat: {e}")
        
        # Return success response with session ID cookie
        response = jsonify({'status': 'ok', 'session_id': session_id})
        response.set_cookie('__app_session_id', session_id, max_age=3600*24)  # 24 hours
        return response
    except Exception as e:
        logger.error(f"Error in heartbeat endpoint: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
