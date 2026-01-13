"""
Reverse proxy routes for forwarding requests to internal apps
"""
from flask import Blueprint, request, Response, session, redirect, url_for, current_app
import requests
from urllib.parse import urljoin
import re
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import ResponseError, MaxRetryError
from app.models.app_config import AppConfig
import logging
import traceback

bp = Blueprint('proxy', __name__)

# Configure logging for proxy route
logger = logging.getLogger(__name__)

# Create a session with connection pooling for better performance
_session = requests.Session()

# Configure retry strategy
# Don't retry on 500 errors - these are application errors that won't be fixed by retrying
# Only retry on connection/network errors (502, 503, 504)
retry_strategy = Retry(
    total=1,
    backoff_factor=0.1,
    status_forcelist=[502, 503, 504],  # Removed 500 - don't retry application errors
)

# Mount adapter with connection pooling
adapter = HTTPAdapter(
    pool_connections=10,
    pool_maxsize=20,
    max_retries=retry_strategy
)
_session.mount("http://", adapter)
_session.mount("https://", adapter)

# Helper function to create URL rewriting patterns for a specific app slug
# These patterns rewrite URLs in the HTML/CSS/JS to add the app slug prefix
# so that browser requests go through the proxy
# The internal app sees requests as if they're at root (e.g., /login)
# But browser sees /appname/login and proxy forwards to internal app
def make_patterns_for_app(app_slug):
    """Create URL rewriting patterns for a specific app"""
    escaped_slug = re.escape(app_slug)
    
    # HTML/CSS patterns - rewrite href, src, action, and CSS url() references
    # Match absolute paths starting with / but NOT already prefixed with /{app_slug}/
    # Also avoid matching // (protocol-relative URLs) or /{app_slug}/ (already rewritten)
    html_css_patterns = [
        # href="/path" -> href="/{app_slug}/path" (but not href="/{app_slug}/path" or href="//example.com")
        (re.compile(rf'(href=["\'])(/)(?!{escaped_slug}/)(?!/)'), rf'\1/{app_slug}\2'),
        # src="/path" -> src="/{app_slug}/path"
        (re.compile(rf'(src=["\'])(/)(?!{escaped_slug}/)(?!/)'), rf'\1/{app_slug}\2'),
        # action="/path" -> action="/{app_slug}/path"
        (re.compile(rf'(action=["\'])(/)(?!{escaped_slug}/)(?!/)'), rf'\1/{app_slug}\2'),
        # url('/path') or url("/path") in CSS -> url('/{app_slug}/path')
        (re.compile(rf'(url\(["\']?)(/)(?!{escaped_slug}/)(?!/)'), rf'\1/{app_slug}\2'),
        # @import url('/path') -> @import url('/{app_slug}/path')
        (re.compile(rf'(@import\s+(?:url\()?["\']?)(/)(?!{escaped_slug}/)(?!/)'), rf'\1/{app_slug}\2'),
    ]
    
    # JavaScript patterns - rewrite fetch, XMLHttpRequest, and other API calls
    js_patterns = [
        # fetch('/api/...') or fetch("/api/...") -> fetch('/{app_slug}/api/...')
        (re.compile(rf"(fetch\(['\"])(/)(?!{escaped_slug}/)(?!/)"), rf'\1/{app_slug}\2'),
        # XMLHttpRequest.open('POST', '/api/...') -> XMLHttpRequest.open('POST', '/{app_slug}/api/...')
        (re.compile(rf"(\.open\([^,]+,\s*['\"])(/)(?!{escaped_slug}/)(?!/)"), rf'\1/{app_slug}\2'),
        # axios.get('/api/...') -> axios.get('/{app_slug}/api/...')
        (re.compile(rf"(axios\.(?:get|post|put|delete|patch)\(['\"])(/)(?!{escaped_slug}/)(?!/)"), rf'\1/{app_slug}\2'),
        # $.ajax({ url: '/api/...' }) -> $.ajax({ url: '/{app_slug}/api/...' })
        (re.compile(rf"(url\s*:\s*['\"])(/)(?!{escaped_slug}/)(?!/)"), rf'\1/{app_slug}\2'),
        # $.get('/api/...') -> $.get('/{app_slug}/api/...')
        (re.compile(rf"(\$\.(?:get|post|ajax)\(['\"])(/)(?!{escaped_slug}/)(?!/)"), rf'\1/{app_slug}\2'),
        # window.location = '/...' -> window.location = '/{app_slug}/...'
        (re.compile(rf"((?:window\.)?location(?:\.href)?\s*=\s*['\"])(/)(?!{escaped_slug}/)(?!/)"), rf'\1/{app_slug}\2'),
    ]
    
    return html_css_patterns, js_patterns

def parse_cookie_header(cookie_header):
    """Parse Cookie header value into a dict of name=value pairs"""
    cookies = {}
    if not cookie_header:
        return cookies
    
    # Split by semicolon and parse each cookie
    for cookie_part in cookie_header.split(';'):
        cookie_part = cookie_part.strip()
        if '=' in cookie_part:
            name, value = cookie_part.split('=', 1)
            cookies[name.strip()] = value.strip()
    
    return cookies

def format_cookie_header(cookies):
    """Format a dict of cookies into a Cookie header value"""
    return '; '.join(f'{name}={value}' for name, value in cookies.items())

def isolate_cookies_for_app(cookie_header, app_slug):
    """
    Filter and rewrite cookies for a specific app.
    Only cookies prefixed with {app_slug}_ are forwarded, and the prefix is removed.
    Returns the rewritten Cookie header value or None if no cookies match.
    """
    if not cookie_header:
        return None
    
    cookies = parse_cookie_header(cookie_header)
    app_cookies = {}
    prefix = f'{app_slug}_'
    
    for name, value in cookies.items():
        # Only forward cookies that belong to this app (prefixed with app_slug_)
        if name.startswith(prefix):
            # Remove the prefix before sending to the app
            app_cookie_name = name[len(prefix):]
            app_cookies[app_cookie_name] = value
    
    if app_cookies:
        return format_cookie_header(app_cookies)
    return None

def prefix_set_cookie(set_cookie_value, app_slug):
    """
    Prefix cookie name in Set-Cookie header with app slug and update Path.
    Preserves all Set-Cookie attributes (Domain, Expires, etc.) but updates Path.
    """
    if not set_cookie_value:
        return set_cookie_value
    
    # Set-Cookie format: name=value; Path=/; Domain=example.com; Secure; HttpOnly
    # We need to prefix the cookie name and update the Path attribute
    parts = set_cookie_value.split(';')
    name_value_part = parts[0].strip()
    attribute_parts = [p.strip() for p in parts[1:]] if len(parts) > 1 else []
    
    if '=' in name_value_part:
        cookie_name, cookie_value = name_value_part.split('=', 1)
        cookie_name = cookie_name.strip()
        cookie_value = cookie_value.strip()
        
        # Prefix the cookie name
        prefixed_name = f'{app_slug}_{cookie_name}'
        
        # Update Path attribute to scope cookie to this app's path
        # Remove existing Path attribute if present
        updated_attributes = []
        path_updated = False
        for attr in attribute_parts:
            attr_lower = attr.lower()
            if attr_lower.startswith('path='):
                # Update Path to include app slug prefix
                updated_attributes.append(f'Path=/{app_slug}/')
                path_updated = True
            else:
                # Keep other attributes as-is
                updated_attributes.append(attr)
        
        # Add Path if it wasn't present
        if not path_updated:
            updated_attributes.insert(0, f'Path=/{app_slug}/')
        
        # Reconstruct Set-Cookie header
        if updated_attributes:
            return f'{prefixed_name}={cookie_value}; ' + '; '.join(updated_attributes)
        else:
            return f'{prefixed_name}={cookie_value}; Path=/{app_slug}/'
    
    # If format is unexpected, return as-is
    return set_cookie_value

@bp.route('/<app_slug>', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
@bp.route('/<app_slug>/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
def proxy_path(app_slug, path):
    """Proxy requests to an app using its URL-safe name (slug)"""
    try:
        # Log the incoming request for debugging
        logger.debug(f"Proxy request: app_slug={app_slug}, path={path}, method={request.method}")
        
        # Look up app by slug
        try:
            app_config = AppConfig.get_by_slug(app_slug)
        except Exception as e:
            # Log the error with full traceback
            logger.error(f"Error looking up app by slug '{app_slug}': {str(e)}\n{traceback.format_exc()}")
            # Also log to Flask logger if available
            try:
                current_app.logger.error(f"Error looking up app by slug '{app_slug}': {str(e)}", exc_info=True)
            except:
                pass
            return f"Error loading app configuration: {str(e)}", 500
        
        if not app_config:
            # App not found, return not found page
            logger.warning(f"App not found for slug: {app_slug}")
            from flask import render_template
            return render_template('app_not_found.html'), 404
        
        # Check if app is set to be served
        if not app_config.get('serve_app', True):
            # App exists but is not being served, return not found page
            logger.info(f"App {app_slug} exists but is not set to be served")
            from flask import render_template
            return render_template('app_not_found.html'), 404
        
        app_port = app_config['port']
        app_name = app_config['name']
        
        # Build target URL
        target_url = f"http://localhost:{app_port}/{path}"
        
        # Add query string if present
        if request.query_string:
            target_url += f"?{request.query_string.decode()}"
        # Forward the request
        method = request.method
        headers = dict(request.headers)
        
        # Remove headers that shouldn't be forwarded or might cause issues
        headers.pop('Host', None)
        headers.pop('Content-Length', None)  # Will be recalculated by requests library
        headers.pop('Connection', None)  # Connection header is managed by requests library
        headers.pop('Accept-Encoding', None)  # Let requests handle encoding
        
        # Set Host header explicitly to match the target URL
        # This ensures the app receives the correct Host header
        headers['Host'] = f'localhost:{app_port}'
        
        # Handle X-Forwarded-* headers - append rather than replace if they exist
        # This preserves the forwarding chain
        if 'X-Forwarded-For' in request.headers:
            # Append our IP to the existing chain
            existing_forwarded = request.headers.get('X-Forwarded-For', '')
            client_ip = request.remote_addr or 'unknown'
            headers['X-Forwarded-For'] = f"{existing_forwarded}, {client_ip}".strip(', ')
        else:
            # Set initial X-Forwarded-For
            headers['X-Forwarded-For'] = request.remote_addr or 'unknown'
        
        # Set X-Real-IP if not already set
        if 'X-Real-IP' not in headers:
            headers['X-Real-IP'] = request.remote_addr or 'unknown'
        
        # Isolate cookies for this app - only forward cookies prefixed with app_slug_
        # This prevents cookie conflicts between apps
        cookie_header = headers.get('Cookie')
        if cookie_header:
            isolated_cookies = isolate_cookies_for_app(cookie_header, app_slug)
            if isolated_cookies:
                headers['Cookie'] = isolated_cookies
            else:
                # No cookies for this app, remove Cookie header
                headers.pop('Cookie', None)
        else:
            # No cookies at all, ensure Cookie header is not present
            headers.pop('Cookie', None)
        
        # Forward request data - handle JSON and form data appropriately
        data = None
        json_data = None
        
        # Check if this is a JSON request
        content_type = headers.get('Content-Type', '').lower()
        if 'application/json' in content_type:
            # Forward as JSON - preserve Content-Type header
            try:
                json_data = request.get_json(force=True)
                # Ensure Content-Type is set for JSON
                if 'application/json' not in headers.get('Content-Type', ''):
                    headers['Content-Type'] = 'application/json'
            except Exception:
                # If JSON parsing fails, send raw data but keep original Content-Type
                data = request.get_data()
        else:
            # For form data or other types, send raw data
            data = request.get_data()
            # Preserve original Content-Type if present
            if not headers.get('Content-Type') and request.content_type:
                headers['Content-Type'] = request.content_type
        
        params = dict(request.args)
        
        # Make request to internal app using session for connection pooling
        # Use json parameter for JSON data, data parameter for other types
        request_kwargs = {
            'method': method,
            'url': target_url,
            'headers': headers,
            'params': params,
            'allow_redirects': False,
            'stream': True,
            'timeout': 30
        }
        
        if json_data is not None:
            request_kwargs['json'] = json_data
        elif data:
            request_kwargs['data'] = data
        
        resp = _session.request(**request_kwargs)
        
        # Log 500 errors for debugging (but don't consume the stream yet)
        if resp.status_code == 500:
            logger.warning(f"App {app_name} (port {app_port}) returned 500 error for path '{path}'. Full error will be logged after reading response.")
            logger.warning(f"Request details - Method: {method}, Target URL: {target_url}, Headers sent: {dict(headers)}")
            # Also log to Flask logger
            try:
                current_app.logger.warning(f"App {app_name} (port {app_port}) returned 500 error for path '{path}'")
            except:
                pass
        
        # Build response headers (exclude some that shouldn't be forwarded)
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        response_headers = []
        
        # Process headers and rewrite Location header for redirects
        try:
            # Try to use raw headers first (more complete)
            raw_headers = resp.raw.headers.items()
        except (AttributeError, Exception) as e:
            logger.warning(f"Error reading raw headers from {app_name} (port {app_port}): {e}")
            # Fallback to regular headers
            try:
                raw_headers = resp.headers.items()
            except Exception as e2:
                logger.error(f"Error reading headers from {app_name} (port {app_port}): {e2}")
                try:
                    current_app.logger.error(f"Error reading headers from {app_name} (port {app_port}): {e2}", exc_info=True)
                except:
                    pass
                print(f"[ERROR] Error reading headers from {app_name} (port {app_port}): {e2}", flush=True)
                raw_headers = []
        
        for name, value in raw_headers:
            name_lower = name.lower()
            if name_lower not in excluded_headers:
                # Prefix Set-Cookie headers with app slug to prevent conflicts
                if name_lower == 'set-cookie':
                    value = prefix_set_cookie(value, app_slug)
                
                # Rewrite Location header for redirects to use app slug path (masks port)
                if name_lower == 'location' and resp.status_code in (301, 302, 303, 307, 308):
                    from urllib.parse import urlparse, urlunparse
                    
                    # Rewrite relative URLs to use app slug prefix
                    if value.startswith('/') and not value.startswith('//'):
                        value = f'/{app_slug}{value}'
                    # Rewrite full URLs pointing to localhost or the app port
                    elif value.startswith('http://') or value.startswith('https://'):
                        try:
                            parsed = urlparse(value)
                            # Check if URL points to localhost or contains the app port
                            host = parsed.netloc.split(':')[0]  # Remove port if present
                            port_in_url = parsed.netloc.split(':')[1] if ':' in parsed.netloc else None
                            
                            if (host in ('localhost', '127.0.0.1') or 
                                port_in_url == str(app_port) or
                                (host == current_app.config.get('SERVER_ADDRESS', '').split(':')[0] and 
                                 port_in_url == str(app_port))):
                                # Extract path and query, rewrite to app slug path
                                path_part = parsed.path if parsed.path else '/'
                                query = parsed.query
                                fragment = parsed.fragment
                                
                                # Build new relative URL with app slug prefix
                                new_path = f'/{app_slug}{path_part}' if path_part.startswith('/') else f'/{app_slug}/{path_part}'
                                if query:
                                    value = f'{new_path}?{query}'
                                    if fragment:
                                        value += f'#{fragment}'
                                elif fragment:
                                    value = f'{new_path}#{fragment}'
                                else:
                                    value = new_path
                        except Exception:
                            # If parsing fails, try simple string replacement
                            if f':{app_port}/' in value or 'localhost' in value:
                                # Extract path after domain/port
                                if '/' in value.split('://', 1)[-1]:
                                    path_part = '/' + '/'.join(value.split('://', 1)[-1].split('/', 1)[-1:])
                                    value = f'/{app_slug}{path_part}'
                                else:
                                    value = f'/{app_slug}'
                response_headers.append((name, value))
        
        # Check if this is HTML, CSS, or JavaScript content that needs URL rewriting
        content_type = resp.headers.get('Content-Type', '').lower()
        # More lenient HTML detection - also check if content starts with HTML tags
        is_html = 'text/html' in content_type or content_type.startswith('text/html')
        is_css = 'text/css' in content_type
        # JavaScript detection - check content-type and file extension
        # Also check the request path in case content-type is missing
        request_path = request.path.lower()
        is_js = (
            'application/javascript' in content_type or 
            'text/javascript' in content_type or
            'application/x-javascript' in content_type or
            'application/ecmascript' in content_type or
            (content_type.startswith('text/') and 'javascript' in content_type) or
            path.endswith('.js') or  # Check proxy path
            request_path.endswith('.js') or  # Check request path
            '/js/' in request_path or  # Common JS directory
            '/static/js/' in request_path  # Common static JS path
        )
        needs_rewriting = is_html or is_css or is_js
        
        # Check content length to decide if we should rewrite
        MAX_REWRITE_SIZE = 16 * 1024 * 1024  # 16MB
        content_length = resp.headers.get('Content-Length')
        should_rewrite = needs_rewriting and (
            content_length is None or int(content_length) <= MAX_REWRITE_SIZE
        )
        
        # If content-type is missing or generic and we haven't detected HTML yet, 
        # we'll check after loading content (but only if size is reasonable)
        if not is_html and should_rewrite and (not content_type or 'text/' not in content_type):
            # We'll check the content after loading it below
            pass
        
        # For non-HTML/CSS content or large files, stream directly without loading into memory
        if not should_rewrite:
            def generate():
                try:
                    for chunk in resp.iter_content(chunk_size=8192):
                        if chunk:
                            yield chunk
                except Exception as e:
                    logger.error(f"Error streaming content from {app_name} (port {app_port}): {e}")
                    try:
                        current_app.logger.error(f"Error streaming content from {app_name} (port {app_port}): {e}", exc_info=True)
                    except:
                        pass
                    print(f"[ERROR] Error streaming content from {app_name} (port {app_port}): {e}", flush=True)
                    yield b'Error streaming content'
            
            return Response(
                generate(),
                status=resp.status_code,
                headers=response_headers,
                mimetype=content_type or 'application/octet-stream'
            )
        
        # For HTML/CSS that's small enough, load and rewrite URLs
        # Note: resp.content will read the entire stream, so we only do this for small files
        try:
            content = resp.content
        except Exception as e:
            error_msg = f"Error reading response content from {app_name} (port {app_port}) for path '{path}': {e}"
            logger.error(error_msg)
            try:
                current_app.logger.error(error_msg, exc_info=True)
            except:
                pass
            print(f"[ERROR] {error_msg}", flush=True)
            return f"Error reading response from app: {str(e)}", 502
        
        # Log full error details for 500 errors after reading content
        if resp.status_code == 500:
            try:
                error_preview = content[:2000].decode('utf-8', errors='ignore') if content else 'Empty response body'
                error_msg = f"App {app_name} (port {app_port}) 500 error details for path '{path}':\n{error_preview}\n\nRequest method: {method}, Headers sent: {dict(headers)}, Target URL: {target_url}"
                logger.error(error_msg)
                # Also log to Flask logger and print to console
                try:
                    current_app.logger.error(error_msg)
                except:
                    pass
                # Print to console/stderr so it's visible even if logging isn't configured
                print(f"[ERROR] {error_msg}", flush=True)
            except Exception as e:
                error_msg = f"App {app_name} (port {app_port}) 500 error for path '{path}' (unable to decode error body: {e})"
                logger.error(error_msg)
                try:
                    current_app.logger.error(error_msg, exc_info=True)
                except:
                    pass
                print(f"[ERROR] {error_msg}", flush=True)
        
        # Double-check size (Content-Length might be wrong or missing)
        if len(content) > MAX_REWRITE_SIZE:
            # Too large, stream without rewriting
            def generate():
                yield content  # Already loaded, just yield it
            
            return Response(
                generate(),
                status=resp.status_code,
                headers=response_headers,
                mimetype=content_type
            )
        
        # For 500 errors, don't try to rewrite content - just return it as-is
        # This ensures we don't accidentally break error pages
        if resp.status_code == 500:
            return Response(
                content,
                status=resp.status_code,
                headers=response_headers,
                mimetype=content_type
            )
        
        # If we haven't detected HTML yet but content looks like HTML, detect it now
        if not is_html and should_rewrite:
            peek_content = content[:512] if len(content) > 512 else content
            if (peek_content.startswith(b'<html') or 
                peek_content.startswith(b'<!DOCTYPE') or 
                b'<html' in peek_content[:200] or
                (b'<head' in peek_content and b'<body' in peek_content)):
                is_html = True
                needs_rewriting = True
        
        # Rewrite URLs in HTML/CSS/JS content using app-specific patterns
        try:
            # Get patterns for this specific app
            html_css_patterns, js_patterns = make_patterns_for_app(app_slug)
            
            # Decode content to string for processing
            content_str = content.decode('utf-8', errors='ignore')
            
            # Choose appropriate patterns based on content type
            if is_js:
                # Apply JavaScript-specific patterns
                for pattern, replacement in js_patterns:
                    content_str = pattern.sub(replacement, content_str)
            elif is_html:
                # Apply HTML/CSS patterns to rewrite absolute URLs to include app slug prefix
                # This ensures browser requests go through the proxy
                for pattern, replacement in html_css_patterns:
                    content_str = pattern.sub(replacement, content_str)
                
                # Add or update base tag to ensure relative paths resolve correctly
                # This makes relative URLs work as if the app is at the root
                base_tag_pattern = re.compile(r'<base\s+[^>]*href=["\']([^"\']+)["\'][^>]*>', re.IGNORECASE)
                base_tag_replacement = f'<base href="/{app_slug}/">'
                
                # Check if base tag exists
                if base_tag_pattern.search(content_str):
                    # Replace existing base tag to point to app slug path
                    content_str = base_tag_pattern.sub(base_tag_replacement, content_str)
                else:
                    # Insert base tag after <head> tag if it exists
                    head_pattern = re.compile(r'(<head[^>]*>)', re.IGNORECASE)
                    if head_pattern.search(content_str):
                        content_str = head_pattern.sub(rf'\1\n    {base_tag_replacement}', content_str, count=1)
                    else:
                        # If no head tag, try to insert after <html>
                        html_pattern = re.compile(r'(<html[^>]*>)', re.IGNORECASE)
                        if html_pattern.search(content_str):
                            content_str = html_pattern.sub(rf'\1\n  {base_tag_replacement}', content_str, count=1)
                
                # Inject favicon links if app has a logo
                if app_config.get('logo'):
                    try:
                        # Generate favicon URL - logo path is stored as "uploads/logos/filename.png"
                        # Route is /admin/uploads/<path:filename>, so URL is /admin/uploads/uploads/logos/filename.png
                        # Admin routes are at root level, not under app slug
                        logo_path = app_config['logo']
                        favicon_url = f'/admin/uploads/{logo_path}'
                        
                        # Create favicon link tags
                        favicon_tags = f'''    <link rel="icon" type="image/png" href="{favicon_url}">
    <link rel="shortcut icon" type="image/png" href="{favicon_url}">
    <link rel="apple-touch-icon" href="{favicon_url}">'''
                        
                        # Remove existing favicon links to avoid duplicates
                        favicon_pattern = re.compile(
                            r'<link\s+[^>]*rel=["\'](?:icon|shortcut\s+icon|apple-touch-icon)["\'][^>]*>',
                            re.IGNORECASE
                        )
                        content_str = favicon_pattern.sub('', content_str)
                        
                        # Insert favicon links after <head> tag or after base tag if it exists
                        base_tag_pattern = re.compile(r'(<base\s+[^>]*href=["\'][^"\']+["\'][^>]*>)', re.IGNORECASE)
                        if base_tag_pattern.search(content_str):
                            # Insert after base tag
                            content_str = base_tag_pattern.sub(rf'\1\n{favicon_tags}', content_str, count=1)
                        else:
                            # Insert after <head> tag
                            head_pattern = re.compile(r'(<head[^>]*>)', re.IGNORECASE)
                            if head_pattern.search(content_str):
                                content_str = head_pattern.sub(rf'\1\n{favicon_tags}', content_str, count=1)
                            else:
                                # If no head tag, try to insert after <html>
                                html_pattern = re.compile(r'(<html[^>]*>)', re.IGNORECASE)
                                if html_pattern.search(content_str):
                                    content_str = html_pattern.sub(rf'\1\n  <head>\n{favicon_tags}\n  </head>', content_str, count=1)
                    except Exception as e:
                        # If favicon injection fails, continue without it
                        logger.warning(f"Failed to inject favicon for app {app_slug}: {e}")
                
                # Also rewrite JavaScript in inline <script> tags
                for pattern, replacement in js_patterns:
                    content_str = pattern.sub(replacement, content_str)
            else:
                # Apply HTML/CSS patterns (for CSS files)
                for pattern, replacement in html_css_patterns:
                    content_str = pattern.sub(replacement, content_str)
            
            # Re-encode to bytes
            content = content_str.encode('utf-8')
        except Exception as e:
            # If rewriting fails, use original content
            error_msg = f"Error rewriting content for app {app_slug}: {e}"
            logger.error(error_msg)
            try:
                current_app.logger.error(error_msg, exc_info=True)
            except:
                pass
            print(f"[ERROR] {error_msg}", flush=True)
            # Continue with original content - don't fail the request
        
        # Create Flask response
        return Response(
            content,
            status=resp.status_code,
            headers=response_headers,
            mimetype=content_type
        )
    
    except requests.exceptions.ConnectionError as e:
        # App is not responding
        error_msg = f"Connection error proxying to {app_name} (port {app_port}): {e}"
        logger.error(error_msg)
        try:
            current_app.logger.error(error_msg, exc_info=True)
        except:
            pass
        print(f"[ERROR] {error_msg}", flush=True)
        return f"App on port {app_port} is not responding. Please check if the app is running.", 503
    except requests.exceptions.Timeout as e:
        error_msg = f"Timeout error proxying to {app_name} (port {app_port}): {e}"
        logger.error(error_msg)
        try:
            current_app.logger.error(error_msg, exc_info=True)
        except:
            pass
        print(f"[ERROR] {error_msg}", flush=True)
        return "Request to app timed out.", 504
    except (ResponseError, MaxRetryError) as e:
        # Handle retry errors - this usually means the app returned multiple 500 errors
        error_msg = f"Retry error proxying to {app_name} (port {app_port}): {e}"
        logger.error(error_msg)
        try:
            current_app.logger.error(error_msg, exc_info=True)
        except:
            pass
        print(f"[ERROR] {error_msg}", flush=True)
        # Try to get more details from the exception
        error_details = str(e)
        if hasattr(e, 'reason') and hasattr(e.reason, 'response'):
            try:
                response = e.reason.response
                status_code = response.status_code if response else 'unknown'
                error_details += f" (Last status: {status_code})"
            except:
                pass
        return f"Error proxying request: {error_details}. The app on port {app_port} may be returning errors.", 502
    except requests.exceptions.RequestException as e:
        # Handle other requests library errors
        error_msg = f"Request error proxying to {app_name} (port {app_port}): {e}"
        logger.error(error_msg)
        try:
            current_app.logger.error(error_msg, exc_info=True)
        except:
            pass
        print(f"[ERROR] {error_msg}", flush=True)
        return f"Error proxying request: {str(e)}", 502
    except Exception as e:
        # Catch any other exceptions in the proxy route itself
        error_trace = traceback.format_exc()
        error_msg = f"Unexpected error in proxy route for {app_slug} (path: {path}): {e}\n{error_trace}"
        logger.error(error_msg)
        try:
            current_app.logger.error(error_msg, exc_info=True)
        except:
            pass
        print(f"[ERROR] {error_msg}", flush=True)
        return f"Internal proxy error: {str(e)}. Check server logs for details.", 500

