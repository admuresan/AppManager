"""
Path-based proxy: forward requests to a managed app on localhost.

IMPORTANT: Read `instructions/architecture` before making changes.
"""
import threading
from flask import request, Response, abort

# Slugs that must not be proxied (AppManager's own paths or reserved)
RESERVED_SLUGS = frozenset({'blackgrid', 'logo', 'static', 'media', 'app-icon'})

# Per-backend Session for connection reuse; each backend has (session, lock). Session is not thread-safe.
_session_cache = {}
_session_cache_lock = threading.Lock()


def _get_session(backend_url_base):
    """Get or create a requests.Session for this backend (connection reuse). Returns (session, lock)."""
    with _session_cache_lock:
        if backend_url_base not in _session_cache:
            import requests
            _session_cache[backend_url_base] = (requests.Session(), threading.Lock())
        return _session_cache[backend_url_base]


def _copy_forward_headers(from_headers, prefix):
    """Build headers for the backend request: forward X-Forwarded-* and add X-Forwarded-Prefix."""
    headers = {}
    for name, value in from_headers:
        name_lower = name.lower()
        if name_lower in ('host', 'connection', 'transfer-encoding', 'content-length'):
            continue
        if name_lower.startswith('x-forwarded-'):
            headers[name] = value
            continue
        headers[name] = value
    headers['X-Forwarded-Prefix'] = prefix
    return headers


def proxy_to_backend(backend_url_base, prefix, timeout=120):
    """
    Forward the current request to backend_url_base (e.g. http://127.0.0.1:6006).
    Uses a per-backend requests.Session for connection reuse (keep-alive).
    prefix is the path prefix (e.g. /calculator) for X-Forwarded-Prefix.
    Returns a Flask Response or None (caller should abort(404) if None).
    """
    import requests

    # Build backend URL: base + path (without prefix) + query string
    path = request.path
    if path.startswith(prefix) and (path == prefix or path[len(prefix)] == '/'):
        backend_path = path[len(prefix):] or '/'
    else:
        backend_path = '/'
    backend_path = backend_path.split('?')[0]
    if not backend_path.startswith('/'):
        backend_path = '/' + backend_path
    query = request.query_string.decode('utf-8') if request.query_string else ''
    backend_url = backend_url_base.rstrip('/') + backend_path + ('?' + query if query else '')

    headers = _copy_forward_headers(request.headers, prefix)
    session, lock = _get_session(backend_url_base)

    try:
        # Stream request body for methods that have one (Werkzeug 2.1+ has no silent arg)
        data = request.get_data() or None
        with lock:
            resp = session.request(
                method=request.method,
                url=backend_url,
                headers=headers,
                data=data,
                stream=True,
                timeout=timeout,
                allow_redirects=False,
            )
            # Read body while holding lock so session is not used concurrently; then stream to client
            chunks = list(resp.iter_content(chunk_size=65536))
    except requests.exceptions.ConnectionError:
        return Response('Backend unreachable', status=502, mimetype='text/plain')
    except requests.exceptions.Timeout:
        return Response('Backend timeout', status=504, mimetype='text/plain')
    except Exception as e:
        return Response(f'Proxy error: {e}', status=502, mimetype='text/plain')

    # Build response headers: copy from backend, drop hop-by-hop and adjust if needed
    excluded = {'transfer-encoding', 'connection', 'content-encoding', 'content-length'}
    response_headers = []
    for name, value in resp.headers.items():
        if name.lower() in excluded:
            continue
        response_headers.append((name, value))

    def generate():
        for chunk in chunks:
            if chunk:
                yield chunk

    return Response(
        generate(),
        status=resp.status_code,
        headers=response_headers,
        direct_passthrough=True,
    )


def proxy_view(slug, subpath=None):
    """
    View for path-based app proxy. Resolve slug to app config; if found and not reserved, proxy.
    """
    from app.models.app_config import AppConfig

    if slug in RESERVED_SLUGS:
        abort(404)
    app_config = AppConfig.get_by_slug(slug)
    if not app_config or not app_config.get('serve_app', True):
        abort(404)
    port = app_config.get('port')
    if not port:
        abort(404)
    prefix = '/' + slug
    backend_url_base = f'http://127.0.0.1:{port}'
    return proxy_to_backend(backend_url_base, prefix)
