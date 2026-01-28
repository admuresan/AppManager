"""
URL rewriting helpers for the proxy.

IMPORTANT: Read `instructions/architecture` before making changes.
"""

from urllib.parse import urlparse

from flask import current_app


def get_manager_domain() -> str:
    """Get the manager domain name from config."""
    try:
        if current_app and hasattr(current_app, "config"):
            domain = current_app.config.get("SERVER_DOMAIN", "blackgrid.ddns.net")
            if domain:
                return domain
    except Exception:
        pass
    return "blackgrid.ddns.net"


def url_has_app_prefix(url_path: str, app_slug: str) -> bool:
    """Return True if first path segment matches app_slug."""
    if not url_path or not url_path.startswith("/"):
        return False

    path_segments = [seg for seg in url_path.split("/") if seg]
    return bool(path_segments and path_segments[0] == app_slug)


def rewrite_url(url: str, app_slug: str, manager_domain: str) -> str:
    """
    Rewrite URL to include /app_slug/ prefix.

    Golden rule: f(x) prepends /app_slug/ so that g(f(x)) = x where g removes the prefix.
    """
    if not url or not isinstance(url, str):
        return url

    if url.startswith(("data:", "javascript:", "mailto:", "tel:", "#")):
        return url

    if url.startswith("//"):
        return url

    if url.startswith("http://") or url.startswith("https://"):
        try:
            parsed = urlparse(url)
            if parsed.netloc.startswith("localhost:") or parsed.netloc.startswith("127.0.0.1:"):
                protocol = "https" if url.startswith("https://") else "http"
                path = parsed.path if parsed.path else "/"
                if not path.startswith("/"):
                    path = "/" + path

                if not url_has_app_prefix(path, app_slug):
                    new_path = f"/{app_slug}{path}"
                else:
                    new_path = path

                new_url = f"{protocol}://{manager_domain}{new_path}"

                if parsed.query:
                    new_url += f"?{parsed.query}"
                if parsed.fragment:
                    new_url += f"#{parsed.fragment}"

                return new_url

            return url
        except Exception:
            return url

    if url.startswith("/"):
        if url_has_app_prefix(url, app_slug):
            return url
        return f"/{app_slug}{url}"

    return f"/{app_slug}/{url}" if not url.startswith("/") else f"/{app_slug}{url}"

