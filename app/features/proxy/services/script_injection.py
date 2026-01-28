"""
Client-side script injection for dynamic URL rewriting.

IMPORTANT: Read `instructions/architecture` before making changes.
"""

import logging
import re

from flask import current_app

logger = logging.getLogger(__name__)


def rewrite_urls_in_content(content, app_slug: str, _manager_domain: str, content_type: str = ""):
    """
    Inject client-side URL rewriting script for JavaScript-generated URLs.

    IMPORTANT: We do NOT rewrite URLs in HTML/CSS content because:
    1. If the app uses ProxyFix correctly, it already generates URLs with the prefix
    2. Server-side rewriting would double-prefix URLs that already have the prefix
    3. Client-side JavaScript handles dynamic URLs created at runtime
    """
    if not content:
        return content

    try:
        if isinstance(content, bytes):
            content_str = content.decode("utf-8", errors="ignore")
        else:
            content_str = str(content)
    except Exception:
        return content

    is_html = "text/html" in (content_type or "").lower()

    if not is_html:
        return content if isinstance(content, bytes) else content_str.encode("utf-8")

    if is_html and "<head" in content_str.lower():
        try:
            template = current_app.jinja_env.get_template("proxy_rewrite_script.html")
            rewrite_script = template.render(app_slug=app_slug)
        except Exception as e:
            logger.error(f"Error loading rewrite script template: {e}")
            return content_str.encode("utf-8")

        if "__APP_MANAGER_REWRITE_LOADED" not in content_str:
            head_pattern = re.compile(r"(<head[^>]*>)", re.IGNORECASE)
            if head_pattern.search(content_str):
                content_str = head_pattern.sub(rf"\1\n{rewrite_script}", content_str, count=1)
            else:
                html_pattern = re.compile(r"(<html[^>]*>)", re.IGNORECASE)
                if html_pattern.search(content_str):
                    content_str = html_pattern.sub(rf"\1\n  <head>{rewrite_script}</head>", content_str, count=1)

    return content_str.encode("utf-8")

