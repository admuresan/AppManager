"""
Cookie rewriting helpers for proxy cookie isolation.

IMPORTANT: Read `instructions/architecture` before making changes.
"""


def prefix_cookie_name(cookie_name: str, app_slug: str) -> str:
    """Add app prefix to cookie name for isolation."""
    prefix = f"{app_slug}_"
    if cookie_name.startswith(prefix):
        return cookie_name
    return prefix + cookie_name


def unprefix_cookie_name(cookie_name: str, app_slug: str) -> str:
    """Remove app prefix from cookie name."""
    prefix = f"{app_slug}_"
    if cookie_name.startswith(prefix):
        return cookie_name[len(prefix) :]
    return cookie_name


def rewrite_cookie_header(cookie_header: str, app_slug: str, add_prefix: bool = True) -> str:
    """Rewrite Cookie header to add or remove app prefix from cookie names."""
    if not cookie_header:
        return cookie_header

    cookies: list[str] = []
    for cookie_pair in cookie_header.split(";"):
        cookie_pair = cookie_pair.strip()
        if "=" in cookie_pair:
            name, value = cookie_pair.split("=", 1)
            name = name.strip()
            value = value.strip()

            if add_prefix:
                name = prefix_cookie_name(name, app_slug)
            else:
                name = unprefix_cookie_name(name, app_slug)

            cookies.append(f"{name}={value}")
        else:
            cookies.append(cookie_pair)

    return "; ".join(cookies)


def rewrite_set_cookie_header(set_cookie_value: str, app_slug: str) -> str:
    """Rewrite Set-Cookie header to add app prefix to cookie name."""
    if not set_cookie_value:
        return set_cookie_value

    parts = [p.strip() for p in set_cookie_value.split(";")]
    if not parts:
        return set_cookie_value

    name_value = parts[0]
    if "=" not in name_value:
        return set_cookie_value

    name, value = name_value.split("=", 1)
    name = name.strip()
    value = value.strip()

    prefixed_name = prefix_cookie_name(name, app_slug)

    result = f"{prefixed_name}={value}"
    if len(parts) > 1:
        result += "; " + "; ".join(parts[1:])

    return result

