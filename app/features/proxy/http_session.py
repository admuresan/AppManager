"""
HTTP session setup for proxying (connection pooling + retry).

IMPORTANT: Read `instructions/architecture` before making changes.
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def create_proxy_session() -> requests.Session:
    """Create a requests session tuned for proxy traffic."""
    session = requests.Session()

    retry_strategy = Retry(
        total=1,
        backoff_factor=0.1,
        status_forcelist=[502, 503, 504],
    )

    adapter = HTTPAdapter(pool_connections=10, pool_maxsize=20, max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    return session


_SESSION = create_proxy_session()

