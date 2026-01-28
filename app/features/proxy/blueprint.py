"""
Proxy blueprint and route registration.

IMPORTANT: Read `instructions/architecture` before making changes.
"""

import os
from flask import Blueprint

bp = Blueprint("proxy", __name__)

# Special prefix for AppManager routes - should never be proxied
MANAGER_PREFIX = "blackgrid"

# Reduce debug logging in production for performance
IS_PRODUCTION = os.environ.get("FLASK_ENV") == "production" or os.environ.get("FLASK_DEBUG") == "0"

# Import routes for side effects (decorators attach to bp)
from . import routes  # noqa: E402,F401

