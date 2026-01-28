"""
Docs blueprint and route registration.

IMPORTANT: Read `instructions/architecture` before making changes.
"""

from flask import Blueprint

bp = Blueprint("docs", __name__, url_prefix="/blackgrid")

# Import routes for side effects (decorators attach to bp)
from . import routes  # noqa: E402,F401

