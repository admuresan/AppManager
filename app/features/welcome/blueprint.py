"""
Welcome blueprint and route registration.

IMPORTANT: Read `instructions/architecture` before making changes.
"""

from flask import Blueprint

bp = Blueprint("welcome", __name__, url_prefix="/blackgrid")

from . import routes  # noqa: E402,F401

