"""
Admin public upload serving routes (logos).

IMPORTANT: Read `instructions/architecture` before making changes.
"""

from pathlib import Path

from flask import current_app, send_from_directory

from ..blueprint import bp


@bp.route("/uploads/<path:filename>")
def uploaded_file(filename):
    """Serve uploaded files (public access for logos)."""
    instance_path = Path(current_app.instance_path)
    # Route is /blackgrid/admin/uploads/<filename>, so filename should be relative to instance/uploads/
    # If filename is 'logos/file.png', we need to serve 'instance/uploads/logos/file.png'
    # If filename already includes 'uploads/', strip it (for backward compatibility)
    if filename.startswith("uploads/"):
        return send_from_directory(instance_path, filename)
    return send_from_directory(instance_path, f"uploads/{filename}")

