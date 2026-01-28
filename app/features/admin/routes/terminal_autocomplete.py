"""
Admin terminal autocomplete API route.

IMPORTANT: Read `instructions/architecture` before making changes.
"""

import os

from flask import current_app, jsonify, request
from flask_login import login_required

from ..blueprint import bp


@bp.route("/api/terminal/autocomplete", methods=["POST"])
@login_required
def terminal_autocomplete():
    """Get autocomplete suggestions for file/folder paths."""
    try:
        data = request.get_json()
        partial_path = (data.get("path", "") if data else "").strip()
        current_dir = data.get("cwd", os.path.expanduser("~")) if data else os.path.expanduser("~")

        if not partial_path:
            return jsonify({"matches": [], "is_directory": False})

        if "/" in partial_path or "\\" in partial_path:
            dir_part = os.path.dirname(partial_path)
            file_part = os.path.basename(partial_path)
        else:
            dir_part = "."
            file_part = partial_path

        if os.path.isabs(dir_part):
            search_dir = dir_part
        elif dir_part == ".":
            search_dir = current_dir
        else:
            search_dir = os.path.join(current_dir, dir_part)

        search_dir = os.path.normpath(search_dir)
        search_dir_abs = os.path.abspath(search_dir)

        safe_directories = [os.path.expanduser("~"), "/opt/appmanager", "/tmp"]

        search_allowed = False
        for safe_dir in safe_directories:
            safe_dir_abs = os.path.abspath(safe_dir)
            if search_dir_abs.startswith(safe_dir_abs + os.sep) or search_dir_abs == safe_dir_abs:
                search_allowed = True
                break

        if not search_allowed:
            return jsonify({"matches": [], "is_directory": False, "error": "Path not in allowed directories"})

        if not os.path.isdir(search_dir_abs):
            return jsonify({"matches": [], "is_directory": False})

        matches = []
        try:
            for item in os.listdir(search_dir_abs):
                if item.startswith(file_part):
                    item_path = os.path.join(search_dir_abs, item)
                    is_dir = os.path.isdir(item_path)
                    matches.append({"name": item, "is_directory": is_dir, "full_path": item_path})
        except PermissionError:
            return jsonify({"matches": [], "is_directory": False, "error": "Permission denied"})
        except Exception as e:
            return jsonify({"matches": [], "is_directory": False, "error": str(e)})

        matches.sort(key=lambda x: (not x["is_directory"], x["name"].lower()))

        return jsonify({"matches": matches, "directory": search_dir_abs, "partial": file_part})

    except Exception as e:
        current_app.logger.error(f"Error in terminal_autocomplete: {str(e)}", exc_info=True)
        return jsonify({"matches": [], "is_directory": False, "error": str(e)}), 500

