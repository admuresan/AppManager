"""
Discover apps by scanning configured folders for app.py files and extracting port.

IMPORTANT: Read `instructions/architecture` before making changes.
"""
import re
from pathlib import Path
from typing import List, Optional, Dict

# Common entry points to check (in order)
_ENTRY_FILES = ["app.py", "run.py", "run_production.py", "main.py"]

# Patterns to extract port from Python files
_PORT_PATTERNS = [
    # app.run(port=5000) or app.run(host='...', port=5000)
    re.compile(r"app\.run\s*\([^)]*port\s*=\s*(\d+)", re.IGNORECASE | re.DOTALL),
    # port=5000 in run() call
    re.compile(r"\.run\s*\([^)]*port\s*=\s*(\d+)", re.IGNORECASE | re.DOTALL),
    # get_port() return or port = 5000
    re.compile(r"(?:return|port\s*=\s*)\s*(\d{4,5})\b"),
    # GAME_PORT = 5000 or PORT = 5000
    re.compile(r"(?:GAME_PORT|PORT|SERVER_PORT)\s*=\s*(\d+)", re.IGNORECASE),
]


def _extract_port_from_python(file_path: Path) -> Optional[int]:
    """Try to extract port from a Python file."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        for pattern in _PORT_PATTERNS:
            match = pattern.search(content)
            if match:
                port = int(match.group(1))
                if 1 <= port <= 65535:
                    return port
    except (IOError, OSError, ValueError):
        pass
    return None


def _get_port_for_folder(folder: Path) -> Optional[int]:
    """Get port for an app folder from Python entry files (app.py, run.py, etc.). deploy_config.json is shared and has no port."""
    # Try Python entry files
    for entry in _ENTRY_FILES:
        py_path = folder / entry
        if py_path.exists() and py_path.is_file():
            port = _extract_port_from_python(py_path)
            if port is not None:
                return port
            # Also check app/ subdir if app.py is a launcher (e.g. Calculator)
            app_py = folder / "app" / "backend" / "app.py"
            if app_py.exists():
                port = _extract_port_from_python(app_py)
                if port is not None:
                    return port

    return None


def discover_apps_in_folder(base_path: Path) -> List[Dict]:
    """
    Scan a folder for direct subdirectories containing app.py.
    Returns list of {folder_path, name, port}.
    """
    results = []
    base_path = Path(base_path).resolve()
    if not base_path.exists() or not base_path.is_dir():
        return results

    try:
        for item in base_path.iterdir():
            if not item.is_dir() or item.name.startswith(".") or item.name in ["lost+found", "__pycache__"]:
                continue
            # Check for app.py (or other entry points) in this subfolder
            has_app = False
            for entry in _ENTRY_FILES:
                if (item / entry).exists():
                    has_app = True
                    break
            if not has_app:
                continue
            port = _get_port_for_folder(item)
            if port is None:
                port = 5000  # fallback
            results.append({
                "folder_path": str(item),
                "name": item.name,
                "port": port,
            })
    except (PermissionError, OSError):
        pass
    return results


def discover_apps(search_folders: List[str], exclude_folders: Optional[List[str]] = None) -> List[Dict]:
    """
    Discover apps in all configured search folders.
    Deduplicates by folder_path. Excludes folders in exclude_folders (e.g. AppManager itself).
    """
    exclude = set()
    if exclude_folders:
        exclude = {str(Path(p).resolve()) for p in exclude_folders}

    seen_paths = set()
    all_apps = []

    for folder_str in search_folders:
        folder = Path(folder_str).resolve()
        if str(folder) in exclude:
            continue
        discovered = discover_apps_in_folder(folder)
        for app in discovered:
            path_key = str(Path(app["folder_path"]).resolve())
            if path_key not in seen_paths and path_key not in exclude:
                seen_paths.add(path_key)
                all_apps.append(app)

    return sorted(all_apps, key=lambda a: (a["name"].lower(), a["port"]))


def get_default_app_search_folder(instance_path: str) -> str:
    """
    Return the default folder to search for apps: parent of AppManager root.
    AppManager runs from e.g. /BlackGrid/appmanager or C:\\Projects\\AppManager;
    instance_path is e.g. /BlackGrid/appmanager/instance, so parent of AppManager = instance_path.parent.parent.
    """
    instance = Path(instance_path).resolve()
    appmanager_root = instance.parent  # /BlackGrid/appmanager or C:\Projects\AppManager
    parent = appmanager_root.parent     # /opt or C:\Projects
    return str(parent)
