"""
Admin configuration loaded from instance/admin_config.json.
"""

import json
from pathlib import Path
from typing import Any


def _get_config_path(instance_path: str) -> Path:
    return Path(instance_path) / "admin_config.json"


def _default_app_search_folders(instance_path: str = None) -> list:
    """Default: parent folder of AppManager (e.g. /opt or C:\\Projects)."""
    if instance_path is None:
        try:
            from flask import current_app
            instance_path = current_app.instance_path
        except RuntimeError:
            return []
    from pathlib import Path
    instance = Path(instance_path).resolve()
    parent = instance.parent.parent  # parent of AppManager folder
    return [str(parent)] if str(parent) else []


def get_admin_config(instance_path: str = None) -> dict:
    """
    Load admin config from instance/admin_config.json.
    Default values: app_search_folders=[parent of AppManager]
    """
    defaults = {
        "app_search_folders": _default_app_search_folders(instance_path),
    }
    if instance_path is None:
        try:
            from flask import current_app
            instance_path = current_app.instance_path
        except RuntimeError:
            return defaults

    cfg_path = _get_config_path(instance_path)
    if not cfg_path.exists():
        return defaults

    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            defaults.update(data)
        return defaults
    except Exception:
        return defaults


def save_admin_config(instance_path: str, cfg: dict) -> bool:
    """Save full admin config to instance/admin_config.json."""
    cfg_path = _get_config_path(instance_path)
    try:
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        return True
    except Exception:
        return False
