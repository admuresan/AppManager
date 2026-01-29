"""
Docs routes.

IMPORTANT: Read `instructions/architecture` before making changes.
"""

from __future__ import annotations

import os
from pathlib import Path

from flask import abort, current_app, jsonify, render_template, request

from app.models.app_config import AppConfig

from .blueprint import bp

_SKIP_DIR_NAMES = {
    ".git",
    "__pycache__",
    "node_modules",
}


def _workspace_root() -> Path:
    """
    Best-effort workspace root discovery.

    In this repo layout, AppManager lives at: <root>/AppManager/app/routes/docs.py
    """
    return Path(__file__).resolve().parents[4]


def _is_venv_dir(p: Path) -> bool:
    name = p.name.lower()
    if name in {"venv", ".venv", "env", ".env", "amvenv"}:
        return True
    if name.endswith("venv") or name.endswith("_venv"):
        return True
    try:
        if (p / "pyvenv.cfg").exists():
            return True
    except Exception:
        pass
    return False


def _resolve_app_root(app_cfg: dict) -> Path | None:
    folder_path = (app_cfg.get("folder_path") or "").strip()
    slug = AppConfig._slugify(app_cfg.get("name", ""))
    name = (app_cfg.get("name") or "").strip()

    candidates: list[Path] = []

    if folder_path:
        fp = Path(folder_path)
        if fp.is_absolute():
            candidates.append(fp)
        else:
            candidates.append(Path("/opt") / folder_path)
            candidates.append(_workspace_root() / folder_path)

    if slug:
        candidates.append(Path("/opt") / slug)
        candidates.append(_workspace_root() / slug)

    if name:
        candidates.append(Path("/opt") / name)
        candidates.append(_workspace_root() / name)

    seen: set[str] = set()
    for c in candidates:
        try:
            key = str(c.resolve()) if c.exists() else str(c)
        except Exception:
            key = str(c)
        if key in seen:
            continue
        seen.add(key)
        try:
            if c.exists() and c.is_dir():
                return c
        except Exception:
            continue
    return None


def _list_markdown_files(root: Path) -> list[str]:
    files: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        base = Path(dirpath)

        pruned: list[str] = []
        for d in list(dirnames):
            dp = base / d
            if d in _SKIP_DIR_NAMES or _is_venv_dir(dp):
                continue
            pruned.append(d)
        dirnames[:] = pruned

        for fn in filenames:
            # Include all .md files (case-insensitive), including README.md
            fn_lower = fn.lower()
            if not fn_lower.endswith(".md"):
                continue
            try:
                rel = (base / fn).relative_to(root)
                files.append(rel.as_posix())
            except Exception:
                continue

    # Sort with README.md files first (case-insensitive)
    files.sort(key=lambda s: (s.lower() != "readme.md", s.lower()))
    return files


def _safe_doc_path(root: Path, rel_path: str) -> Path:
    rel = Path(rel_path)
    if rel.is_absolute():
        raise ValueError("absolute path not allowed")
    if ".." in rel.parts:
        raise ValueError("path traversal not allowed")
    if rel.suffix.lower() != ".md":
        raise ValueError("only .md files are allowed")

    full = (root / rel).resolve()
    root_resolved = root.resolve()

    if hasattr(full, "is_relative_to"):
        if not full.is_relative_to(root_resolved):  # type: ignore[attr-defined]
            raise ValueError("path outside root")
    else:
        if not str(full).startswith(str(root_resolved)):
            raise ValueError("path outside root")

    if not full.exists() or not full.is_file():
        raise FileNotFoundError("file not found")
    return full


def _render_markdown(md_text: str) -> str:
    try:
        import bleach
        import markdown as markdown_lib
    except Exception as e:
        # Degrade gracefully if optional deps aren't installed.
        current_app.logger.error(f"Docs rendering dependencies missing: {e}")
        return "<p>Documentation rendering is not available (missing Markdown dependencies).</p>"

    html = markdown_lib.markdown(
        md_text,
        extensions=[
            "fenced_code",
            "tables",
            "sane_lists",
        ],
        output_format="html5",
    )

    allowed_tags = [
        "a",
        "blockquote",
        "br",
        "code",
        "em",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "hr",
        "li",
        "ol",
        "p",
        "pre",
        "strong",
        "table",
        "thead",
        "tbody",
        "tr",
        "th",
        "td",
        "ul",
    ]
    allowed_attrs = {"a": ["href", "title", "rel", "target"], "*": ["class"]}

    clean = bleach.clean(html, tags=allowed_tags, attributes=allowed_attrs, protocols=["http", "https", "mailto"], strip=True)
    clean = bleach.linkify(clean, callbacks=[bleach.callbacks.nofollow, bleach.callbacks.target_blank])
    return clean


@bp.get("/docs")
def index():
    apps = AppConfig.get_all()
    selected_app_id = request.args.get("app_id") or (apps[0]["id"] if apps else "")
    selected_path = request.args.get("path") or ""
    return render_template("docs.html", apps=apps, selected_app_id=selected_app_id, selected_path=selected_path)


@bp.get("/docs/api/files")
def api_files():
    app_id = request.args.get("app_id")
    if not app_id:
        return jsonify({"success": False, "error": "app_id is required"}), 400

    app_cfg = AppConfig.get_by_id(app_id)
    if not app_cfg:
        return jsonify({"success": False, "error": "App not found"}), 404

    root = _resolve_app_root(app_cfg)
    if not root:
        return jsonify({"success": True, "app_id": app_id, "root": None, "files": [], "warning": "App folder not found. Set folder_path for this app in AppManager."})

    files = _list_markdown_files(root)
    return jsonify({"success": True, "app_id": app_id, "root": str(root), "files": files})


@bp.get("/docs/api/render")
def api_render():
    app_id = request.args.get("app_id")
    rel_path = request.args.get("path")
    if not app_id or not rel_path:
        return jsonify({"success": False, "error": "app_id and path are required"}), 400

    app_cfg = AppConfig.get_by_id(app_id)
    if not app_cfg:
        return jsonify({"success": False, "error": "App not found"}), 404

    root = _resolve_app_root(app_cfg)
    if not root:
        return jsonify({"success": False, "error": "App folder not found. Set folder_path for this app."}), 404

    try:
        full = _safe_doc_path(root, rel_path)
    except FileNotFoundError:
        return jsonify({"success": False, "error": "File not found"}), 404
    except Exception as e:
        current_app.logger.warning(f"Docs render blocked: {e}")
        return jsonify({"success": False, "error": "Invalid path"}), 400

    try:
        raw = full.read_text(encoding="utf-8", errors="replace")
    except Exception:
        abort(500)

    if len(raw) > 2_000_000:
        return jsonify({"success": False, "error": "File too large to render"}), 413

    html = _render_markdown(raw)
    return jsonify({"success": True, "app_id": app_id, "path": rel_path, "title": full.name, "html": html})

