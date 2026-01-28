"""
Admin OCI API routes.

IMPORTANT: Read `instructions/architecture` before making changes.
"""

import json
import os
from pathlib import Path

from flask import current_app, jsonify, request
from flask_login import login_required

from ..blueprint import bp


@bp.route("/api/oci/config", methods=["GET", "POST"])
@login_required
def oci_config_api():
    """Get/set OCI config stored in instance/oci_config.json."""
    cfg_path = Path(current_app.instance_path) / "oci_config.json"

    if request.method == "GET":
        if cfg_path.exists():
            try:
                with open(cfg_path, "r") as f:
                    cfg = json.load(f) or {}
            except Exception:
                cfg = {}
        else:
            cfg = {}
        return jsonify({"success": True, "config": cfg})

    data = request.get_json(silent=True) or {}
    cfg = {
        "user": (data.get("user") or "").strip(),
        "tenancy": (data.get("tenancy") or "").strip(),
        "region": (data.get("region") or "").strip(),
        "fingerprint": (data.get("fingerprint") or "").strip(),
        "key_file": (data.get("key_file") or "").strip() or "~/.oci/oci_api_key.pem",
        "compartment_id": (data.get("compartment_id") or "").strip(),
        "vcn_id": (data.get("vcn_id") or "").strip(),
    }

    # Minimal validation: require the fields AppManager needs for security list edits.
    required = ["user", "tenancy", "region", "fingerprint", "compartment_id", "vcn_id"]
    missing = [k for k in required if not cfg.get(k)]
    if missing:
        return jsonify({"success": False, "error": f"Missing required fields: {', '.join(missing)}"}), 400

    try:
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        with open(cfg_path, "w") as f:
            json.dump(cfg, f, indent=4)

        # Reset OCI singleton so new settings take effect immediately.
        from app.utils.oci_manager import reset_oci_manager

        reset_oci_manager()
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

    return jsonify({"success": True})


@bp.route("/api/oci/test", methods=["POST"])
@login_required
def oci_test_api():
    """Test OCI API connectivity + permissions to read security lists."""
    try:
        from app.utils.oci_manager import get_oci_manager, reset_oci_manager

        # Important in multi-worker gunicorn: ensure this process reloads latest saved config.
        reset_oci_manager()
        mgr = get_oci_manager()

        missing = []
        has_config = bool(getattr(mgr, "config", None))
        has_network_client = bool(getattr(mgr, "network_client", None))
        compartment_id = getattr(mgr, "compartment_id", None)
        vcn_id = getattr(mgr, "vcn_id", None)
        region = None
        key_file = None
        key_file_exists = None
        config_source = None
        last_error = getattr(mgr, "last_error", None)

        # Inspect expected config paths on THIS server/process.
        instance_cfg_path = Path(current_app.instance_path) / "oci_config.json"
        home_cfg_path = Path.home() / ".oci" / "config"
        instance_cfg_exists = instance_cfg_path.exists()
        home_cfg_exists = home_cfg_path.exists()
        instance_cfg_summary = None
        try:
            if instance_cfg_exists:
                with open(instance_cfg_path, "r") as f:
                    raw_cfg = json.load(f) or {}
                instance_cfg_summary = {
                    "has_user": bool(raw_cfg.get("user")),
                    "has_tenancy": bool(raw_cfg.get("tenancy")),
                    "has_fingerprint": bool(raw_cfg.get("fingerprint")),
                    "region": raw_cfg.get("region"),
                    "key_file": raw_cfg.get("key_file"),
                    "has_compartment_id": bool(raw_cfg.get("compartment_id")),
                    "has_vcn_id": bool(raw_cfg.get("vcn_id")),
                }
        except Exception as e:
            instance_cfg_summary = {"error": str(e)}

        try:
            if mgr.config:
                region = mgr.config.get("region")
                key_file = mgr.config.get("key_file")
                if key_file:
                    key_file_exists = os.path.exists(os.path.expanduser(key_file))
                config_source = getattr(mgr, "config_source", None)
        except Exception:
            pass

        if not has_config:
            missing.append("OCI auth config not loaded (instance/oci_config.json or ~/.oci/config)")
        if not has_network_client:
            missing.append("OCI network client not initialized (check credentials, region, key file, fingerprint)")
        if not compartment_id:
            missing.append("compartment_id missing (set it on this page)")
        if not vcn_id:
            missing.append("vcn_id missing (set it on this page)")
        if key_file and key_file_exists is False:
            missing.append(f"key_file not found on disk: {key_file}")

        result = {
            "success": True,
            "oci_configured": mgr.is_configured(),
            "has_config": has_config,
            "has_network_client": has_network_client,
            "config_source": config_source,
            "last_error": last_error,
            "process_user": os.environ.get("USER") or os.environ.get("USERNAME") or None,
            "home_dir": str(Path.home()),
            "instance_path": str(current_app.instance_path),
            "instance_cfg_path": str(instance_cfg_path),
            "instance_cfg_exists": instance_cfg_exists,
            "instance_cfg_summary": instance_cfg_summary,
            "home_cfg_path": str(home_cfg_path),
            "home_cfg_exists": home_cfg_exists,
            "region": region,
            "key_file": key_file,
            "key_file_exists": key_file_exists,
            "compartment_id": compartment_id,
            "vcn_id": vcn_id,
            "security_lists_count": None,
            "default_security_list_id": None,
            "missing": missing,
            "note": "If your instance uses an NSG, security-list rules alone may not open the port. You may also need NSG ingress rules.",
        }

        # If we have enough to attempt listing, do it even if mgr.is_configured() is false for some reason.
        if has_network_client and compartment_id and vcn_id:
            try:
                sls = mgr.get_security_lists(compartment_id, vcn_id)
                result["security_lists_count"] = len(sls)
                result["default_security_list_id"] = mgr.get_default_security_list(compartment_id, vcn_id)
            except Exception as e:
                result["note"] = f"OCI client initialized, but listing security lists failed: {e}"

        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

