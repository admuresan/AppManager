"""
Port configuration utilities (UFW + OCI).

IMPORTANT: Read `instructions/architecture` before making changes.
"""

from __future__ import annotations

import os
import platform
import subprocess


def is_server_environment() -> bool:
    """Check if running on a Linux server environment where UFW is expected to work."""
    # Check if we're in development mode
    if os.environ.get("FLASK_ENV") == "development":
        return False

    # Check if running on Windows (no ufw support)
    if platform.system() != "Linux":
        return False

    # Check if ufw is available
    try:
        result = subprocess.run(["which", "ufw"], capture_output=True, timeout=2)
        if result.returncode != 0:
            return False
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

    return True


def configure_firewall_port_detailed(port: int, action: str = "allow") -> dict:
    """
    Configure firewall rules for a port using UFW and OCI security lists, returning structured detail.

    Returns:
        dict with keys:
          - port, action
          - ufw: {attempted, success, action, command, message, stdout, stderr}
          - oci: {attempted, configured, success, action, message, error}
          - overall_success
          - messages (list[str]) and combined_message (str)
    """
    messages: list[str] = []
    ufw = {
        "attempted": False,
        "success": True,
        "action": "skipped",
        "command": None,
        "message": None,
        "stdout": None,
        "stderr": None,
    }
    oci = {
        "attempted": False,
        "configured": False,
        "success": True,
        "action": "skipped",
        "message": None,
        "error": None,
    }

    ufw_success = True
    oci_success = True

    # --- UFW ---
    if is_server_environment():
        ufw["attempted"] = True
        try:
            if action == "allow":
                # Check if rule already exists
                status_cmd = ["sudo", "ufw", "status", "numbered"]
                status = subprocess.run(status_cmd, capture_output=True, text=True, timeout=5)
                ufw["command"] = " ".join(status_cmd)
                ufw["stdout"] = status.stdout
                ufw["stderr"] = status.stderr

                if str(port) in (status.stdout or ""):
                    ufw["action"] = "already_allowed"
                    ufw["success"] = True
                    ufw["message"] = f"Port {port} already allowed in UFW"
                    messages.append(f"UFW: already allowed ({port}/tcp)")
                else:
                    allow_cmd = ["sudo", "ufw", "allow", f"{port}/tcp"]
                    result = subprocess.run(allow_cmd, capture_output=True, text=True, timeout=10)
                    ufw["command"] = " ".join(allow_cmd)
                    ufw["stdout"] = result.stdout
                    ufw["stderr"] = result.stderr
                    if result.returncode == 0:
                        ufw["action"] = "rule_added"
                        ufw["success"] = True
                        ufw["message"] = f"Added UFW rule: allow {port}/tcp"
                        messages.append(f"UFW: rule added (allow {port}/tcp)")
                    else:
                        ufw_success = False
                        ufw["action"] = "failed"
                        ufw["success"] = False
                        ufw["message"] = f"Failed to add UFW rule for {port}/tcp"
                        messages.append(f"UFW: failed to add rule (allow {port}/tcp): {result.stderr}".strip())

            elif action == "delete":
                delete_cmd = ["sudo", "ufw", "delete", "allow", f"{port}/tcp"]
                result = subprocess.run(delete_cmd, capture_output=True, text=True, timeout=10)
                ufw["command"] = " ".join(delete_cmd)
                ufw["stdout"] = result.stdout
                ufw["stderr"] = result.stderr
                if result.returncode == 0:
                    ufw["action"] = "rule_removed"
                    ufw["success"] = True
                    ufw["message"] = f"Removed UFW rule: allow {port}/tcp"
                    messages.append(f"UFW: rule removed (allow {port}/tcp)")
                else:
                    # Non-fatal: rule might not exist
                    ufw["action"] = "not_found"
                    ufw["success"] = True
                    ufw["message"] = f"UFW rule not found for {port}/tcp"
                    messages.append(f"UFW: rule not found (allow {port}/tcp)")

            else:
                ufw_success = False
                ufw["action"] = "invalid_action"
                ufw["success"] = False
                ufw["message"] = f"Unknown action: {action}"
                messages.append(f"UFW: unknown action {action}")

        except subprocess.TimeoutExpired:
            ufw_success = False
            ufw["action"] = "timeout"
            ufw["success"] = False
            ufw["message"] = "UFW command timed out"
            messages.append("UFW: command timed out")
        except FileNotFoundError:
            ufw_success = False
            ufw["action"] = "not_available"
            ufw["success"] = False
            ufw["message"] = "ufw command not found"
            messages.append("UFW: ufw command not found")
        except Exception as e:
            ufw_success = False
            ufw["action"] = "error"
            ufw["success"] = False
            ufw["message"] = f"Error configuring UFW: {str(e)}"
            messages.append(f"UFW: error: {str(e)}")
    else:
        ufw["attempted"] = False
        ufw["action"] = "skipped"
        ufw["success"] = True
        ufw["message"] = "Skipped UFW (not server environment)"
        messages.append("UFW: skipped (not server environment)")

    # --- OCI ---
    try:
        from app.utils.oci_manager import configure_oci_port, is_oci_configured

        if is_oci_configured():
            oci["attempted"] = True
            oci["configured"] = True
            oci_success, oci_message = configure_oci_port(port, action)
            oci["success"] = bool(oci_success)
            oci["message"] = oci_message
            oci["action"] = "updated" if oci_success else "failed"
            messages.append(f"OCI: {oci_message}")
        else:
            oci["attempted"] = False
            oci["configured"] = False
            oci["success"] = True
            oci["action"] = "skipped"
            oci["message"] = "OCI not configured"
            messages.append("OCI: skipped (not configured)")
    except ImportError:
        oci["attempted"] = False
        oci["configured"] = False
        oci["success"] = True
        oci["action"] = "skipped"
        oci["message"] = "OCI SDK not available"
        messages.append("OCI: skipped (SDK not available)")
    except Exception as e:
        oci_success = False
        oci["attempted"] = True
        oci["configured"] = True
        oci["success"] = False
        oci["action"] = "error"
        oci["error"] = str(e)
        oci["message"] = f"OCI error: {str(e)}"
        messages.append(f"OCI: error: {str(e)}")

    overall_success = bool(ufw_success or oci_success)
    combined_message = "; ".join(messages)

    return {
        "port": port,
        "action": action,
        "ufw": ufw,
        "oci": oci,
        "overall_success": overall_success,
        "messages": messages,
        "combined_message": combined_message,
    }


def configure_firewall_port(port: int, action: str = "allow"):
    """
    Configure firewall rules for a port using UFW and OCI security lists.

    Returns:
        tuple: (success: bool, message: str)
    """
    detail = configure_firewall_port_detailed(port=port, action=action)
    return bool(detail.get("overall_success")), str(detail.get("combined_message") or "")

