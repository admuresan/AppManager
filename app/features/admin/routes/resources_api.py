"""
Admin system resource/statistics API routes.

IMPORTANT: Read `instructions/architecture` before making changes.
"""

import os
import subprocess

from flask import current_app, jsonify
from flask_login import login_required

from app.models.app_config import AppConfig

from ..blueprint import bp


# Simple in-memory cache for resource stats (to minimize server load)
_resource_cache = {"data": None, "timestamp": 0, "ttl": 5}  # cache for 5 seconds


def _get_appmanager_pid():
    """Get AppManager's process ID."""
    try:
        import psutil

        from app.utils.app_manager import _get_pid_by_port

        for port in [5000, 80, 443]:
            pid = _get_pid_by_port(port)
            if pid:
                try:
                    proc = psutil.Process(pid)
                    proc_name = proc.name().lower()
                    cmdline = " ".join(proc.cmdline()).lower()
                    if "python" in proc_name and ("appmanager" in cmdline or "app.py" in cmdline or "run.py" in cmdline):
                        return pid
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        return os.getpid()
    except Exception:
        try:
            return os.getpid()
        except Exception:
            return None


def _get_directory_size(path):
    """Get the total size of a directory in bytes."""
    try:
        total_size = 0
        if not os.path.exists(path):
            return 0

        if os.path.isfile(path):
            return os.path.getsize(path)

        for dirpath, _dirnames, filenames in os.walk(path):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                try:
                    total_size += os.path.getsize(filepath)
                except (OSError, PermissionError, FileNotFoundError):
                    continue

        return total_size
    except (OSError, PermissionError, FileNotFoundError):
        return 0


def _get_process_tree_resources(pid):
    """Get memory and CPU usage for a process and all its children."""
    try:
        import psutil

        total_memory = 0
        total_cpu = 0

        try:
            proc = psutil.Process(pid)
            mem_info = proc.memory_info()
            total_memory += mem_info.rss

            total_cpu += proc.cpu_percent(interval=None) or 0

            for child in proc.children(recursive=True):
                try:
                    child_mem = child.memory_info()
                    total_memory += child_mem.rss
                    total_cpu += child.cpu_percent(interval=None) or 0
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        return {"memory_bytes": total_memory, "memory_gb": round(total_memory / (1024**3), 3), "cpu_percent": round(total_cpu, 2)}
    except Exception:
        return {"memory_bytes": 0, "memory_gb": 0, "cpu_percent": 0}


def _get_app_process_pids(app_config):
    """Get all PIDs associated with an app (by port or service)."""
    import psutil

    from app.utils.app_manager import _get_pid_by_port

    pids = set()
    port = app_config.get("port")
    service_name = app_config.get("service_name")

    if port:
        pid = _get_pid_by_port(port)
        if pid:
            pids.add(pid)

    if service_name:
        try:
            result = subprocess.run(
                ["systemctl", "show", service_name, "--property=MainPID", "--value"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            if result.returncode == 0:
                pid_str = result.stdout.strip()
                if pid_str and pid_str.isdigit():
                    pids.add(int(pid_str))
        except Exception:
            pass

    if port:
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.laddr.port == port and conn.status == "LISTEN" and conn.pid:
                    pids.add(conn.pid)
        except Exception:
            pass

    return list(pids)


@bp.route("/api/opt-folders", methods=["GET"])
@login_required
def get_opt_folders():
    """Get list of folders in /opt directory."""
    try:
        from pathlib import Path

        opt_path = Path("/opt")
        folders = []

        if opt_path.exists() and opt_path.is_dir():
            for item in opt_path.iterdir():
                if item.is_dir():
                    if not item.name.startswith(".") and item.name not in ["lost+found"]:
                        folders.append(item.name)

        folders.sort()
        return jsonify({"success": True, "folders": folders})
    except Exception as e:
        current_app.logger.error(f"Error listing /opt folders: {str(e)}", exc_info=True)
        return jsonify({"success": False, "error": str(e), "folders": []}), 500


@bp.route("/api/resources", methods=["GET"])
@login_required
def get_resource_stats():
    """Get system resource statistics (memory, disk, network). Uses caching to minimize server load."""
    import time

    current_time = time.time()
    if _resource_cache["data"] is not None and current_time - _resource_cache["timestamp"] < _resource_cache["ttl"]:
        cached_data = _resource_cache["data"].copy()
        cached_data["cached"] = True
        return jsonify(cached_data)

    try:
        import psutil

        memory = psutil.virtual_memory()
        memory_stats = {
            "total_gb": round(memory.total / (1024**3), 2),
            "available_gb": round(memory.available / (1024**3), 2),
            "used_gb": round(memory.used / (1024**3), 2),
            "percent": memory.percent,
            "free_gb": round(memory.free / (1024**3), 2),
        }

        disk = psutil.disk_usage("/")
        disk_stats = {
            "total_gb": round(disk.total / (1024**3), 2),
            "used_gb": round(disk.used / (1024**3), 2),
            "free_gb": round(disk.free / (1024**3), 2),
            "percent": round((disk.used / disk.total) * 100, 2),
        }

        net_io = psutil.net_io_counters()
        network_stats = {
            "bytes_sent": net_io.bytes_sent,
            "bytes_recv": net_io.bytes_recv,
            "packets_sent": net_io.packets_sent,
            "packets_recv": net_io.packets_recv,
            "bytes_sent_gb": round(net_io.bytes_sent / (1024**3), 2),
            "bytes_recv_gb": round(net_io.bytes_recv / (1024**3), 2),
            "errors_in": net_io.errin,
            "errors_out": net_io.errout,
            "drops_in": net_io.dropin,
            "drops_out": net_io.dropout,
        }

        cpu_percent = psutil.cpu_percent(interval=None)
        cpu_stats = {"percent": cpu_percent if cpu_percent > 0 else 0, "count": psutil.cpu_count()}

        app_resources = []
        apps = AppConfig.get_all()
        total_app_memory = 0
        total_app_cpu = 0
        appmanager_memory = 0
        appmanager_cpu = 0

        appmanager_pid = _get_appmanager_pid()
        if appmanager_pid:
            appmanager_resources = _get_process_tree_resources(appmanager_pid)
            appmanager_memory = appmanager_resources["memory_bytes"]
            appmanager_cpu = appmanager_resources["cpu_percent"]

        for app in apps:
            app_pids = _get_app_process_pids(app)
            if app_pids:
                app_memory_bytes = 0
                app_cpu_percent = 0

                for pid in app_pids:
                    resources = _get_process_tree_resources(pid)
                    app_memory_bytes += resources["memory_bytes"]
                    app_cpu_percent += resources["cpu_percent"]

                app_memory_gb = round(app_memory_bytes / (1024**3), 3)
                app_memory_percent = round((app_memory_bytes / memory.total) * 100, 2) if memory.total > 0 else 0

                total_app_memory += app_memory_bytes
                total_app_cpu += app_cpu_percent

                folder_path = app.get("folder_path")
                if folder_path:
                    app_disk_path = f"/opt/{folder_path}"
                else:
                    app_name = app.get("name", "").lower().replace(" ", "-")
                    app_disk_path = f"/opt/{app_name}"
                app_disk_bytes = _get_directory_size(app_disk_path)
                app_disk_gb = round(app_disk_bytes / (1024**3), 3)

                app_resources.append(
                    {
                        "app_id": app.get("id"),
                        "app_name": app.get("name"),
                        "port": app.get("port"),
                        "memory_gb": app_memory_gb,
                        "memory_percent": app_memory_percent,
                        "cpu_percent": round(app_cpu_percent, 2),
                        "disk_gb": app_disk_gb,
                        "disk_percent": round((app_disk_bytes / disk.total) * 100, 3) if disk.total > 0 else 0,
                        "pids": app_pids,
                    }
                )

        appmanager_disk_path = "/opt/appmanager"
        appmanager_disk_bytes = _get_directory_size(appmanager_disk_path)
        appmanager_disk_gb = round(appmanager_disk_bytes / (1024**3), 2)

        total_app_memory_gb = round(total_app_memory / (1024**3), 2)
        appmanager_memory_gb = round(appmanager_memory / (1024**3), 2)
        system_memory_gb = round(memory.total / (1024**3) * 0.1, 2)
        other_memory_gb = round((memory.used - total_app_memory - appmanager_memory) / (1024**3), 2)
        other_memory_gb = max(0, other_memory_gb - system_memory_gb)

        total_app_disk = sum(r.get("disk_gb", 0) * (1024**3) for r in app_resources)
        other_disk_bytes = disk.used - total_app_disk - appmanager_disk_bytes
        other_disk_gb = round(max(0, other_disk_bytes) / (1024**3), 2)

        result = {
            "success": True,
            "memory": memory_stats,
            "disk": disk_stats,
            "network": network_stats,
            "cpu": cpu_stats,
            "timestamp": time.time(),
            "cached": False,
            "apps": app_resources,
            "appmanager": {
                "memory_gb": appmanager_memory_gb,
                "memory_percent": round((appmanager_memory / memory.total) * 100, 2) if memory.total > 0 else 0,
                "cpu_percent": round(appmanager_cpu, 2),
                "disk_gb": appmanager_disk_gb,
                "disk_percent": round((appmanager_disk_bytes / disk.total) * 100, 2) if disk.total > 0 else 0,
            },
            "breakdown": {
                "apps": {
                    "memory_gb": total_app_memory_gb,
                    "memory_percent": round((total_app_memory / memory.total) * 100, 2) if memory.total > 0 else 0,
                    "cpu_percent": round(total_app_cpu, 2),
                },
                "system": {
                    "memory_gb": system_memory_gb,
                    "memory_percent": round((system_memory_gb * 1024**3 / memory.total) * 100, 2) if memory.total > 0 else 0,
                    "cpu_percent": round(max(0, cpu_percent - total_app_cpu - appmanager_cpu), 2),
                },
                "other": {
                    "memory_gb": other_memory_gb,
                    "memory_percent": round((other_memory_gb * 1024**3 / memory.total) * 100, 2) if memory.total > 0 else 0,
                    "cpu_percent": 0,
                    "disk_gb": other_disk_gb,
                    "disk_percent": round((other_disk_bytes / disk.total) * 100, 2) if disk.total > 0 else 0,
                },
            },
        }

        _resource_cache["data"] = result.copy()
        _resource_cache["timestamp"] = current_time

        return jsonify(result)
    except Exception as e:
        current_app.logger.error(f"Error getting resource stats: {str(e)}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500

