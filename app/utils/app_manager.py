"""
Utility functions for managing apps.

IMPORTANT: Read `instructions/architecture` before making changes.
"""
import os
import platform
import re
import socket
import subprocess
import time
from pathlib import Path

import psutil

def _log_startup_step(step: str):
    """Log startup step so it appears in terminal and AppManager log file."""
    import sys
    print(f"[AppManager] {step}", flush=True, file=sys.stderr)


def test_app_port(port):
    """Test if an app is listening on a specific port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('localhost', port))
        sock.close()
        return result == 0
    except:
        return False

def check_port_status(port):
    """
    Check detailed status of a specific port.
    Returns a dict with listening status, PID, service name, and process name.
    """
    result = {
        'port': port,
        'is_listening': False,
        'pid': None,
        'service_name': None,
        'process_name': None,
        'detection_method': None
    }
    
    # First, test if port is listening via socket
    result['is_listening'] = test_app_port(port)
    
    # Try to get PID using _get_pid_by_port
    pid = _get_pid_by_port(port)
    if pid:
        result['pid'] = pid
        result['detection_method'] = 'pid_detection'
        
        # Try to get service name from PID
        service_name = _get_service_by_pid(pid)
        if service_name:
            result['service_name'] = service_name
        
        # Get process name
        try:
            proc = psutil.Process(pid)
            result['process_name'] = proc.name()
        except:
            pass
    
    # If no PID found but port is listening, try service detection by port
    if not result['pid'] and result['is_listening']:
        service_name = detect_service_name_by_port(port)
        if service_name:
            result['service_name'] = service_name
            result['detection_method'] = 'service_detection'
    
    # Also check using psutil directly
    if not result['pid']:
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr.port == port and conn.status == 'LISTEN':
                    if conn.pid:
                        result['pid'] = conn.pid
                        result['detection_method'] = 'psutil'
                        try:
                            proc = psutil.Process(conn.pid)
                            result['process_name'] = proc.name()
                        except:
                            pass
                        break
        except:
            pass
    
    return result

def _find_venv_python(app_path: Path, venv_name: str = None) -> Path:
    """Find Python executable in a venv. Returns Path or None."""
    if platform.system() == "Windows":
        candidates = [venv_name] if venv_name else ['venv', '.venv', 'env']
        for name in candidates:
            py_path = app_path / name / 'Scripts' / 'python.exe'
            if py_path.exists():
                return py_path
    else:
        # Linux: venv/bin/python
        candidates = [venv_name] if venv_name else ['venv', '.venv', 'env']
        for name in candidates:
            py_path = app_path / name / 'bin' / 'python'
            if py_path.exists():
                return py_path
        # Also check *_venv pattern
        if app_path.is_dir():
            for item in app_path.iterdir():
                if item.is_dir() and (item.name.endswith('_venv') or item.name.endswith('venv')):
                    py_path = item / 'bin' / 'python'
                    if py_path.exists():
                        return py_path
    return None


def _venv_requirements_match(app_path: Path, venv_dir: Path) -> bool:
    """Check if venv's installed requirements match app's requirements.txt."""
    app_req = app_path / 'requirements.txt'
    if not app_req.exists():
        return True  # No requirements to compare
    venv_req = venv_dir / 'requirements.txt'
    if not venv_req.exists():
        venv_req = venv_dir / 'requirements_installed.txt'
    if not venv_req.exists():
        return False
    try:
        return open(app_req, 'rb').read() == open(venv_req, 'rb').read()
    except Exception:
        return False


def _ensure_venv_and_deps(app_path: Path, venv_name: str = None) -> tuple:
    """
    Ensure a virtual environment exists and dependencies are installed.
    Returns (python_exe_path, message) - path is None on failure.
    """
    if platform.system() != 'Windows':
        return None, "Only supported on Windows"

    # 1. Find existing venv
    py_path = _find_venv_python(app_path, venv_name)
    created = False

    if not py_path:
        # 2. Create venv (use 'venv' as default folder name)
        _log_startup_step("Creating venv...")
        target_name = venv_name or 'venv'
        venv_dir = app_path / target_name
        try:
            # Prefer py -m venv (Python launcher) then python -m venv
            for cmd in [['py', '-3', '-m', 'venv', target_name], ['python', '-m', 'venv', target_name]]:
                result = subprocess.run(
                    cmd,
                    cwd=str(app_path),
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                if result.returncode == 0:
                    created = True
                    py_path = _find_venv_python(app_path, target_name)
                    if py_path:
                        break
        except subprocess.TimeoutExpired:
            return None, "Virtual environment creation timed out"
        except Exception as e:
            return None, f"Failed to create venv: {e}"

        if not py_path:
            return None, "Virtual environment was created but python.exe not found"

    # 3. Install requirements if present
    req_files = [app_path / 'requirements.txt', app_path / 'app' / 'requirements.txt']
    for req_file in req_files:
        if req_file.exists():
            _log_startup_step("Installing requirements...")
            try:
                subprocess.run(
                    [str(py_path), '-m', 'pip', 'install', '-r', str(req_file), '-q'],
                    cwd=str(app_path),
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
            except subprocess.TimeoutExpired:
                pass  # Non-fatal; app might still run
            except Exception:
                pass  # Non-fatal
            break

    return py_path, "Venv ready" if created else "Using existing venv"


def _ensure_venv_and_deps_linux(app_path: Path, venv_name: str = None) -> tuple:
    """
    Ensure a virtual environment exists on Linux, deps match requirements.txt.
    If no venv or requirements mismatch: create venv, install deps, copy requirements.txt into venv.
    Returns (python_exe_path, message) - path is None on failure.
    """
    if platform.system() != 'Linux':
        return None, "Only supported on Linux"

    py_path = _find_venv_python(app_path, venv_name)
    venv_dir = py_path.parent.parent if py_path else None
    recreate = False

    if py_path and venv_dir:
        if not _venv_requirements_match(app_path, venv_dir):
            recreate = True
    else:
        recreate = True

    if recreate:
        _log_startup_step("No venv or requirements mismatch; creating venv and installing requirements...")
    else:
        _log_startup_step("Found venv with matching requirements.")

    if recreate:
        _log_startup_step("Creating venv...")
        # Remove old venv if exists
        for name in ['venv', '.venv', 'env']:
            vd = app_path / name
            if vd.exists():
                try:
                    import shutil
                    shutil.rmtree(vd)
                except Exception:
                    pass
                break
        # Create venv
        target_name = venv_name or 'venv'
        try:
            for cmd in [['python3', '-m', 'venv', target_name], ['python', '-m', 'venv', target_name]]:
                r = subprocess.run(cmd, cwd=str(app_path), capture_output=True, text=True, timeout=120)
                if r.returncode == 0:
                    py_path = _find_venv_python(app_path, target_name)
                    venv_dir = app_path / target_name
                    break
        except subprocess.TimeoutExpired:
            return None, "Virtual environment creation timed out"
        except Exception as e:
            return None, f"Failed to create venv: {e}"

        if not py_path:
            return None, "Virtual environment was created but python not found"

        # Install requirements
        req_file = app_path / 'requirements.txt'
        if not req_file.exists():
            req_file = app_path / 'app' / 'requirements.txt'
        if req_file.exists():
            _log_startup_step("Installing requirements...")
            try:
                subprocess.run(
                    [str(py_path), '-m', 'pip', 'install', '-r', str(req_file), '-q'],
                    cwd=str(app_path),
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                pass
        # Copy requirements.txt into venv folder
        src_req = app_path / 'requirements.txt'
        if src_req.exists():
            try:
                import shutil
                shutil.copy(src_req, venv_dir / 'requirements.txt')
            except Exception:
                pass

    return py_path, "Venv ready" if recreate else "Using existing venv"


def start_app_linux(
    folder_path: str,
    start_command: str = "python app.py",
    port: int = None,
    app_id: str = None,
    instance_path: str = None,
) -> tuple:
    """
    Start an app in the background on Linux.
    Checks for venv, creates/updates if requirements mismatch, then launches with FLASK_ENV=production.
    If app_id and instance_path are provided, stdout/stderr are captured to instance/logs/apps/{app_id}.log.
    """
    if platform.system() != 'Linux':
        return False, "Linux start is only available on Linux"

    folder_path = (folder_path or "").strip()
    if not folder_path:
        return False, "App folder path is not configured for this app"

    path = Path(folder_path)
    if not path.exists():
        return False, f"Folder does not exist: {folder_path}"
    if not path.is_dir():
        return False, f"Path is not a directory: {folder_path}"

    start_command = (start_command or "python app.py").strip()
    if not start_command:
        return False, "Start command is empty"

    py_path, venv_msg = _ensure_venv_and_deps_linux(path, venv_name=None)
    if py_path is None:
        return False, venv_msg

    _log_startup_step("Running app.py...")
    venv_bin = str(py_path.parent)
    venv_root = str(py_path.parent.parent)
    env = {
        'PATH': venv_bin,
        'VIRTUAL_ENV': venv_root,
        'FLASK_ENV': 'production',
    }
    if port is not None:
        env['PORT'] = str(port)
        env['SERVER_PORT'] = str(port)
    if 'HOME' in os.environ:
        env['HOME'] = os.environ['HOME']

    # Resolve command: use venv python with -u for unbuffered (real-time) logs
    if start_command.strip().startswith('python ') or start_command.strip().startswith('python3 '):
        rest = start_command.split()[1:]
        cmd_args = [str(py_path), '-u'] + rest
    else:
        cmd_args = ['/bin/sh', '-c', start_command]

    stdout_err = subprocess.DEVNULL
    stderr_err = subprocess.DEVNULL
    opened_log = None
    if app_id and instance_path:
        logs_dir = Path(instance_path) / "logs" / "apps"
        logs_dir.mkdir(parents=True, exist_ok=True)
        log_path = logs_dir / f"{app_id}.log"
        try:
            opened_log = open(log_path, "a", encoding="utf-8")
            opened_log.write(f"[AppManager] Starting process at {time.strftime('%Y-%m-%d %H:%M:%S')} ...\n")
            opened_log.flush()
            stdout_err = opened_log
            stderr_err = subprocess.STDOUT
        except Exception:
            pass

    try:
        if len(cmd_args) == 1:
            proc = subprocess.Popen(
                cmd_args,
                cwd=str(path.resolve()),
                env=env,
                stdout=stdout_err,
                stderr=stderr_err,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
        else:
            proc = subprocess.Popen(
                cmd_args,
                cwd=str(path.resolve()),
                env=env,
                stdout=stdout_err,
                stderr=stderr_err,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
        if opened_log:
            try:
                opened_log.write(f"[AppManager] Process started (PID: {proc.pid})\n")
                opened_log.flush()
            except Exception:
                pass
            opened_log.close()

        if port is not None:
            for attempt in range(4):
                time.sleep(2)
                if test_app_port(port):
                    _log_startup_step("Port is listening.")
                    return True, f"App started (PID: {proc.pid}, port {port} ready)"
            _log_startup_step("Port did not come up within 8s.")
            return False, "App process started but port did not come up within 8 seconds"
        return True, f"App started in background (PID: {proc.pid})"
    except Exception as e:
        return False, f"Failed to start app: {str(e)}"


def start_app_windows(
    folder_path: str,
    start_command: str = "python app.py",
    port: int = None,
    app_id: str = None,
    instance_path: str = None,
) -> tuple:
    """
    Start an app in the background on Windows.
    Ensures a virtual environment exists (creates one if not), installs requirements.txt if present,
    then runs the start_command in the given folder_path as a detached process.
    If app_id and instance_path are provided, stdout/stderr are captured to instance/logs/apps/{app_id}.log.

    Returns:
        Tuple of (success: bool, message: str)
    """
    if platform.system() != 'Windows':
        return False, "Windows start is only available on Windows"

    folder_path = (folder_path or "").strip()
    if not folder_path:
        return False, "Windows path is not configured for this app"

    path = Path(folder_path)
    if not path.exists():
        return False, f"Folder does not exist: {folder_path}"
    if not path.is_dir():
        return False, f"Path is not a directory: {folder_path}"

    start_command = (start_command or "python app.py").strip()
    if not start_command:
        return False, "Start command is empty"

    _log_startup_step("Checking venv and dependencies...")
    py_path, venv_msg = _ensure_venv_and_deps(path, venv_name=None)
    if py_path is None:
        return False, venv_msg

    _log_startup_step("Running app.py...")
    scripts_dir = py_path.parent
    env = {
        'PATH': str(scripts_dir),
        'VIRTUAL_ENV': str(scripts_dir.parent),
        'FLASK_ENV': 'production',
    }
    if port is not None:
        env['PORT'] = str(port)
        env['SERVER_PORT'] = str(port)
    if 'HOME' in os.environ:
        env['HOME'] = os.environ['HOME']
    if 'SYSTEMROOT' in os.environ:
        env['SYSTEMROOT'] = os.environ['SYSTEMROOT']

    # Use -u for unbuffered (real-time) logs
    run_cmd = start_command.strip()
    if run_cmd.startswith('python ') or run_cmd.startswith('python3 '):
        parts = run_cmd.split(None, 1)
        run_cmd = parts[0] + ' -u ' + (parts[1] if len(parts) > 1 else '')

    stdout_err = subprocess.DEVNULL
    stderr_err = subprocess.DEVNULL
    opened_log = None
    if app_id and instance_path:
        logs_dir = Path(instance_path) / "logs" / "apps"
        logs_dir.mkdir(parents=True, exist_ok=True)
        log_path = logs_dir / f"{app_id}.log"
        try:
            opened_log = open(log_path, "a", encoding="utf-8")
            opened_log.write(f"[AppManager] Starting process at {time.strftime('%Y-%m-%d %H:%M:%S')} ...\n")
            opened_log.flush()
            stdout_err = opened_log
            stderr_err = subprocess.STDOUT
        except Exception:
            pass

    try:
        creation_flags = 0
        if hasattr(subprocess, 'CREATE_NO_WINDOW'):
            creation_flags = subprocess.CREATE_NO_WINDOW
        elif hasattr(subprocess, 'DETACHED_PROCESS'):
            creation_flags = subprocess.DETACHED_PROCESS

        proc = subprocess.Popen(
            run_cmd,
            cwd=str(path.resolve()),
            shell=True,
            env=env,
            stdout=stdout_err,
            stderr=stderr_err,
            stdin=subprocess.DEVNULL,
            creationflags=creation_flags,
        )
        if opened_log:
            try:
                opened_log.write(f"[AppManager] Process started (PID: {proc.pid})\n")
                opened_log.flush()
            except Exception:
                pass
            opened_log.close()

        if port is not None:
            for attempt in range(4):
                time.sleep(2)
                if test_app_port(port):
                    _log_startup_step("Port is listening.")
                    return True, f"App started (PID: {proc.pid}, port {port} ready)"
            _log_startup_step("Port did not come up within 8s.")
            return False, "App process started but port did not come up within 8 seconds"
        return True, f"App started in background (PID: {proc.pid})"
    except Exception as e:
        return False, f"Failed to start app: {str(e)}"


def detect_service_name_by_port(port):
    """
    Detect systemd service name by checking which service is using the given port.
    Returns the service name if found, None otherwise.
    """
    # Only works on Linux with systemd
    if os.name == 'nt':  # Windows
        return None
    
    try:
        # Method 1: Use systemctl to find services and check their environment/exec
        # List all active services
        result = subprocess.run(
            ['systemctl', 'list-units', '--type=service', '--state=running', '--no-pager', '--no-legend'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            services = result.stdout.strip().split('\n')
            for service_line in services:
                if not service_line.strip():
                    continue
                # Extract service name (first field)
                service_name = service_line.split()[0]
                
                # Check if this service is listening on our port
                if _service_uses_port(service_name, port):
                    return service_name
        
        # Method 2: Find process using the port, then find its systemd service
        process_pid = _get_pid_by_port(port)
        if process_pid:
            service_name = _get_service_by_pid(process_pid)
            if service_name:
                return service_name
        
        return None
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        # systemctl not available or error occurred
        return None

def _service_uses_port(service_name, port):
    """Check if a systemd service is using a specific port"""
    try:
        # Get service status and check environment/exec for port
        result = subprocess.run(
            ['systemctl', 'show', service_name, '--property=Environment,ExecStart'],
            capture_output=True,
            text=True,
            timeout=3
        )
        
        if result.returncode == 0:
            output = result.stdout.lower()
            # Check if port is mentioned in environment or exec command
            if f'port={port}' in output or f':{port}' in output or f' {port}' in output:
                return True
        
        # Also check if the service's process is using the port
        try:
            # Get main PID of the service
            pid_result = subprocess.run(
                ['systemctl', 'show', service_name, '--property=MainPID', '--value'],
                capture_output=True,
                text=True,
                timeout=3
            )
            if pid_result.returncode == 0:
                pid = pid_result.stdout.strip()
                if pid and pid.isdigit():
                    if _pid_uses_port(int(pid), port):
                        return True
        except:
            pass
        
        return False
    except:
        return False

def _get_pid_by_port(port):
    """Get process ID using a specific port"""
    try:
        # Try using ss (preferred on modern Linux)
        result = subprocess.run(
            ['ss', '-tlnp'],  # tcp, listen, numeric, process
            capture_output=True,
            text=True,
            timeout=3
        )
        
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if f':{port} ' in line or f':{port}\n' in line:
                    # Extract PID from line like: "LISTEN 0 128 *:5001 *:* users:(("python3",pid=12345,fd=3))"
                    match = re.search(r'pid=(\d+)', line)
                    if match:
                        return int(match.group(1))
        
        # Fallback to netstat
        result = subprocess.run(
            ['netstat', '-tlnp'],
            capture_output=True,
            text=True,
            timeout=3
        )
        
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if f':{port} ' in line:
                    # Extract PID from netstat output
                    parts = line.split()
                    if len(parts) > 6:
                        pid_program = parts[-1]
                        match = re.search(r'(\d+)/', pid_program)
                        if match:
                            return int(match.group(1))
        
        # Fallback to psutil
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr.port == port and conn.status == 'LISTEN':
                return conn.pid
        
        return None
    except:
        return None

def _pid_uses_port(pid, port):
    """Check if a specific PID is using a port"""
    try:
        for conn in psutil.Process(pid).connections(kind='inet'):
            if conn.laddr.port == port and conn.status == 'LISTEN':
                return True
        return False
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False

def _get_service_by_pid(pid):
    """Get systemd service name for a given PID"""
    try:
        # Use systemd-cgls or systemctl status to find service
        result = subprocess.run(
            ['systemctl', 'status', str(pid)],
            capture_output=True,
            text=True,
            timeout=3
        )
        
        if result.returncode == 0:
            # Look for service name in output
            for line in result.stdout.split('\n'):
                if '.service' in line.lower():
                    # Extract service name
                    match = re.search(r'([a-zA-Z0-9\-_]+\.service)', line)
                    if match:
                        return match.group(1)
        
        # Alternative: check /proc/PID/cgroup for systemd slice
        try:
            with open(f'/proc/{pid}/cgroup', 'r') as f:
                for line in f:
                    if 'systemd' in line:
                        # Extract service name from cgroup path
                        # Format: /system.slice/service-name.service
                        match = re.search(r'/([a-zA-Z0-9\-_]+\.service)', line)
                        if match:
                            return match.group(1)
        except:
            pass
        
        return None
    except:
        return None

def _should_exclude_port(port, service_name=None, process_name=None):
    """
    Determine if a port should be excluded from the active ports list.
    Excludes system ports, web server ports, and AppManager itself.
    """
    # Exclude AppManager port (5000)
    if port == 5000:
        return True
    
    # Exclude standard web server ports
    if port in (80, 443):
        return True
    
    # Exclude well-known system ports (0-1023)
    if port < 1024:
        return True
    
    # Exclude common system service names
    system_services = [
        'ssh', 'sshd', 'nginx', 'apache2', 'httpd', 'mysql', 'mysqld',
        'postgresql', 'postgres', 'redis', 'redis-server', 'mongod', 'mongodb',
        'systemd', 'systemd-resolved', 'systemd-networkd', 'dbus', 'NetworkManager',
        'cron', 'rsyslog', 'syslog', 'journald', 'logrotate', 'snapd',
        'ufw', 'firewalld', 'iptables', 'fail2ban', 'unattended-upgrades',
        'apparmor', 'polkit', 'gdm', 'lightdm', 'xrdp', 'vnc', 'tigervnc'
    ]
    
    if service_name:
        service_lower = service_name.lower()
        # Remove .service suffix if present
        if service_lower.endswith('.service'):
            service_lower = service_lower[:-8]
        if service_lower in system_services:
            return True
    
    if process_name:
        process_lower = process_name.lower()
        if process_lower in system_services:
            return True
    
    return False

def get_active_ports_and_services():
    """
    Get a list of all active ports on localhost and their associated service names.
    Returns a list of dicts with port, service_name, and pid.
    Excludes system ports, web server ports (80/443), and AppManager port (5000).
    """
    active_ports = []
    
    # Only works on Linux with systemd
    if os.name == 'nt':  # Windows
        # Fallback: just get ports using psutil
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN' and conn.laddr.ip in ('127.0.0.1', '0.0.0.0', '::', '::1'):
                    port = conn.laddr.port
                    pid = conn.pid
                    process_name = None
                    if pid:
                        try:
                            proc = psutil.Process(pid)
                            process_name = proc.name()
                        except:
                            pass
                    
                    # Filter out excluded ports
                    if not _should_exclude_port(port, process_name=process_name):
                        active_ports.append({
                            'port': port,
                            'service_name': None,
                            'pid': pid,
                            'process_name': process_name
                        })
        except:
            pass
        return active_ports
    
    try:
        # Get all listening ports
        ports_used = {}
        
        # Method 1: Use ss to get ports and PIDs (improved to include ports without PIDs)
        try:
            result = subprocess.run(
                ['ss', '-tlnp'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'LISTEN' in line:
                        # Parse line like: "LISTEN 0 128 *:5001 *:* users:(("python3",pid=12345,fd=3))"
                        # or: "LISTEN 0 128 *:6002 *:*"
                        port_match = re.search(r':(\d+)(\s|$)', line)
                        if port_match:
                            port = int(port_match.group(1))
                            # Try to extract PID, but don't require it
                            pid_match = re.search(r'pid=(\d+)', line)
                            pid = int(pid_match.group(1)) if pid_match else None
                            if port not in ports_used:
                                ports_used[port] = {'pid': pid}
        except:
            pass
        
        # Method 2: Use ss without -p flag to get all ports (including those without PID info)
        try:
            result = subprocess.run(
                ['ss', '-tln'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'LISTEN' in line:
                        port_match = re.search(r':(\d+)(\s|$)', line)
                        if port_match:
                            port = int(port_match.group(1))
                            # Only add if we haven't seen this port yet
                            if port not in ports_used:
                                ports_used[port] = {'pid': None}
        except:
            pass
        
        # Method 3: Use psutil as fallback (include ports even without PID)
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN' and conn.laddr.ip in ('127.0.0.1', '0.0.0.0', '::', '::1'):
                    port = conn.laddr.port
                    pid = conn.pid
                    if port not in ports_used:
                        ports_used[port] = {'pid': pid}
                    elif ports_used[port].get('pid') is None and pid:
                        # Update with PID if we found one
                        ports_used[port] = {'pid': pid}
        except:
            pass
        
        # For each port, try to find the service name
        for port, info in ports_used.items():
            # Skip excluded ports early
            if _should_exclude_port(port):
                continue
            
            pid = info.get('pid')
            service_name = None
            
            if pid:
                # Try to get service name from PID
                service_name = _get_service_by_pid(pid)
                
                # If not found, try detection by port
                if not service_name:
                    service_name = detect_service_name_by_port(port)
            else:
                # Even without PID, try to detect service by port
                service_name = detect_service_name_by_port(port)
            
            # Get process name if PID is available
            process_name = None
            if pid:
                try:
                    proc = psutil.Process(pid)
                    process_name = proc.name()
                except:
                    pass
            
            # Final check: exclude if service or process name indicates system service
            if _should_exclude_port(port, service_name=service_name, process_name=process_name):
                continue
            
            active_ports.append({
                'port': port,
                'service_name': service_name,
                'pid': pid,
                'process_name': process_name
            })
        
        # Sort by port number
        active_ports.sort(key=lambda x: x['port'])
        
    except Exception as e:
        pass
    
    return active_ports

def get_app_logs(service_name, lines=500, since=None, until=None):
    """
    Get logs from systemd journalctl for a given service.
    
    Args:
        service_name: Systemd service name (e.g., 'calculator.service')
        lines: Number of log lines to retrieve (default: 500)
        since: Start timestamp (ISO format or 'YYYY-MM-DD HH:MM:SS')
        until: End timestamp (ISO format or 'YYYY-MM-DD HH:MM:SS')
    
    Returns:
        tuple: (success: bool, logs: str or error message: str, oldest_timestamp: str or None, newest_timestamp: str or None)
    """
    # Only works on Linux with systemd
    if platform.system() != 'Linux':
        return False, "Logs are only available on Linux systems with systemd", None, None
    
    if not service_name:
        return False, "Service name is required to view logs", None, None
    
    try:
        # Build journalctl command (without sudo to avoid password prompts)
        cmd = ['journalctl', '-u', service_name, '--no-pager']
        
        if since:
            cmd.extend(['--since', since])
        if until:
            cmd.extend(['--until', until])
        
        if not since and not until:
            cmd.extend(['-n', str(lines)])
        else:
            cmd.extend(['-n', str(lines)])
        
        cmd.append('--output=short-iso')
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            logs = result.stdout
            oldest_ts, newest_ts = _extract_timestamps_from_logs(logs)
            return True, logs, oldest_ts, newest_ts
        else:
            error_msg = result.stderr.strip() if result.stderr else "Unknown error"
            if "Permission denied" in error_msg or "Access denied" in error_msg:
                return False, f"Permission denied. Add user to systemd-journal group: sudo usermod -aG systemd-journal $USER", None, None
            elif "No entries" in error_msg or "No journal files" in error_msg:
                return False, f"No logs found for service '{service_name}'. The service may not exist or have no log entries.", None, None
            else:
                return False, f"Failed to retrieve logs: {error_msg}", None, None
    
    except subprocess.TimeoutExpired:
        return False, "Log retrieval timed out", None, None
    except FileNotFoundError:
        return False, "journalctl command not found (systemd not available)", None, None
    except Exception as e:
        return False, f"Error retrieving logs: {str(e)}", None, None

def get_app_logs_from_file(app_id: str, instance_path: str, lines: int = 500) -> tuple:
    """
    Read logs for an app started via folder (not systemd) from instance/logs/apps/{app_id}.log.
    Returns (success, logs_or_error, oldest_ts, newest_ts).
    """
    if not app_id or not instance_path:
        return False, "App ID and instance path required", None, None
    log_path = Path(instance_path) / "logs" / "apps" / f"{app_id}.log"
    if not log_path.exists():
        return False, "No log file yet. Start the app from the dashboard to capture logs.", None, None
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
        if not all_lines:
            return True, "", None, None
        result_lines = all_lines[-lines:] if len(all_lines) > lines else all_lines
        logs = "".join(result_lines).rstrip()
        oldest_ts, newest_ts = _extract_timestamps_from_logs(logs)
        return True, logs, oldest_ts, newest_ts
    except Exception as e:
        return False, str(e), None, None


def get_appmanager_logs_from_file(instance_path: str, lines: int = 300) -> tuple:
    """
    Read AppManager logs from instance/logs/appmanager.log (used when not running as systemd).
    Returns (success, logs_or_error, oldest_ts, newest_ts).
    """
    if not instance_path:
        return False, "Instance path required", None, None
    log_path = Path(instance_path) / "logs" / "appmanager.log"
    if not log_path.exists():
        return False, f"Log file not found at {log_path}. Restart AppManager from its project directory (e.g. python app.py).", None, None
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
        if not all_lines:
            return True, "", None, None
        # Return last N lines (newest first in file = at end)
        result_lines = all_lines[-lines:] if len(all_lines) > lines else all_lines
        logs = "".join(result_lines).rstrip()
        oldest_ts, newest_ts = _extract_timestamps_from_logs(logs)
        return True, logs, oldest_ts, newest_ts
    except Exception as e:
        return False, str(e), None, None


def _extract_timestamps_from_logs(logs):
    """
    Extract oldest and newest timestamps from journalctl output.
    
    Args:
        logs: Log output string from journalctl
    
    Returns:
        tuple: (oldest_timestamp: str or None, newest_timestamp: str or None)
    """
    if not logs or not logs.strip():
        return None, None
    
    lines = logs.strip().split('\n')
    timestamps = []
    
    # journalctl short-iso format: "2024-01-01T12:00:00+0000 hostname service[pid]: message"
    # Pattern: YYYY-MM-DDTHH:MM:SS (with optional timezone)
    import re
    # Match timestamp with optional timezone: 2024-01-01T12:00:00 or 2024-01-01T12:00:00+0000
    timestamp_pattern = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{4})?)'
    
    for line in lines:
        match = re.search(timestamp_pattern, line)
        if match:
            ts = match.group(1)
            # Keep full timestamp including timezone for API calls
            timestamps.append(ts)
    
    if not timestamps:
        return None, None
    
    # Sort to get oldest and newest
    timestamps.sort()
    return timestamps[0], timestamps[-1]

