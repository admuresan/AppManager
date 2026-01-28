"""
Utility functions for managing apps.

IMPORTANT: Read `instructions/architecture` before making changes.
"""
import socket
import subprocess
import psutil
import os
import re
import platform

# NOTE: Port configuration utilities were extracted to keep this module focused.
# Re-exported here for backward compatibility with existing imports.
from app.utils.port_configuration import (  # noqa: E402
    configure_firewall_port,
    configure_firewall_port_detailed,
    is_server_environment,
)

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

def start_app_service(service_name):
    """Start a systemd service"""
    try:
        # Try to start the service using systemctl
        result = subprocess.run(
            ['sudo', 'systemctl', 'start', service_name],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            return True, f"Service {service_name} started successfully"
        else:
            return False, f"Failed to start service: {result.stderr}"
    except subprocess.TimeoutExpired:
        return False, "Service start timed out"
    except FileNotFoundError:
        return False, "systemctl not available"
    except Exception as e:
        return False, f"Error starting service: {str(e)}"

def stop_app_service(service_name):
    """Stop a systemd service"""
    try:
        # Try to stop the service using systemctl
        result = subprocess.run(
            ['sudo', 'systemctl', 'stop', service_name],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            return True, f"Service {service_name} stopped successfully"
        else:
            return False, f"Failed to stop service: {result.stderr}"
    except subprocess.TimeoutExpired:
        return False, "Service stop timed out"
    except FileNotFoundError:
        return False, "systemctl not available"
    except Exception as e:
        return False, f"Error stopping service: {str(e)}"

def restart_app_service(service_name):
    """Restart a systemd service"""
    try:
        # Try to restart the service using systemctl
        result = subprocess.run(
            ['sudo', 'systemctl', 'restart', service_name],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            return True, f"Service {service_name} restarted successfully"
        else:
            return False, f"Failed to restart service: {result.stderr}"
    except subprocess.TimeoutExpired:
        return False, "Service restart timed out"
    except FileNotFoundError:
        # systemctl not available, try alternative method
        return restart_app_by_port(service_name)
    except Exception as e:
        return False, f"Error restarting service: {str(e)}"

def restart_app_by_port(service_name):
    """Alternative method: find and restart process by port (fallback)"""
    # Extract port from service name if possible
    # This is a fallback if systemctl is not available
    try:
        # Try to find process by service name pattern
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = proc.info.get('cmdline', [])
                if cmdline and service_name in ' '.join(cmdline):
                    proc.terminate()
                    proc.wait(timeout=5)
                    return True, f"Process restarted (PID: {proc.info['pid']})"
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
                continue
        return False, "Could not find process to restart"
    except Exception as e:
        return False, f"Error finding process: {str(e)}"

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

#
# Port configuration helpers live in `app.utils.port_configuration`.
# (See imports near the top of this file.)

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
        # Build journalctl command
        cmd = ['sudo', 'journalctl', '-u', service_name, '--no-pager']
        
        # Add timestamp filters if provided
        if since:
            cmd.extend(['--since', since])
        if until:
            cmd.extend(['--until', until])
        
        # If no timestamps, use -n for last N lines
        if not since and not until:
            cmd.extend(['-n', str(lines)])
        else:
            # When using timestamps, limit output
            cmd.extend(['-n', str(lines)])
        
        # Use --output=short-iso for consistent timestamp format
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
            # Try without sudo if that fails
            cmd[0] = 'journalctl'
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
                # Provide helpful error messages for common issues
                if "Permission denied" in error_msg or "Access denied" in error_msg:
                    return False, f"Permission denied accessing logs. The AppManager user needs sudo access or membership in systemd-journal group. Error: {error_msg}", None, None
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

