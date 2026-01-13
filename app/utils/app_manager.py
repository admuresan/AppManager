"""
Utility functions for managing apps
"""
import socket
import subprocess
import psutil
import os
import re
import platform

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

def get_active_ports_and_services():
    """
    Get a list of all active ports on localhost and their associated service names.
    Returns a list of dicts with port, service_name, and pid.
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
                    if pid:
                        try:
                            proc = psutil.Process(pid)
                            name = proc.name()
                        except:
                            name = None
                        active_ports.append({
                            'port': port,
                            'service_name': None,
                            'pid': pid,
                            'process_name': name
                        })
        except:
            pass
        return active_ports
    
    try:
        # Get all listening ports
        ports_used = {}
        
        # Method 1: Use ss to get ports and PIDs
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
                        port_match = re.search(r':(\d+)\s', line)
                        pid_match = re.search(r'pid=(\d+)', line)
                        if port_match and pid_match:
                            port = int(port_match.group(1))
                            pid = int(pid_match.group(1))
                            if port not in ports_used:
                                ports_used[port] = {'pid': pid}
        except:
            pass
        
        # Method 2: Use psutil as fallback
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN' and conn.laddr.ip in ('127.0.0.1', '0.0.0.0', '::', '::1'):
                    port = conn.laddr.port
                    pid = conn.pid
                    if port not in ports_used and pid:
                        ports_used[port] = {'pid': pid}
        except:
            pass
        
        # For each port, try to find the service name
        for port, info in ports_used.items():
            pid = info.get('pid')
            service_name = None
            
            if pid:
                # Try to get service name from PID
                service_name = _get_service_by_pid(pid)
                
                # If not found, try detection by port
                if not service_name:
                    service_name = detect_service_name_by_port(port)
            
            active_ports.append({
                'port': port,
                'service_name': service_name,
                'pid': pid,
                'process_name': None
            })
        
        # Sort by port number
        active_ports.sort(key=lambda x: x['port'])
        
    except Exception as e:
        pass
    
    return active_ports

def is_server_environment():
    """Check if running on a server (not localhost/development)"""
    # Check if we're in development mode
    if os.environ.get('FLASK_ENV') == 'development':
        return False
    
    # Check if running on Windows (no ufw support)
    if platform.system() != 'Linux':
        return False
    
    # Check if ufw is available
    try:
        result = subprocess.run(['which', 'ufw'], capture_output=True, timeout=2)
        if result.returncode != 0:
            return False
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    
    return True

def configure_firewall_port(port, action='allow'):
    """
    Configure firewall rules for a port using ufw and OCI security lists.
    
    Args:
        port: Port number to configure
        action: 'allow' to open port, 'delete' to remove rule
    
    Returns:
        tuple: (success: bool, message: str)
    """
    messages = []
    ufw_success = True
    oci_success = True
    
    # Configure local firewall (ufw) if on server
    if is_server_environment():
        try:
            if action == 'allow':
                # Check if rule already exists
                result = subprocess.run(
                    ['sudo', 'ufw', 'status', 'numbered'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                # Check if port is already allowed
                if str(port) in result.stdout:
                    messages.append(f"Port {port} is already allowed in ufw")
                else:
                    # Add firewall rule
                    result = subprocess.run(
                        ['sudo', 'ufw', 'allow', f'{port}/tcp'],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    
                    if result.returncode == 0:
                        messages.append(f"UFW rule added: ufw allow {port}/tcp")
                    else:
                        ufw_success = False
                        messages.append(f"Failed to add UFW rule: {result.stderr}")
            
            elif action == 'delete':
                # Remove firewall rule (if exists)
                result = subprocess.run(
                    ['sudo', 'ufw', 'delete', 'allow', f'{port}/tcp'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    messages.append(f"UFW rule removed: ufw delete allow {port}/tcp")
                else:
                    # Rule might not exist, which is okay
                    messages.append(f"UFW rule for port {port} not found (may not exist)")
            
            else:
                ufw_success = False
                messages.append(f"Unknown action: {action}")
        
        except subprocess.TimeoutExpired:
            ufw_success = False
            messages.append("UFW command timed out")
        except FileNotFoundError:
            ufw_success = False
            messages.append("ufw command not found (not installed?)")
        except Exception as e:
            ufw_success = False
            messages.append(f"Error configuring UFW: {str(e)}")
    else:
        messages.append("Skipped UFW (not on server environment)")
    
    # Configure OCI security list if configured
    try:
        from app.utils.oci_manager import configure_oci_port, is_oci_configured
        
        if is_oci_configured():
            oci_success, oci_message = configure_oci_port(port, action)
            messages.append(f"OCI: {oci_message}")
        else:
            messages.append("OCI not configured, skipping OCI security list update")
    except ImportError:
        messages.append("OCI SDK not available, skipping OCI security list update")
    except Exception as e:
        oci_success = False
        messages.append(f"OCI error: {str(e)}")
    
    # Return success if at least one method succeeded
    overall_success = ufw_success or oci_success
    combined_message = "; ".join(messages)
    
    return overall_success, combined_message

