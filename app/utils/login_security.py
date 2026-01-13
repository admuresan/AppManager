"""
Login security utility for tracking and limiting failed login attempts
"""
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from threading import Lock

# Thread-safe lock for file operations
_login_security_lock = Lock()

# Maximum failed attempts before blocking
MAX_FAILED_ATTEMPTS = 3

# Lockout duration in minutes (0 = permanent until manual reset or successful login from another IP)
LOCKOUT_DURATION_MINUTES = 0  # Set to 0 for permanent lockout, or set to a number for temporary lockout

def _get_login_attempts_file_path(instance_path):
    """Get the path to the login attempts file"""
    data_dir = Path(instance_path) / 'data'
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir / 'login_attempts.json'

def _load_login_attempts(instance_path):
    """Load login attempts data from file"""
    attempts_file = _get_login_attempts_file_path(instance_path)
    if attempts_file.exists():
        try:
            with open(attempts_file, 'r') as f:
                data = json.load(f)
                return data
        except:
            pass
    
    # Return default structure
    return {
        'attempts': {},  # IP -> {'count': int, 'last_attempt': iso_string, 'blocked_until': iso_string or None}
        'updated': datetime.now().isoformat()
    }

def _save_login_attempts(instance_path, data):
    """Save login attempts data to file"""
    attempts_file = _get_login_attempts_file_path(instance_path)
    data['updated'] = datetime.now().isoformat()
    try:
        with open(attempts_file, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        import logging
        logging.error(f"Error saving login attempts: {e}")

def _cleanup_old_attempts(data, max_age_hours=24):
    """Remove old attempt records that are no longer relevant"""
    cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
    ips_to_remove = []
    
    for ip, attempt_data in data['attempts'].items():
        last_attempt_str = attempt_data.get('last_attempt')
        if last_attempt_str:
            try:
                last_attempt = datetime.fromisoformat(last_attempt_str)
                # Remove if old and not blocked
                if last_attempt < cutoff_time and not attempt_data.get('blocked_until'):
                    ips_to_remove.append(ip)
            except:
                # If parsing fails, remove the entry
                ips_to_remove.append(ip)
    
    for ip in ips_to_remove:
        del data['attempts'][ip]

def is_ip_blocked(instance_path, ip_address):
    """Check if an IP address is currently blocked from login attempts
    
    Args:
        instance_path: Path to instance directory
        ip_address: IP address to check
    
    Returns:
        Tuple of (is_blocked: bool, remaining_attempts: int, message: str)
    """
    if not ip_address:
        return False, MAX_FAILED_ATTEMPTS, ""
    
    with _login_security_lock:
        data = _load_login_attempts(instance_path)
        _cleanup_old_attempts(data)
        
        attempt_data = data['attempts'].get(ip_address)
        if not attempt_data:
            return False, MAX_FAILED_ATTEMPTS, ""
        
        failed_count = attempt_data.get('count', 0)
        
        # Check if IP is blocked
        if failed_count >= MAX_FAILED_ATTEMPTS:
            blocked_until_str = attempt_data.get('blocked_until')
            
            # If lockout duration is 0, block is permanent (until successful login)
            if LOCKOUT_DURATION_MINUTES == 0:
                return True, 0, f"IP address blocked due to {failed_count} failed login attempts"
            
            # Otherwise, check if block has expired
            if blocked_until_str:
                try:
                    blocked_until = datetime.fromisoformat(blocked_until_str)
                    if datetime.now() < blocked_until:
                        remaining_minutes = int((blocked_until - datetime.now()).total_seconds() / 60)
                        return True, 0, f"IP address blocked. Try again in {remaining_minutes} minute(s)"
                    else:
                        # Block expired, reset
                        del data['attempts'][ip_address]
                        _save_login_attempts(instance_path, data)
                        return False, MAX_FAILED_ATTEMPTS, ""
                except:
                    # If parsing fails, treat as permanent block
                    return True, 0, f"IP address blocked due to {failed_count} failed login attempts"
            else:
                # No block time set, treat as permanent
                return True, 0, f"IP address blocked due to {failed_count} failed login attempts"
        
        remaining_attempts = MAX_FAILED_ATTEMPTS - failed_count
        return False, remaining_attempts, ""

def record_failed_attempt(instance_path, ip_address):
    """Record a failed login attempt for an IP address
    
    Args:
        instance_path: Path to instance directory
        ip_address: IP address that failed
    
    Returns:
        Tuple of (is_now_blocked: bool, remaining_attempts: int, message: str)
    """
    if not ip_address:
        return False, MAX_FAILED_ATTEMPTS, ""
    
    with _login_security_lock:
        data = _load_login_attempts(instance_path)
        _cleanup_old_attempts(data)
        
        attempt_data = data['attempts'].get(ip_address, {'count': 0})
        attempt_data['count'] = attempt_data.get('count', 0) + 1
        attempt_data['last_attempt'] = datetime.now().isoformat()
        
        # If this is the 3rd failed attempt, set block time if using temporary lockout
        if attempt_data['count'] >= MAX_FAILED_ATTEMPTS:
            if LOCKOUT_DURATION_MINUTES > 0:
                attempt_data['blocked_until'] = (datetime.now() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)).isoformat()
            else:
                # Permanent block (until successful login)
                attempt_data['blocked_until'] = None
        
        data['attempts'][ip_address] = attempt_data
        _save_login_attempts(instance_path, data)
        
        failed_count = attempt_data['count']
        remaining_attempts = max(0, MAX_FAILED_ATTEMPTS - failed_count)
        
        if failed_count >= MAX_FAILED_ATTEMPTS:
            if LOCKOUT_DURATION_MINUTES > 0:
                return True, 0, f"Too many failed login attempts. IP address blocked for {LOCKOUT_DURATION_MINUTES} minutes."
            else:
                return True, 0, f"Too many failed login attempts. IP address blocked."
        else:
            return False, remaining_attempts, f"Invalid credentials. {remaining_attempts} attempt(s) remaining."

def reset_failed_attempts(instance_path, ip_address):
    """Reset failed login attempts for an IP address (called on successful login)
    
    Args:
        instance_path: Path to instance directory
        ip_address: IP address that successfully logged in
    """
    if not ip_address:
        return
    
    with _login_security_lock:
        data = _load_login_attempts(instance_path)
        if ip_address in data['attempts']:
            del data['attempts'][ip_address]
            _save_login_attempts(instance_path, data)

