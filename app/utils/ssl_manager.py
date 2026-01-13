"""
SSL certificate management for app ports
"""
import subprocess
import os
import platform
import re
from pathlib import Path
from typing import Tuple, List, Dict
import logging

logger = logging.getLogger(__name__)


def _check_file_exists(file_path: str) -> bool:
    """
    Check if a file exists, using sudo if needed for protected directories.
    
    Args:
        file_path: Path to the file to check
        
    Returns:
        True if file exists, False otherwise
    """
    # Try normal check first (works for most files)
    if os.path.exists(file_path):
        return True
    
    # For protected directories like /etc/letsencrypt/, try with sudo
    if '/letsencrypt/' in file_path or '/etc/ssl/' in file_path:
        try:
            result = subprocess.run(
                ['sudo', 'test', '-f', file_path],
                timeout=5,
                capture_output=True
            )
            return result.returncode == 0
        except:
            pass
    
    return False

def create_ssl_certificate_for_port(port: int, server_ip: str, server_domain: str = None) -> Tuple[bool, str]:
    """
    This function is deprecated - SSL certificates are now managed via Let's Encrypt only.
    Child apps use the main Let's Encrypt certificate.
    
    Args:
        port: Port number for the app (unused)
        server_ip: Server IP address (unused)
        server_domain: Server domain name (unused)
        
    Returns:
        Tuple of (success: bool, message: str)
    """
    return False, "Self-signed certificates are no longer supported. Please use Let's Encrypt certificates. Child apps will use the main Let's Encrypt certificate."


def get_main_ssl_certificate() -> Tuple[str, str]:
    """
    Get the main SSL certificate paths (reused for all apps)
    
    Returns:
        Tuple of (cert_path, key_path)
    """
    # Check for Let's Encrypt first (prefer domain-based cert)
    server_domain = os.environ.get('SERVER_DOMAIN', 'blackgrid.ddns.net')
    server_ip = os.environ.get('SERVER_ADDRESS', '40.233.70.245')
    
    # Try domain-based Let's Encrypt certificate first
    letsencrypt_cert_domain = f'/etc/letsencrypt/live/{server_domain}/fullchain.pem'
    letsencrypt_key_domain = f'/etc/letsencrypt/live/{server_domain}/privkey.pem'
    
    if _check_file_exists(letsencrypt_cert_domain) and _check_file_exists(letsencrypt_key_domain):
        return letsencrypt_cert_domain, letsencrypt_key_domain
    
    # Fall back to IP-based Let's Encrypt certificate
    letsencrypt_cert_ip = f'/etc/letsencrypt/live/{server_ip}/fullchain.pem'
    letsencrypt_key_ip = f'/etc/letsencrypt/live/{server_ip}/privkey.pem'
    
    if _check_file_exists(letsencrypt_cert_ip) and _check_file_exists(letsencrypt_key_ip):
        return letsencrypt_cert_ip, letsencrypt_key_ip
    
    # No Let's Encrypt certificate found - raise error
    raise FileNotFoundError(
        f"No Let's Encrypt certificate found. Please set up Let's Encrypt for {server_domain} or {server_ip}. "
        f"Run: sudo certbot certonly --standalone -d {server_domain} --non-interactive --agree-tos --register-unsafely-without-email"
    )


def configure_nginx_for_app_port(port: int, server_ip: str, server_domain: str = None) -> Tuple[bool, str]:
    """
    Configure nginx to handle SSL for an app port
    Maps app HTTP port to an HTTPS port (port + 10000)
    Example: app on 5001 -> HTTPS on 15001
    
    Uses the main SSL certificate (Let's Encrypt only).
    Let's Encrypt certificates work for all ports on the same domain.
    
    Args:
        port: HTTP port number for the app
        server_ip: Server IP address
        server_domain: Server domain name (defaults to blackgrid.ddns.net)
        
    Returns:
        Tuple of (success: bool, message: str)
    """
    if platform.system() != 'Linux':
        return False, "Nginx configuration only supported on Linux"
    
    if server_domain is None:
        server_domain = os.environ.get('SERVER_DOMAIN', 'blackgrid.ddns.net')
    
    # Get main SSL certificate (reuse for all apps - Let's Encrypt certs work for all ports)
    try:
        cert_file, key_file = get_main_ssl_certificate()
    except FileNotFoundError as e:
        return False, f"Let's Encrypt certificate not found. Please set up Let's Encrypt for {server_domain} first. Error: {str(e)}"
    except Exception as e:
        return False, f"Error getting SSL certificate: {str(e)}"
    
    if not _check_file_exists(cert_file) or not _check_file_exists(key_file):
        return False, f"Let's Encrypt certificate not found at {cert_file}. Please set up Let's Encrypt for {server_domain} first. Run: sudo certbot certonly --standalone -d {server_domain} --non-interactive --agree-tos --register-unsafely-without-email"
    
    # Verify certificate is valid and properly signed (should be Let's Encrypt)
    cert_trusted = is_certificate_trusted(cert_file)
    if not cert_trusted:
        return False, f"Certificate at {cert_file} is not a trusted Let's Encrypt certificate. Please set up Let's Encrypt for {server_domain}."
    
    # Map HTTP port to HTTPS port (add 10000)
    https_port = port + 10000
    
    # Create nginx config for this app port
    # Note: We only configure HTTPS port since the app may be listening on the HTTP port
    # Users should access via HTTPS port directly
    # Use domain as primary server_name, IP as fallback
    nginx_config = f"""# HTTPS server for app on port {port} (listens on {https_port})
server {{
    listen {https_port} ssl http2;
    server_name {server_domain} {server_ip} _;

    # SSL certificates (reuse main certificate)
    ssl_certificate {cert_file};
    ssl_certificate_key {key_file};

    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Proxy to app on localhost (HTTP)
    location / {{
        proxy_pass http://127.0.0.1:{port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Port $server_port;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }}
}}
"""
    
    try:
        # Write nginx config to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write(nginx_config)
            temp_config = f.name
        
        try:
            # Append to main nginx config or create separate file
            site_name = f'app-port-{port}'
            result = subprocess.run(
                ['sudo', 'cp', temp_config, f'/etc/nginx/sites-available/{site_name}'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                return False, f"Failed to copy nginx config: {result.stderr}"
            
            # Enable site
            result = subprocess.run(
                ['sudo', 'ln', '-sf', f'/etc/nginx/sites-available/{site_name}', f'/etc/nginx/sites-enabled/{site_name}'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                return False, f"Failed to enable nginx site: {result.stderr}"
            
            # Test nginx configuration
            result = subprocess.run(
                ['sudo', 'nginx', '-t'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                # Remove the site if config test fails
                subprocess.run(['sudo', 'rm', '-f', f'/etc/nginx/sites-enabled/{site_name}'], timeout=5)
                return False, f"Nginx configuration test failed: {result.stderr}"
            
            # Reload nginx
            result = subprocess.run(
                ['sudo', 'systemctl', 'reload', 'nginx'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                https_port = port + 10000
                return True, f"Nginx configured for SSL. Access via https://{server_domain}:{https_port} or https://{server_ip}:{https_port}"
            else:
                return False, f"Failed to reload nginx: {result.stderr}"
                
        finally:
            try:
                os.unlink(temp_config)
            except:
                pass
                
    except Exception as e:
        logger.error(f"Error configuring nginx: {e}")
        return False, f"Error configuring nginx: {str(e)}"


def is_certificate_trusted(cert_path: str) -> bool:
    """
    Check if a certificate is trusted (Let's Encrypt)
    
    Args:
        cert_path: Path to the certificate file
        
    Returns:
        True if certificate is from Let's Encrypt, False otherwise
    """
    if not _check_file_exists(cert_path):
        return False
    
    # Let's Encrypt certificates are in /etc/letsencrypt/live/
    if '/letsencrypt/' in cert_path:
        return True
    
    # Try to check certificate issuer
    try:
        result = subprocess.run(
            ['openssl', 'x509', '-in', cert_path, '-noout', '-issuer'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            issuer = result.stdout.lower()
            # Let's Encrypt issuer contains "lets encrypt"
            if 'lets encrypt' in issuer or 'let\'s encrypt' in issuer:
                return True
    except:
        pass
    
    return False


def setup_ssl_for_app_port(port: int, server_ip: str, server_domain: str = None) -> Tuple[bool, str]:
    """
    Set up SSL certificate and nginx configuration for an app port.
    Requires Let's Encrypt certificate - no self-signed certificates are created.
    
    Args:
        port: HTTP port number for the app
        server_ip: Server IP address
        server_domain: Server domain name (defaults to blackgrid.ddns.net)
        
    Returns:
        Tuple of (success: bool, message: str)
    """
    if server_domain is None:
        server_domain = os.environ.get('SERVER_DOMAIN', 'blackgrid.ddns.net')
    
    # Get the certificate that will be used (must be Let's Encrypt)
    try:
        cert_file, key_file = get_main_ssl_certificate()
    except FileNotFoundError as e:
        return False, f"Let's Encrypt certificate not found. Please set up Let's Encrypt first. Error: {str(e)}"
    except Exception as e:
        return False, f"Error getting SSL certificate: {str(e)}"
    
    # Verify it's a trusted Let's Encrypt certificate
    is_trusted = is_certificate_trusted(cert_file)
    if not is_trusted:
        return False, f"Certificate at {cert_file} is not a trusted Let's Encrypt certificate. Please set up Let's Encrypt for {server_domain}."
    
    # Configure nginx (maps HTTP port to HTTPS port)
    nginx_success, nginx_msg = configure_nginx_for_app_port(port, server_ip, server_domain)
    if not nginx_success:
        return False, nginx_msg
    
    https_port = port + 10000
    
    return True, f"SSL setup complete with Let's Encrypt certificate. HTTP port {port} -> HTTPS port {https_port}. Access via https://{server_domain}:{https_port} or https://{server_ip}:{https_port}"


def is_nginx_configured_for_port(port: int) -> bool:
    """
    Check if nginx is configured for a specific app port
    
    Args:
        port: HTTP port number for the app
        
    Returns:
        True if nginx config exists for this port, False otherwise
    """
    if platform.system() != 'Linux':
        return False
    
    site_name = f'app-port-{port}'
    config_path = Path(f'/etc/nginx/sites-enabled/{site_name}')
    return config_path.exists() or config_path.is_symlink()


def update_all_app_nginx_configs_with_new_certificate() -> Tuple[int, int]:
    """
    Update all existing app port nginx configs to use the current main certificate.
    This is useful when Let's Encrypt is set up and we want all child apps to use it.
    
    Returns:
        Tuple of (updated_count: int, total_count: int)
    """
    if platform.system() != 'Linux':
        return 0, 0
    
    updated_count = 0
    total_count = 0
    
    try:
        # Find all app port nginx configs
        sites_available = Path('/etc/nginx/sites-available')
        if not sites_available.exists():
            return 0, 0
        
        # Get current certificate paths
        cert_file, key_file = get_main_ssl_certificate()
        
        if not _check_file_exists(cert_file) or not _check_file_exists(key_file):
            return 0, 0
        
        # Find all app-port-* configs
        for config_file in sites_available.glob('app-port-*'):
            total_count += 1
            try:
                # Read the config
                with open(config_file, 'r') as f:
                    config_content = f.read()
                
                # Check if certificate paths need updating
                # Extract current cert paths from config
                cert_match = re.search(r'ssl_certificate\s+([^;]+);', config_content)
                key_match = re.search(r'ssl_certificate_key\s+([^;]+);', config_content)
                
                if cert_match and key_match:
                    current_cert = cert_match.group(1).strip()
                    current_key = key_match.group(1).strip()
                    
                    # If paths are different, update them
                    if current_cert != cert_file or current_key != key_file:
                        config_content = config_content.replace(current_cert, cert_file)
                        config_content = config_content.replace(current_key, key_file)
                        
                        # Write updated config
                        with open(config_file, 'w') as f:
                            f.write(config_content)
                        
                        updated_count += 1
                        logger.info(f"Updated nginx config {config_file} to use certificate {cert_file}")
            except Exception as e:
                logger.error(f"Error updating nginx config {config_file}: {e}")
        
        # If any configs were updated, test and reload nginx
        if updated_count > 0:
            # Test nginx configuration
            result = subprocess.run(
                ['sudo', 'nginx', '-t'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Reload nginx
                subprocess.run(['sudo', 'systemctl', 'reload', 'nginx'], timeout=10)
                logger.info(f"Reloaded nginx after updating {updated_count} app configs")
            else:
                logger.error(f"Nginx config test failed after updating configs: {result.stderr}")
        
    except Exception as e:
        logger.error(f"Error updating app nginx configs: {e}")
    
    return updated_count, total_count


def setup_letsencrypt_certificate(server_domain: str = None, email: str = None) -> Tuple[bool, str]:
    """
    Set up Let's Encrypt certificate for the domain using certbot.
    After setup, automatically updates all child app nginx configs to use the trusted certificate.
    
    Args:
        server_domain: Server domain name (defaults to blackgrid.ddns.net)
        email: Email address for Let's Encrypt notifications (optional)
        
    Returns:
        Tuple of (success: bool, message: str)
    """
    if platform.system() != 'Linux':
        return False, "Let's Encrypt setup only supported on Linux"
    
    if server_domain is None:
        server_domain = os.environ.get('SERVER_DOMAIN', 'blackgrid.ddns.net')
    
    # Check if certbot is installed
    try:
        result = subprocess.run(
            ['which', 'certbot'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode != 0:
            return False, "certbot is not installed. Install it with: sudo apt-get install -y certbot python3-certbot-nginx"
    except:
        return False, "Could not check if certbot is installed"
    
    # Check if certificate already exists (use helper function for protected directories)
    cert_path = f'/etc/letsencrypt/live/{server_domain}/fullchain.pem'
    cert_already_exists = _check_file_exists(cert_path)
    
    if not cert_already_exists:
        try:
            # Try standalone mode first (doesn't require nginx to be configured)
            # Stop nginx temporarily to free port 80 for standalone certbot
            nginx_was_running = False
            try:
                result = subprocess.run(
                    ['sudo', 'systemctl', 'is-active', '--quiet', 'nginx'],
                    timeout=5,
                    capture_output=True
                )
                if result.returncode == 0:
                    nginx_was_running = True
                    subprocess.run(['sudo', 'systemctl', 'stop', 'nginx'], timeout=10, capture_output=True)
            except:
                pass  # Ignore errors checking/stopping nginx
            
            # Build certbot command using standalone mode
            cmd = ['sudo', 'certbot', 'certonly', '--standalone', '-d', server_domain, '--non-interactive', '--agree-tos', '--preferred-challenges', 'http']
            
            if email:
                cmd.extend(['--email', email])
            else:
                cmd.append('--register-unsafely-without-email')
            
            # Run certbot
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120  # Certbot can take a while
            )
            
            # Restart nginx if it was running
            if nginx_was_running:
                try:
                    subprocess.run(['sudo', 'systemctl', 'start', 'nginx'], timeout=10, capture_output=True)
                except:
                    pass  # Ignore errors restarting nginx
            
            if result.returncode != 0:
                error_msg = result.stderr or result.stdout
                return False, f"Failed to obtain Let's Encrypt certificate: {error_msg}. Make sure domain {server_domain} resolves to this server and port 80 is accessible."
            
            # Verify certificate was actually created
            if not _check_file_exists(cert_path):
                return False, f"certbot reported success but certificate file not found at {cert_path}. Check certbot logs."
                
        except subprocess.TimeoutExpired:
            # Restart nginx if it was running
            if nginx_was_running:
                try:
                    subprocess.run(['sudo', 'systemctl', 'start', 'nginx'], timeout=10, capture_output=True)
                except:
                    pass
            return False, "Let's Encrypt setup timed out"
        except Exception as e:
            # Restart nginx if it was running
            if nginx_was_running:
                try:
                    subprocess.run(['sudo', 'systemctl', 'start', 'nginx'], timeout=10, capture_output=True)
                except:
                    pass
            logger.error(f"Error setting up Let's Encrypt: {e}")
            return False, f"Error setting up Let's Encrypt: {str(e)}"
    
    # Update all child app nginx configs to use the new trusted certificate
    updated_count, total_count = update_all_app_nginx_configs_with_new_certificate()
    
    # Reload nginx to use new certificate
    subprocess.run(['sudo', 'systemctl', 'reload', 'nginx'], timeout=10)
    
    if cert_already_exists:
        message = f"Let's Encrypt certificate for {server_domain} already exists. Updated {updated_count} of {total_count} child app configs to use the trusted certificate."
    else:
        message = f"Let's Encrypt certificate successfully obtained for {server_domain}. Updated {updated_count} of {total_count} child app configs to use the trusted certificate."
    
    return True, message


def get_certificate_status_for_all_apps() -> Dict[str, any]:
    """
    Get certificate status for all configured app ports
    
    Returns:
        Dictionary with certificate status information
    """
    status = {
        'main_certificate': {},
        'child_apps': [],
        'all_trusted': True,
        'summary': {}
    }
    
    # Get main certificate info
    cert_file, key_file = get_main_ssl_certificate()
    cert_exists = _check_file_exists(cert_file)
    is_trusted = is_certificate_trusted(cert_file) if cert_exists else False
    
    status['main_certificate'] = {
        'cert_path': cert_file,
        'key_path': key_file,
        'exists': cert_exists and _check_file_exists(key_file),
        'trusted': is_trusted,
        'type': 'Let\'s Encrypt' if is_trusted else 'Not trusted'
    }
    
    # Check all child app configs
    if platform.system() == 'Linux':
        sites_available = Path('/etc/nginx/sites-available')
        if sites_available.exists():
            for config_file in sites_available.glob('app-port-*'):
                try:
                    # Extract port from filename (app-port-6005)
                    port_match = re.search(r'app-port-(\d+)', config_file.name)
                    if port_match:
                        port = int(port_match.group(1))
                        
                        # Read config to get certificate path
                        with open(config_file, 'r') as f:
                            config_content = f.read()
                        
                        cert_match = re.search(r'ssl_certificate\s+([^;]+);', config_content)
                        app_cert_path = cert_match.group(1).strip() if cert_match else None
                        app_cert_exists = _check_file_exists(app_cert_path) if app_cert_path else False
                        app_is_trusted = is_certificate_trusted(app_cert_path) if app_cert_path and app_cert_exists else False
                        
                        if not app_is_trusted:
                            status['all_trusted'] = False
                        
                        status['child_apps'].append({
                            'port': port,
                            'https_port': port + 10000,
                            'config_file': str(config_file),
                            'cert_path': app_cert_path,
                            'trusted': app_is_trusted,
                            'type': 'Let\'s Encrypt' if app_is_trusted else 'Not trusted'
                        })
                except Exception as e:
                    logger.error(f"Error checking certificate for {config_file}: {e}")
    
    # Summary
    trusted_count = sum(1 for app in status['child_apps'] if app['trusted'])
    total_count = len(status['child_apps'])
    
    status['summary'] = {
        'total_apps': total_count,
        'trusted_certificates': trusted_count,
        'self_signed_certificates': total_count - trusted_count,
        'main_certificate_trusted': is_trusted
    }
    
    return status


def regenerate_main_certificate(server_ip: str = None, server_domain: str = None) -> Tuple[bool, str]:
    """
    Set up or renew Let's Encrypt certificate for the main domain.
    Self-signed certificates are no longer supported.
    
    Args:
        server_ip: Server IP address (defaults from environment)
        server_domain: Server domain name (defaults to blackgrid.ddns.net)
        
    Returns:
        Tuple of (success: bool, message: str)
    """
    if platform.system() != 'Linux':
        return False, "Let's Encrypt certificate setup only supported on Linux"
    
    if server_domain is None:
        server_domain = os.environ.get('SERVER_DOMAIN', 'blackgrid.ddns.net')
    
    # Use setup_letsencrypt_certificate instead
    return setup_letsencrypt_certificate(server_domain)
