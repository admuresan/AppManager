"""
Admin routes for managing apps
"""
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash, current_app, send_from_directory
from flask_login import login_required, login_user, logout_user, current_user
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
import os
import platform
import subprocess
import json
from pathlib import Path
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
import time

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from app.models.user import User
from app.models.app_config import AppConfig
from app.utils.app_manager import test_app_port, restart_app_service, detect_service_name_by_port, get_active_ports_and_services, configure_firewall_port, check_port_status, get_app_logs
from app.utils.ssl_manager import setup_ssl_for_app_port, setup_letsencrypt_certificate, regenerate_main_certificate, get_certificate_status_for_all_apps, _check_file_exists
from app.utils.app_usage_tracker import get_tracker

bp = Blueprint('admin', __name__, url_prefix='/blackgrid/admin')

@bp.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    """Handle 413 Request Entity Too Large errors"""
    return jsonify({
        'error': 'File too large. Maximum file size is 20MB. If you\'re using nginx, ensure client_max_body_size is set to at least 20m in your nginx configuration.'
    }), 413

@bp.route('/login', methods=['GET', 'POST'])
def login():
    """Admin login page"""
    # Get client IP address (handle proxy headers)
    ip_address = request.headers.get('X-Forwarded-For', request.headers.get('X-Real-IP', request.remote_addr))
    if ip_address:
        ip_address = ip_address.split(',')[0].strip()
    else:
        ip_address = request.remote_addr or None
    
    if request.method == 'POST':
        # Check if IP is blocked before processing login
        from app.utils.login_security import is_ip_blocked, record_failed_attempt, reset_failed_attempts
        
        is_blocked, remaining_attempts, block_message = is_ip_blocked(current_app.instance_path, ip_address)
        if is_blocked:
            flash(block_message, 'error')
            return render_template('admin/login.html')
        
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.get_by_username(username)
        if user and user.check_password(password):
            # Successful login - reset failed attempts
            reset_failed_attempts(current_app.instance_path, ip_address)
            
            # Track admin login
            try:
                from app.utils.traffic_tracker import track_admin_login, add_admin_ip
                if ip_address:
                    track_admin_login(current_app.instance_path, ip_address)
                    add_admin_ip(current_app.instance_path, ip_address)
            except:
                pass  # Don't fail login if tracking fails
            
            login_user(user)
            return redirect(url_for('admin.dashboard'))
        else:
            # Failed login - record attempt
            is_now_blocked, remaining_attempts, error_message = record_failed_attempt(current_app.instance_path, ip_address)
            if is_now_blocked:
                flash(error_message, 'error')
            else:
                flash(f'Invalid username or password. {error_message}', 'error')
    
    return render_template('admin/login.html')

@bp.route('/logout')
@login_required
def logout():
    """Logout admin"""
    logout_user()
    return redirect(url_for('welcome.index'))

@bp.route('/dashboard')
@login_required
def dashboard():
    """Admin dashboard showing all apps"""
    # Track admin IP for filtering
    try:
        from app.utils.traffic_tracker import add_admin_ip
        ip_address = request.headers.get('X-Forwarded-For', request.headers.get('X-Real-IP', request.remote_addr))
        if ip_address:
            ip_address = ip_address.split(',')[0].strip()
        else:
            ip_address = request.remote_addr or None
        if ip_address:
            add_admin_ip(current_app.instance_path, ip_address)
    except:
        pass  # Don't fail if tracking fails
    
    apps = AppConfig.get_all()
    return render_template('admin/dashboard.html', apps=apps)

@bp.route('/api/apps', methods=['GET'])
@login_required
def get_apps():
    """Get all apps (API endpoint)"""
    apps = AppConfig.get_all()
    return jsonify({'apps': apps})

@bp.route('/api/apps', methods=['POST'])
@login_required
def create_app():
    """Create a new app"""
    name = request.form.get('name')
    port = request.form.get('port')
    service_name = request.form.get('service_name', '')
    folder_path = request.form.get('folder_path', '').strip()
    
    if not name or not port:
        return jsonify({'error': 'Name and port are required'}), 400
    
    try:
        port = int(port)
    except ValueError:
        return jsonify({'error': 'Port must be a number'}), 400
    
    # Test if the port is listening before adding
    is_listening = test_app_port(port)
    if not is_listening:
        return jsonify({
            'error': f'Port {port} is not listening. Please ensure the app is running on this port before adding it.',
            'port': port,
            'is_listening': False
        }), 400
    
    # Handle logo upload
    logo_path = None
    if 'logo' in request.files:
        file = request.files['logo']
        if file.filename:
            filename = secure_filename(file.filename)
            instance_path = Path(current_app.instance_path)
            logo_dir = instance_path / 'uploads' / 'logos'
            logo_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate unique filename
            import uuid
            unique_filename = f"{uuid.uuid4()}_{filename}"
            filepath = logo_dir / unique_filename
            file.save(filepath)
            # Store path relative to instance directory (without 'uploads/' prefix since route handles it)
            logo_path = f"logos/{unique_filename}"
    
    try:
        app_config = AppConfig.create(
            name=name,
            port=port,
            logo=logo_path,
            service_name=service_name if service_name else None,
            folder_path=folder_path if folder_path else None
        )
    except ValueError as e:
        # Handle duplicate slug error
        return jsonify({'error': str(e)}), 400
    
    # Configure firewall to allow HTTP port (only on server, not localhost)
    firewall_success, firewall_message = configure_firewall_port(port, action='allow')
    # Note: We don't fail the request if firewall config fails, just log it
    
    # Set up SSL for this app port (requires Let's Encrypt certificate)
    server_address = current_app.config.get('SERVER_ADDRESS', '40.233.70.245')
    server_domain = current_app.config.get('SERVER_DOMAIN', 'blackgrid.ddns.net')
    ssl_success, ssl_message = setup_ssl_for_app_port(port, server_address, server_domain)
    # Note: SSL setup requires Let's Encrypt certificate. If it fails, app is created but HTTPS won't work until certificate is set up.
    
    # Also configure firewall for HTTPS port (port + 10000)
    https_port = port + 10000
    https_firewall_success, https_firewall_message = configure_firewall_port(https_port, action='allow')
    
    response_data = {'success': True, 'app': app_config}
    if not firewall_success:
        response_data['firewall_warning'] = firewall_message
    if not https_firewall_success:
        response_data['https_firewall_warning'] = https_firewall_message
    if not ssl_success:
        response_data['ssl_warning'] = ssl_message
    elif ssl_success:
        response_data['ssl_info'] = ssl_message
        response_data['https_port'] = https_port
    
    return jsonify(response_data)

@bp.route('/api/apps/<app_id>', methods=['PUT'])
@login_required
def update_app(app_id):
    """Update an existing app"""
    # Check if this is form data (file upload) or JSON
    if request.content_type and 'multipart/form-data' in request.content_type:
        data = request.form
        name = data.get('name')
        port = data.get('port')
        service_name = data.get('service_name', '')
        folder_path = data.get('folder_path', '').strip()
        
        # Handle logo upload if provided
        logo_path = None
        if 'logo' in request.files:
            file = request.files['logo']
            if file.filename:
                filename = secure_filename(file.filename)
                instance_path = Path(current_app.instance_path)
                logo_dir = instance_path / 'uploads' / 'logos'
                logo_dir.mkdir(parents=True, exist_ok=True)
                
                import uuid
                unique_filename = f"{uuid.uuid4()}_{filename}"
                filepath = logo_dir / unique_filename
                file.save(filepath)
                logo_path = f"uploads/logos/{unique_filename}"
        
        # Get existing app to preserve logo if not updating
        existing_app = AppConfig.get_by_id(app_id)
        if not existing_app:
            return jsonify({'error': 'App not found'}), 404
        
        final_logo = logo_path if logo_path else existing_app.get('logo')
    else:
        # JSON request
        data = request.get_json()
        name = data.get('name')
        port = data.get('port')
        service_name = data.get('service_name', '')
        folder_path = data.get('folder_path', '').strip()
        final_logo = data.get('logo')
    
    if not name or not port:
        return jsonify({'error': 'Name and port are required'}), 400
    
    try:
        port = int(port)
    except ValueError:
        return jsonify({'error': 'Port must be a number'}), 400
    
    # Get existing app to check if port changed
    existing_app = AppConfig.get_by_id(app_id)
    if not existing_app:
        return jsonify({'error': 'App not found'}), 404
    
    old_port = existing_app.get('port')
    port_changed = old_port != port
    
    try:
        app_config = AppConfig.update(
            app_id=app_id,
            name=name,
            port=port,
            logo=final_logo,
            service_name=service_name if service_name else None,
            folder_path=folder_path if folder_path else None
        )
    except ValueError as e:
        # Handle duplicate slug error
        return jsonify({'error': str(e)}), 400
    
    if app_config:
        # If port changed, update firewall rules and SSL
        if port_changed:
            # Remove old port rule (if it was only used by this app)
            # Note: We're conservative here - we don't delete in case other apps use it
            # Just ensure the new port is allowed
            configure_firewall_port(port, action='allow')
        
        # Set up SSL for this app port (requires Let's Encrypt certificate)
        server_address = current_app.config.get('SERVER_ADDRESS', '40.233.70.245')
        server_domain = current_app.config.get('SERVER_DOMAIN', 'blackgrid.ddns.net')
        ssl_success, ssl_message = setup_ssl_for_app_port(port, server_address, server_domain)
        # Note: SSL setup requires Let's Encrypt certificate. If it fails, app is updated but HTTPS won't work until certificate is set up.
        
        # Also configure firewall for HTTPS port
        https_port = port + 10000
        https_firewall_success, https_firewall_message = configure_firewall_port(https_port, action='allow')
        
        response_data = {'success': True, 'app': app_config}
        if not https_firewall_success:
            response_data['https_firewall_warning'] = https_firewall_message
        if not ssl_success:
            response_data['ssl_warning'] = ssl_message
        elif ssl_success:
            response_data['ssl_info'] = ssl_message
            response_data['https_port'] = https_port
        
        return jsonify(response_data)
    else:
        return jsonify({'error': 'App not found'}), 404

@bp.route('/api/apps/<app_id>', methods=['DELETE'])
@login_required
def delete_app(app_id):
    """Delete an app"""
    # Get app config before deleting to get the port
    app_config = AppConfig.get_by_id(app_id)
    if not app_config:
        return jsonify({'error': 'App not found'}), 404
    
    port = app_config.get('port')
    
    success = AppConfig.delete(app_id)
    if success:
        # Note: We don't automatically remove firewall rules when deleting an app
        # because the port might still be in use by the app itself or other services
        # Admin can manually remove firewall rules if needed
        return jsonify({'success': True})
    else:
        return jsonify({'error': 'App not found'}), 404

@bp.route('/api/apps/<app_id>/toggle-serve', methods=['POST'])
@login_required
def toggle_serve_app(app_id):
    """Toggle the serve_app status for an app"""
    app_config = AppConfig.toggle_serve_app(app_id)
    if app_config:
        return jsonify({'success': True, 'app': app_config})
    else:
        return jsonify({'error': 'App not found'}), 404

def test_url(url, timeout=3, check_ssl_cert=False):
    """Test if a URL is accessible
    
    Args:
        url: URL to test
        timeout: Request timeout in seconds
        check_ssl_cert: If True, verify SSL certificate (default: False for compatibility)
    
    Returns:
        Tuple of (connection_successful: bool, status: int or str, cert_info: dict or None, request_successful: bool)
        - connection_successful: True if we got any HTTP response (even 4xx/5xx)
        - request_successful: True only if status is 2xx (success)
    """
    cert_info = None
    try:
        # Create a session with retry strategy
        session = requests.Session()
        retry_strategy = Retry(
            total=1,
            backoff_factor=0.1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # For HTTPS, check certificate if requested
        verify_ssl = check_ssl_cert if url.startswith('https://') else False
        
        response = session.get(url, timeout=timeout, verify=verify_ssl, allow_redirects=True)
        
        # Determine if request was successful (2xx status codes)
        request_successful = 200 <= response.status_code < 300
        
        # If HTTPS, get certificate info
        cert_info = None
        if url.startswith('https://'):
            try:
                cert_info = {
                    'verified': verify_ssl,
                    'subject': None,
                    'issuer': None,
                    'expires': None
                }
                # Try to get certificate details from response
                # Method 1: Try from response connection
                try:
                    if hasattr(response.raw, 'connection') and hasattr(response.raw.connection, 'sock'):
                        sock = response.raw.connection.sock
                        if hasattr(sock, 'getpeercert'):
                            cert = sock.getpeercert()
                            if cert:
                                cert_info['subject'] = dict(x[0] for x in cert.get('subject', []))
                                cert_info['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                                cert_info['expires'] = cert.get('notAfter')
                except:
                    pass
                
                # Method 2: Try from response history (redirects)
                if not cert_info.get('issuer') and response.history:
                    try:
                        for hist_resp in response.history:
                            if hasattr(hist_resp.raw, 'connection') and hasattr(hist_resp.raw.connection, 'sock'):
                                sock = hist_resp.raw.connection.sock
                                if hasattr(sock, 'getpeercert'):
                                    cert = sock.getpeercert()
                                    if cert:
                                        cert_info['subject'] = dict(x[0] for x in cert.get('subject', []))
                                        cert_info['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                                        cert_info['expires'] = cert.get('notAfter')
                                        break
                    except:
                        pass
            except Exception as e:
                cert_info = {'verified': verify_ssl, 'error': str(e)}
        
        # Return connection successful (we got a response), status code, cert info, and request success
        return True, response.status_code, cert_info if cert_info else None, request_successful
    except requests.exceptions.SSLError as e:
        # SSL error but connection was attempted - port is open
        # Try to get certificate info even on SSL error
        cert_info = {
            'verified': False,
            'error': str(e),
            'subject': None,
            'issuer': None
        }
        # Try to get certificate details even if verification failed
        try:
            # Make a request with verify=False to get certificate info
            temp_session = requests.Session()
            temp_response = temp_session.get(url, timeout=timeout, verify=False, allow_redirects=True)
            if hasattr(temp_response.raw, 'connection') and hasattr(temp_response.raw.connection, 'sock'):
                sock = temp_response.raw.connection.sock
                if hasattr(sock, 'getpeercert'):
                    cert = sock.getpeercert()
                    if cert:
                        cert_info['subject'] = dict(x[0] for x in cert.get('subject', []))
                        cert_info['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                        cert_info['expires'] = cert.get('notAfter')
        except:
            pass
        # SSL error means connection worked but SSL failed - request not successful
        return True, 'SSL_ERROR', cert_info, False
    except requests.exceptions.ConnectionError:
        return False, 'CONNECTION_ERROR', None, False
    except requests.exceptions.Timeout:
        return False, 'TIMEOUT', None, False
    except Exception as e:
        return False, str(e), None, False

@bp.route('/api/apps/<app_id>/test', methods=['POST'])
@login_required
def test_app(app_id):
    """Test if an app is listening on both HTTP and HTTPS ports, including masked path"""
    app_config = AppConfig.get_by_id(app_id)
    if not app_config:
        return jsonify({'error': 'App not found'}), 404
    
    port = app_config['port']
    app_slug = AppConfig._slugify(app_config['name'])
    server_address = current_app.config.get('SERVER_ADDRESS', 'localhost')
    server_domain = current_app.config.get('SERVER_DOMAIN', None)
    
    # Determine base URL for masked path testing
    # Use the same protocol as the current request
    protocol = 'https' if request.is_secure else 'http'
    if server_domain and server_domain != 'localhost':
        base_host = server_domain
    else:
        base_host = server_address if server_address != 'localhost' else request.host.split(':')[0]
    
    # Test HTTP on original port (try server_address first, then localhost as fallback)
    http_url = f"http://{server_address}:{port}"
    http_accessible, http_status, _, http_successful = test_url(http_url)
    http_test_url = http_url
    
    # If server_address test failed and it's not localhost, try localhost
    if not http_accessible and server_address != 'localhost':
        localhost_url = f"http://localhost:{port}"
        localhost_accessible, localhost_status, _, localhost_successful = test_url(localhost_url)
        if localhost_accessible:
            http_accessible = True
            http_status = localhost_status
            http_test_url = localhost_url
            http_successful = localhost_successful
    
    # Test HTTPS on port + 10000
    # Prefer domain over IP for HTTPS (matches SSL certificate configuration)
    https_port = port + 10000
    if server_domain and server_domain != 'localhost':
        https_host = server_domain
    else:
        https_host = server_address
    
    # Test HTTPS with domain first (if available) - check SSL cert
    https_url = f"https://{https_host}:{https_port}"
    https_accessible, https_status, https_cert_info, https_successful = test_url(https_url, check_ssl_cert=True)
    https_test_url = https_url
    
    # If domain test failed and we used domain, also try IP as fallback
    if not https_accessible and server_domain and server_domain != 'localhost' and server_address != 'localhost':
        https_url_ip = f"https://{server_address}:{https_port}"
        https_accessible_ip, https_status_ip, https_cert_info_ip, https_successful_ip = test_url(https_url_ip, check_ssl_cert=True)
        if https_accessible_ip:
            https_accessible = True
            https_status = https_status_ip
            https_test_url = https_url_ip
            https_cert_info = https_cert_info_ip
            https_successful = https_successful_ip
    
    # Test masked path (through proxy) - HTTP
    # Use internal request to Flask's proxy route instead of external HTTP request
    # This avoids issues with nginx or external infrastructure
    masked_http_url = f"{protocol}://{base_host}/{app_slug}/"
    
    # Try internal test first (using Flask test client for more reliable testing)
    masked_http_accessible = False
    masked_http_status = None
    masked_http_successful = False
    
    try:
        # Use Flask's test client to make an internal request to the proxy route
        # This bypasses external infrastructure and tests the Flask route directly
        with current_app.test_client() as client:
            # Make request to the proxy route
            response = client.get(f'/{app_slug}/', follow_redirects=False)
            masked_http_accessible = True
            masked_http_status = response.status_code
            masked_http_successful = 200 <= response.status_code < 300
    except Exception as e:
        # Fallback 1: Try internal HTTP request to localhost
        # Get Flask port from request host
        try:
            host_parts = request.host.split(':')
            flask_host = host_parts[0] if host_parts else 'localhost'
            flask_port = int(host_parts[1]) if len(host_parts) > 1 else (80 if not request.is_secure else 443)
            # Use HTTP for internal request regardless of external protocol
            internal_url = f"http://localhost:{flask_port}/{app_slug}/"
            masked_http_accessible, masked_http_status, _, masked_http_successful = test_url(internal_url, timeout=2)
            if not masked_http_accessible:
                # Fallback 2: Try default ports if port detection failed
                for default_port in [5000, 80]:
                    if default_port != flask_port:
                        internal_url = f"http://localhost:{default_port}/{app_slug}/"
                        masked_http_accessible, masked_http_status, _, masked_http_successful = test_url(internal_url, timeout=2)
                        if masked_http_accessible:
                            break
        except Exception as e2:
            current_app.logger.warning(f"Internal HTTP request failed for masked path test: {e2}")
        
        # Fallback 3: External HTTP request (last resort)
        if not masked_http_accessible:
            current_app.logger.warning(f"Flask test client failed for masked path test, falling back to external HTTP request: {e}")
            masked_http_accessible, masked_http_status, _, masked_http_successful = test_url(masked_http_url)
    
    # Test masked path (through proxy) - HTTPS (if we have domain)
    masked_https_accessible = False
    masked_https_status = None
    masked_https_successful = False
    masked_https_url = None
    if server_domain and server_domain != 'localhost':
        masked_https_url = f"https://{base_host}/{app_slug}/"
        
        # Try internal test first (using Flask test client)
        try:
            # Use Flask's test client to make an internal request
            # Simulate HTTPS by setting the appropriate headers
            with current_app.test_client() as client:
                # Make request to the proxy route with HTTPS simulation
                response = client.get(f'/{app_slug}/', follow_redirects=False, 
                                     headers={'X-Forwarded-Proto': 'https'})
                masked_https_accessible = True
                masked_https_status = response.status_code
                masked_https_successful = 200 <= response.status_code < 300
        except Exception as e:
            # Fallback 1: Try internal HTTP request to localhost
            try:
                host_parts = request.host.split(':')
                flask_host = host_parts[0] if host_parts else 'localhost'
                flask_port = int(host_parts[1]) if len(host_parts) > 1 else (80 if not request.is_secure else 443)
                # Use HTTP for internal request regardless of external protocol
                internal_url = f"http://localhost:{flask_port}/{app_slug}/"
                masked_https_accessible, masked_https_status, _, masked_https_successful = test_url(internal_url, timeout=2)
                if not masked_https_accessible:
                    # Fallback: Try default ports if port detection failed
                    for default_port in [5000, 80]:
                        if default_port != flask_port:
                            internal_url = f"http://localhost:{default_port}/{app_slug}/"
                            masked_https_accessible, masked_https_status, _, masked_https_successful = test_url(internal_url, timeout=2)
                            if masked_https_accessible:
                                break
            except Exception as e2:
                current_app.logger.warning(f"Internal HTTP request failed for masked HTTPS path test: {e2}")
            
            # Fallback 2: External HTTPS request (last resort)
            if not masked_https_accessible:
                current_app.logger.warning(f"Flask test client failed for masked HTTPS path test, falling back to external HTTPS request: {e}")
                masked_https_accessible, masked_https_status, _, masked_https_successful = test_url(masked_https_url)
    
    # Also test if port is listening (socket level)
    is_listening = test_app_port(port)
    
    # Check if nginx is configured for HTTPS
    from app.utils.ssl_manager import is_nginx_configured_for_port, get_main_ssl_certificate, is_certificate_trusted, _check_file_exists
    nginx_configured = is_nginx_configured_for_port(port)
    
    # Check SSL certificate status
    ssl_cert_status = {
        'nginx_configured': nginx_configured,
        'certificate_exists': False,
        'certificate_trusted': False,
        'certificate_path': None,
        'certificate_info': https_cert_info
    }
    
    try:
        cert_file, key_file = get_main_ssl_certificate()
        cert_exists = _check_file_exists(cert_file) and _check_file_exists(key_file)
        cert_trusted = is_certificate_trusted(cert_file) if cert_exists else False
        
        ssl_cert_status['certificate_exists'] = cert_exists
        ssl_cert_status['certificate_trusted'] = cert_trusted
        ssl_cert_status['certificate_path'] = cert_file if cert_exists else None
        
        # If we have cert info from the test, merge it
        if https_cert_info:
            ssl_cert_status['certificate_info'] = https_cert_info
    except Exception as e:
        ssl_cert_status['error'] = str(e)
    
    return jsonify({
        'success': True,
        'port': port,
        'app_slug': app_slug,
        'http': {
            'accessible': http_accessible,
            'successful': http_successful if http_accessible else False,
            'status': http_status,
            'url': http_test_url
        },
        'https': {
            'accessible': https_accessible,
            'successful': https_successful if https_accessible else False,
            'status': https_status,
            'url': https_test_url,
            'port': https_port,
            'nginx_configured': nginx_configured,
            'certificate_status': ssl_cert_status
        },
        'masked_path': {
            'http': {
                'accessible': masked_http_accessible,
                'successful': masked_http_successful if masked_http_accessible else False,
                'status': masked_http_status,
                'url': masked_http_url
            },
            'https': {
                'accessible': masked_https_accessible,
                'successful': masked_https_successful if masked_https_accessible else False,
                'status': masked_https_status,
                'url': masked_https_url
            } if masked_https_url else None
        },
        'is_listening': is_listening
    })

@bp.route('/api/detect-service/<int:port>', methods=['GET'])
@login_required
def detect_service(port):
    """Detect systemd service name for a given port"""
    service_name = detect_service_name_by_port(port)
    if service_name:
        return jsonify({
            'success': True,
            'service_name': service_name,
            'port': port
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Could not detect service name for this port',
            'port': port
        })

@bp.route('/api/active-ports', methods=['GET'])
@login_required
def active_ports():
    """Get list of active ports and their service names"""
    ports = get_active_ports_and_services()
    return jsonify({
        'success': True,
        'ports': ports
    })

@bp.route('/api/check-port/<int:port>', methods=['GET'])
@login_required
def check_port(port):
    """Check detailed status of a specific port"""
    status = check_port_status(port)
    return jsonify({
        'success': True,
        'status': status
    })

@bp.route('/api/apps/<app_id>/fix-ssl', methods=['POST'])
@login_required
def fix_app_ssl(app_id):
    """Fix SSL certificate and nginx configuration for an app
    
    This will:
    1. Remove existing nginx configuration for the app port
    2. Ensure the main SSL certificate exists and is properly configured
    3. Recreate nginx configuration with proper domain and certificate
    4. Reload nginx to apply changes
    """
    app_config = AppConfig.get_by_id(app_id)
    if not app_config:
        return jsonify({'error': 'App not found'}), 404
    
    port = app_config['port']
    server_address = current_app.config.get('SERVER_ADDRESS', '40.233.70.245')
    server_domain = current_app.config.get('SERVER_DOMAIN', 'blackgrid.ddns.net')
    
    from app.utils.ssl_manager import get_main_ssl_certificate, is_certificate_trusted, _check_file_exists
    
    # Check if main Let's Encrypt certificate exists, if not, try to set it up
    try:
        cert_file, key_file = get_main_ssl_certificate()
        cert_exists = _check_file_exists(cert_file) and _check_file_exists(key_file)
    except FileNotFoundError:
        cert_exists = False
    
    if not cert_exists:
        # Try to set up Let's Encrypt certificate
        from app.utils.ssl_manager import setup_letsencrypt_certificate
        setup_success, setup_message = setup_letsencrypt_certificate(server_domain)
        if not setup_success:
            return jsonify({
                'error': f'Let\'s Encrypt certificate not found and could not be set up automatically. {setup_message}',
                'suggestion': f'Please set up Let\'s Encrypt manually by running on the server: sudo certbot certonly --standalone -d {server_domain} --non-interactive --agree-tos --register-unsafely-without-email'
            }), 500
        
        # Retry getting the certificate after setup
        try:
            cert_file, key_file = get_main_ssl_certificate()
            cert_exists = _check_file_exists(cert_file) and _check_file_exists(key_file)
        except FileNotFoundError:
            return jsonify({
                'error': 'Let\'s Encrypt certificate setup reported success but certificate files not found. Please check certbot logs.',
                'suggestion': f'Try running manually: sudo certbot certonly --standalone -d {server_domain} --non-interactive --agree-tos --register-unsafely-without-email'
            }), 500
    
    # Remove existing nginx config to force recreation
    if platform.system() == 'Linux':
        site_name = f'app-port-{port}'
        # Remove existing config if it exists
        try:
            subprocess.run(['sudo', 'rm', '-f', f'/etc/nginx/sites-enabled/{site_name}'], timeout=5, check=False)
            subprocess.run(['sudo', 'rm', '-f', f'/etc/nginx/sites-available/{site_name}'], timeout=5, check=False)
        except:
            pass  # Ignore errors if files don't exist
    
    # Recreate SSL setup with proper domain
    ssl_success, ssl_message = setup_ssl_for_app_port(port, server_address, server_domain)
    
    if not ssl_success:
        return jsonify({'error': f'Failed to fix SSL: {ssl_message}'}), 500
    
    # Get updated certificate info
    cert_file, key_file = get_main_ssl_certificate()
    cert_exists = _check_file_exists(cert_file)
    cert_trusted = is_certificate_trusted(cert_file) if cert_exists else False
    
    certificate_info = {
        'type': 'Let\'s Encrypt' if cert_trusted else 'Not trusted',
        'trusted': cert_trusted,
        'cert_path': cert_file
    }
    
    https_port = port + 10000
    message = f"SSL certificate and nginx configuration recreated for port {port}. HTTPS available on port {https_port}."
    
    if cert_trusted:
        message += " Using trusted Let's Encrypt certificate - browsers will trust it."
    else:
        message += " Certificate is not trusted. Please set up Let's Encrypt for trusted certificates."
    
    return jsonify({
        'success': True,
        'message': message,
        'certificate_info': certificate_info,
        'https_port': https_port
    })

@bp.route('/api/apps/<app_id>/restart', methods=['POST'])
@login_required
def restart_app(app_id):
    """Restart an app service"""
    try:
        app_config = AppConfig.get_by_id(app_id)
        if not app_config:
            return jsonify({'success': False, 'error': 'App not found'}), 404
        
        service_name = app_config.get('service_name', f"app-{app_config['port']}.service")
        success, message = restart_app_service(service_name)
        
        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'error': message}), 500
    except Exception as e:
        current_app.logger.error(f"Error restarting app {app_id}: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': f'Error restarting app: {str(e)}'}), 500

@bp.route('/api/restart-appmanager', methods=['POST'])
@login_required
def restart_appmanager():
    """Restart the AppManager service"""
    try:
        # Send response first before restarting (so client gets it before service stops)
        # Use a subprocess that runs independently and survives process termination
        # We'll use systemd-run or nohup to ensure the restart command executes even if this process dies
        
        # Create a command that delays then restarts (gives time for HTTP response to be sent)
        restart_command = 'sleep 1 && sudo systemctl restart appmanager.service'
        
        # Try systemd-run first (most reliable on systemd systems)
        # This creates a transient unit that runs independently of the Flask process
        try:
            subprocess.Popen(
                ['sudo', 'systemd-run', '--unit=appmanager-restart', 'sh', '-c', restart_command],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True  # Detach from parent process
            )
        except (FileNotFoundError, OSError):
            # Fallback: use nohup with a shell command
            # This works even if systemd-run is not available
            subprocess.Popen(
                ['nohup', 'sh', '-c', restart_command],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,  # Detach from parent process
                preexec_fn=os.setsid if hasattr(os, 'setsid') else None  # Create new process group (Unix only)
            )
        
        return jsonify({
            'success': True, 
            'message': 'App Manager restart initiated. You will be disconnected momentarily.'
        })
    except Exception as e:
        current_app.logger.error(f"Error initiating AppManager restart: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': f'Error initiating restart: {str(e)}'}), 500

@bp.route('/api/ssl/setup-letsencrypt', methods=['POST'])
@login_required
def setup_letsencrypt():
    """Set up Let's Encrypt certificate for the domain"""
    server_domain = current_app.config.get('SERVER_DOMAIN', 'blackgrid.ddns.net')
    email = request.form.get('email', None)
    
    success, message = setup_letsencrypt_certificate(server_domain, email)
    
    if success:
        return jsonify({'success': True, 'message': message})
    else:
        return jsonify({'error': message}), 500

@bp.route('/api/ssl/regenerate-cert', methods=['POST'])
@login_required
def regenerate_cert():
    """Set up or renew Let's Encrypt certificate for the main domain"""
    server_address = current_app.config.get('SERVER_ADDRESS', '40.233.70.245')
    server_domain = current_app.config.get('SERVER_DOMAIN', 'blackgrid.ddns.net')
    
    success, message = regenerate_main_certificate(server_address, server_domain)
    
    if success:
        # Update all child app configs to use the regenerated certificate
        from app.utils.ssl_manager import update_all_app_nginx_configs_with_new_certificate
        updated_count, total_count = update_all_app_nginx_configs_with_new_certificate()
        message += f" Updated {updated_count} of {total_count} child app configs."
        
        return jsonify({'success': True, 'message': message})
    else:
        return jsonify({'error': message}), 500

@bp.route('/api/ssl/status', methods=['GET'])
@login_required
def get_ssl_status():
    """Get SSL certificate status for all apps"""
    status = get_certificate_status_for_all_apps()
    return jsonify(status)

@bp.route('/api/debug/proxy-test/<app_slug>')
@login_required
def debug_proxy_test(app_slug):
    """Debug endpoint to test proxy connection and see detailed error information"""
    import requests
    from app.models.app_config import AppConfig
    
    app_config = AppConfig.get_by_slug(app_slug)
    if not app_config:
        return jsonify({'error': 'App not found'}), 404
    
    app_port = app_config['port']
    app_name = app_config['name']
    
    # Test direct connection
    results = {
        'app_name': app_name,
        'app_port': app_port,
        'app_slug': app_slug,
        'direct_test': None,
        'proxy_test': None,
    }
    
    # Test 1: Direct connection
    try:
        resp = requests.get(f'http://localhost:{app_port}/', timeout=5, allow_redirects=True)
        results['direct_test'] = {
            'status': resp.status_code,
            'headers': dict(resp.headers),
            'content_preview': resp.text[:500] if resp.text else None
        }
    except Exception as e:
        results['direct_test'] = {'error': str(e)}
    
    # Test 2: Simulate proxy request with headers
    try:
        headers = {
            'Host': f'localhost:{app_port}',
            'X-Forwarded-For': '127.0.0.1',
            'X-Real-IP': '127.0.0.1',
            'X-Forwarded-Proto': 'http',
        }
        resp = requests.get(f'http://localhost:{app_port}/', headers=headers, timeout=5, allow_redirects=True)
        results['proxy_test'] = {
            'status': resp.status_code,
            'headers': dict(resp.headers),
            'content_preview': resp.text[:500] if resp.text else None
        }
    except Exception as e:
        results['proxy_test'] = {'error': str(e)}
    
    return jsonify(results)

@bp.route('/apps/<app_id>/logs')
@login_required
def view_logs(app_id):
    """View logs for an application"""
    try:
        app_config = AppConfig.get_by_id(app_id)
        if not app_config:
            flash('App not found', 'error')
            return redirect(url_for('admin.dashboard'))
        
        service_name = app_config.get('service_name')
        app_name = app_config.get('name', 'Unknown')
        
        # Get logs
        lines = request.args.get('lines', 500, type=int)
        # Ensure lines is within reasonable bounds
        if lines < 1:
            lines = 100
        elif lines > 10000:
            lines = 10000
        
        success, logs_or_error, oldest_ts, newest_ts = get_app_logs(service_name, lines=lines)
        
        return render_template(
            'admin/logs.html',
            app=app_config,
            app_name=app_name,
            service_name=service_name,
            logs=logs_or_error if success else None,
            error=logs_or_error if not success else None,
            lines=lines,
            oldest_timestamp=oldest_ts or None,
            newest_timestamp=newest_ts or None
        )
    except Exception as e:
        current_app.logger.error(f"Error in view_logs: {str(e)}", exc_info=True)
        flash(f'Error loading logs: {str(e)}', 'error')
        return redirect(url_for('admin.dashboard'))

@bp.route('/api/apps/<app_id>/logs')
@login_required
def get_logs_api(app_id):
    """API endpoint for dynamic log loading"""
    app_config = AppConfig.get_by_id(app_id)
    if not app_config:
        return jsonify({'error': 'App not found'}), 404
    
    service_name = app_config.get('service_name')
    if not service_name:
        return jsonify({'error': 'Service name not configured'}), 400
    
    # Get parameters
    lines = request.args.get('lines', 500, type=int)
    since = request.args.get('since', None)  # Timestamp to load logs before (for older logs)
    until = request.args.get('until', None)  # Timestamp to load logs after (for newer logs)
    direction = request.args.get('direction', 'newer')  # 'older' or 'newer'
    
    # Build timestamp filters
    since_param = None
    until_param = None
    
    if direction == 'older' and since:
        # Load older logs (before the given timestamp)
        # Use the timestamp directly as --until parameter
        until_param = since
    elif direction == 'newer' and until:
        # Load newer logs (after the given timestamp)
        # Use the timestamp directly as --since parameter
        since_param = until
    
    success, logs_or_error, oldest_ts, newest_ts = get_app_logs(
        service_name, 
        lines=lines,
        since=since_param,
        until=until_param
    )
    
    if success:
        return jsonify({
            'success': True,
            'logs': logs_or_error,
            'oldest_timestamp': oldest_ts,
            'newest_timestamp': newest_ts,
            'has_more': len(logs_or_error.strip().split('\n')) >= lines
        })
    else:
        return jsonify({
            'success': False,
            'error': logs_or_error
        }), 500

@bp.route('/api/logs/appmanager')
@login_required
def get_appmanager_logs():
    """Get AppManager's own logs, filtered for errors and proxy issues"""
    try:
        lines = request.args.get('lines', 200, type=int)
        filter_type = request.args.get('filter', 'all')  # 'all', 'error', 'proxy', 'deltabooks'
        
        # Get AppManager service logs
        success, logs_or_error, oldest_ts, newest_ts = get_app_logs('appmanager.service', lines=lines)
        
        if not success:
            return jsonify({'error': logs_or_error}), 500
        
        # Filter logs if requested
        if filter_type == 'error':
            # Filter for ERROR level logs
            filtered_lines = [line for line in logs_or_error.split('\n') if 'ERROR' in line.upper() or 'error' in line.lower()]
            logs_or_error = '\n'.join(filtered_lines)
        elif filter_type == 'proxy':
            # Filter for proxy-related logs
            filtered_lines = [line for line in logs_or_error.split('\n') if 'proxy' in line.lower() or 'proxying' in line.lower()]
            logs_or_error = '\n'.join(filtered_lines)
        elif filter_type == 'deltabooks':
            # Filter for deltabooks-related logs
            filtered_lines = [line for line in logs_or_error.split('\n') if 'deltabooks' in line.lower() or '6002' in line]
            logs_or_error = '\n'.join(filtered_lines)
        
        return jsonify({
            'success': True,
            'logs': logs_or_error,
            'oldest_timestamp': oldest_ts,
            'newest_timestamp': newest_ts,
            'filter': filter_type
        })
    except Exception as e:
        current_app.logger.error(f"Error getting AppManager logs: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@bp.route('/api/logs/proxy-errors')
@login_required
def get_proxy_errors():
    """Get recent proxy-related errors"""
    try:
        lines = request.args.get('lines', 100, type=int)
        
        # Get AppManager service logs
        success, logs_or_error, oldest_ts, newest_ts = get_app_logs('appmanager.service', lines=lines * 2)  # Get more to filter
        
        if not success:
            return jsonify({'error': logs_or_error}), 500
        
        # Filter for errors related to proxying
        error_keywords = ['error', 'exception', 'traceback', 'failed', '500', 'proxy']
        filtered_lines = []
        for line in logs_or_error.split('\n'):
            line_lower = line.lower()
            if any(keyword in line_lower for keyword in error_keywords):
                filtered_lines.append(line)
        
        logs_or_error = '\n'.join(filtered_lines[-lines:])  # Take last N filtered lines
        
        return jsonify({
            'success': True,
            'logs': logs_or_error,
            'oldest_timestamp': oldest_ts,
            'newest_timestamp': newest_ts
        })
    except Exception as e:
        current_app.logger.error(f"Error getting proxy errors: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@bp.route('/api/terminal/execute', methods=['POST'])
@login_required
def execute_terminal_command():
    """Execute a command in the server terminal"""
    try:
        data = request.get_json()
        command = data.get('command', '').strip()
        current_dir = data.get('cwd', os.path.expanduser('~'))
        
        if not command:
            return jsonify({'error': 'No command provided'}), 400
        
        # Resolve current directory
        if current_dir == '~':
            working_dir = os.path.expanduser('~')
        elif os.path.isabs(current_dir):
            working_dir = current_dir
        else:
            working_dir = os.path.join(os.path.expanduser('~'), current_dir)
        
        working_dir = os.path.normpath(os.path.abspath(working_dir))
        
        # Security: Ensure working directory is in safe locations
        safe_directories = [
            os.path.expanduser('~'),
            '/opt/appmanager',
            '/tmp',
        ]
        
        dir_allowed = False
        for safe_dir in safe_directories:
            safe_dir_abs = os.path.abspath(safe_dir)
            # Check if working directory is within the safe directory tree
            if working_dir.startswith(safe_dir_abs + os.sep) or working_dir == safe_dir_abs:
                dir_allowed = True
                break
            # Allow parent directories as long as they're still within the safe tree
            # (e.g., /home is allowed if /home/ubuntu is safe)
            if safe_dir_abs.startswith(working_dir + os.sep) and working_dir != os.sep and working_dir != '':
                dir_allowed = True
                break
        
        if not dir_allowed:
            # Fallback to home directory if not in safe location
            working_dir = os.path.expanduser('~')
        
        # Handle cd command specially to update working directory
        new_working_dir = working_dir
        if command.startswith('cd ') or command == 'cd':
            if command == 'cd':
                # cd without arguments goes to home
                new_working_dir = os.path.expanduser('~')
                working_dir = new_working_dir
                home = os.path.expanduser('~')
                display_dir = '~'
                return jsonify({
                    'success': True,
                    'output': '',
                    'exit_code': 0,
                    'command': command,
                    'cwd': display_dir
                })
            
            cd_target = command[3:].strip() if command.startswith('cd ') else ''
            if not cd_target:
                # cd without arguments goes to home
                new_working_dir = os.path.expanduser('~')
                working_dir = new_working_dir
                home = os.path.expanduser('~')
                display_dir = '~'
                return jsonify({
                    'success': True,
                    'output': '',
                    'exit_code': 0,
                    'command': command,
                    'cwd': display_dir
                })
            elif cd_target == '-':
                # cd - goes to previous directory (we don't track this, so go to home)
                new_working_dir = os.path.expanduser('~')
                working_dir = new_working_dir
                home = os.path.expanduser('~')
                display_dir = '~'
                return jsonify({
                    'success': True,
                    'output': '',
                    'exit_code': 0,
                    'command': command,
                    'cwd': display_dir
                })
            else:
                # Resolve the target directory
                if os.path.isabs(cd_target):
                    target_dir = cd_target
                else:
                    target_dir = os.path.join(working_dir, cd_target)
                
                target_dir = os.path.normpath(os.path.abspath(target_dir))
                
                # Check if target is in safe directories
                # Allow navigation within safe directory trees, including parent directories
                # (e.g., allow cd .. from /home/ubuntu to /home, but not to /)
                target_allowed = False
                for safe_dir in safe_directories:
                    safe_dir_abs = os.path.abspath(safe_dir)
                    # Check if target is within the safe directory tree
                    if target_dir.startswith(safe_dir_abs + os.sep) or target_dir == safe_dir_abs:
                        target_allowed = True
                        break
                    # Allow parent directories as long as they're still within the safe tree
                    # (e.g., /home is allowed if /home/ubuntu is safe)
                    if safe_dir_abs.startswith(target_dir + os.sep) and target_dir != os.sep and target_dir != '':
                        target_allowed = True
                        break
                
                if target_allowed and os.path.isdir(target_dir):
                    new_working_dir = target_dir
                    # Update working_dir immediately for cd command
                    working_dir = new_working_dir
                    # Return early for cd command - don't execute it as shell command
                    home = os.path.expanduser('~')
                    if working_dir == home:
                        display_dir = '~'
                    elif working_dir.startswith(home + os.sep):
                        display_dir = '~' + working_dir[len(home):]
                    else:
                        display_dir = working_dir
                    return jsonify({
                        'success': True,
                        'output': '',  # cd commands produce no output
                        'exit_code': 0,
                        'command': command,
                        'cwd': display_dir
                    })
                elif not os.path.isdir(target_dir):
                    # Directory doesn't exist - return error
                    # Return current working directory to maintain state
                    home = os.path.expanduser('~')
                    if working_dir == home:
                        display_dir = '~'
                    elif working_dir.startswith(home + os.sep):
                        display_dir = '~' + working_dir[len(home):]
                    else:
                        display_dir = working_dir
                    return jsonify({
                        'success': False,
                        'error': f'cd: no such file or directory: {cd_target}',
                        'exit_code': 1,
                        'command': command,
                        'cwd': display_dir
                    })
                else:
                    # Directory not in safe location
                    # Return current working directory to maintain state
                    home = os.path.expanduser('~')
                    if working_dir == home:
                        display_dir = '~'
                    elif working_dir.startswith(home + os.sep):
                        display_dir = '~' + working_dir[len(home):]
                    else:
                        display_dir = working_dir
                    return jsonify({
                        'success': False,
                        'error': f'cd: permission denied: {cd_target}',
                        'exit_code': 1,
                        'command': command,
                        'cwd': display_dir
                    })
        
        # Use the (possibly updated) working directory for command execution
        working_dir = new_working_dir
        
        # Security: Whitelist of allowed commands/patterns
        # Allow common safe commands for server management
        allowed_patterns = [
            r'^ls\s', r'^ls$',
            r'^cd\s', r'^cd$',
            r'^pwd$',
            r'^cat\s', r'^head\s', r'^tail\s',
            r'^grep\s', r'^find\s',
            r'^ps\s', r'^ps$',
            r'^df\s', r'^df$',
            r'^du\s',
            r'^free\s', r'^free$',
            r'^uptime$',
            r'^whoami$',
            r'^uname\s', r'^uname$',
            r'^systemctl\s',
            r'^journalctl\s',
            r'^netstat\s', r'^ss\s',
            r'^sudo\s',  # Allow sudo since we have permissions configured
            r'^echo\s', r'^echo$',
            r'^date$',
            r'^hostname$',
            r'^ip\s', r'^ifconfig\s',
            r'^curl\s', r'^wget\s',
            r'^git\s',
            r'^python3\s', r'^python\s',
            r'^pip\s',
            r'^npm\s', r'^node\s',
            r'^docker\s',  # If docker is installed
            r'^docker-compose\s',
            r'^nginx\s',
            r'^certbot\s',
            r'^ufw\s',
            r'^iptables\s',
            r'^history$',
            r'^env$',
            r'^export\s',
            r'^source\s',
            r'^\.\s',  # Source script
            r'^mkdir\s', r'^rmdir\s',
            r'^touch\s',
            r'^chmod\s', r'^chown\s',
            r'^cp\s', r'^mv\s',
            r'^rm\s',
            r'^tar\s', r'^zip\s', r'^unzip\s',
            r'^gzip\s', r'^gunzip\s',
            r'^less\s', r'^more\s',
            r'^nano\s', r'^vim\s', r'^vi\s',  # Text editors (read-only mode recommended)
            r'^wc\s', r'^wc$',
            r'^sort\s', r'^uniq\s',
            r'^diff\s',
            r'^which\s', r'^whereis\s',
            r'^man\s',
            r'^help$',
            r'^clear$',
            # Shell script execution
            r'^bash\s', r'^sh\s', r'^\.\/',  # bash script.sh, sh script.sh, ./script.sh
        ]
        
        # Block dangerous commands
        blocked_patterns = [
            r'rm\s+-rf\s+/',  # Prevent deleting root
            r'rm\s+-rf\s+/\s',  # Prevent deleting root
            r'^dd\s',  # Disk destroyer
            r'^mkfs\s',  # Format filesystem
            r'^fdisk\s',  # Partition disk
            r'^shutdown\s', r'^reboot\s', r'^halt\s', r'^poweroff\s',  # System shutdown
            r'^>.*dev/',  # Prevent output redirection to devices
            r'^rm\s+.*\.\.\.*\/',  # Prevent deleting parent directories
        ]
        
        import re
        
        # Check blocked patterns first
        for pattern in blocked_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return jsonify({'error': f'Command blocked for security: {command}'}), 403
        
        # Check if command matches allowed patterns
        command_allowed = False
        for pattern in allowed_patterns:
            if re.match(pattern, command, re.IGNORECASE):
                command_allowed = True
                break
        
        # Special handling for shell script execution
        script_patterns = [
            r'^(bash|sh)\s+.*\.sh',  # bash script.sh or sh script.sh
            r'^\.\/.*\.sh',  # ./script.sh
            r'^bash\s+.*',  # bash with any argument (could be script)
            r'^sh\s+.*',  # sh with any argument
        ]
        
        is_script_execution = False
        for pattern in script_patterns:
            if re.match(pattern, command, re.IGNORECASE):
                is_script_execution = True
                break
        
        # If it's a script execution, validate the script path
        if is_script_execution:
            # Extract script path from command
            script_path = None
            if re.match(r'^(bash|sh)\s+(.+)', command, re.IGNORECASE):
                match = re.match(r'^(bash|sh)\s+(.+)', command, re.IGNORECASE)
                script_path = match.group(2).strip().split()[0]  # Get first argument
            elif re.match(r'^\.\/(.+)', command):
                match = re.match(r'^\.\/(.+)', command)
                script_path = match.group(1).strip().split()[0]
            
            if script_path:
                # Resolve relative paths
                # Get safe directories
                safe_directories = [
                    os.path.expanduser('~'),  # User home directory
                    '/opt/appmanager',  # AppManager deployment directory
                    '/tmp',  # Temporary directory
                ]
                
                # Resolve absolute path
                if not os.path.isabs(script_path):
                    # Relative path - resolve from current working directory (home)
                    script_path = os.path.join(os.path.expanduser('~'), script_path)
                
                script_path = os.path.normpath(script_path)
                script_path_abs = os.path.abspath(script_path)
                
                # Check if script is in a safe directory
                script_allowed = False
                for safe_dir in safe_directories:
                    safe_dir_abs = os.path.abspath(safe_dir)
                    if script_path_abs.startswith(safe_dir_abs + os.sep) or script_path_abs == safe_dir_abs:
                        script_allowed = True
                        break
                
                if not script_allowed:
                    return jsonify({
                        'error': f'Script execution not allowed: {script_path}',
                        'hint': f'Scripts must be in one of these directories: {", ".join(safe_directories)}'
                    }), 403
                
                # Check if file exists and is a .sh file (or allow if it's executable)
                if not os.path.exists(script_path_abs):
                    return jsonify({
                        'error': f'Script not found: {script_path}'
                    }), 404
                
                # Allow execution
                command_allowed = True
        
        # Also allow commands that are just shell built-ins or aliases (be careful)
        # For now, require explicit pattern match
        if not command_allowed:
            # Check if it's a simple command without arguments
            if re.match(r'^[a-zA-Z0-9_-]+$', command):
                # Single word command - might be an alias or builtin, allow it but log
                current_app.logger.warning(f"Unknown single-word command executed: {command}")
                command_allowed = True
        
        if not command_allowed:
            # Return current working directory even when command is not allowed
            home = os.path.expanduser('~')
            if working_dir == home:
                display_dir = '~'
            elif working_dir.startswith(home + os.sep):
                display_dir = '~' + working_dir[len(home):]
            else:
                display_dir = working_dir
            return jsonify({
                'error': f'Command not allowed: {command}',
                'hint': 'Only whitelisted commands are allowed for security. Contact admin to add new commands.',
                'cwd': display_dir
            }), 403
        
        # Execute command with timeout
        try:
            # Use shell=True but with restricted environment
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,  # 30 second timeout
                cwd=working_dir,  # Use the working directory (may have been changed by cd)
                env=dict(os.environ, **{
                    'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                })
            )
            
            # Combine stdout and stderr
            output = result.stdout
            if result.stderr:
                output += f"\n{result.stderr}"
            
            # Return relative path for display
            home = os.path.expanduser('~')
            if working_dir == home:
                display_dir = '~'
            elif working_dir.startswith(home + os.sep):
                display_dir = '~' + working_dir[len(home):]
            else:
                display_dir = working_dir
            
            return jsonify({
                'success': True,
                'output': output,
                'exit_code': result.returncode,
                'command': command,
                'cwd': display_dir  # Return current working directory
            })
            
        except subprocess.TimeoutExpired:
            # Return current working directory even on timeout
            home = os.path.expanduser('~')
            if working_dir == home:
                display_dir = '~'
            elif working_dir.startswith(home + os.sep):
                display_dir = '~' + working_dir[len(home):]
            else:
                display_dir = working_dir
            return jsonify({
                'error': 'Command timed out after 30 seconds',
                'command': command,
                'cwd': display_dir
            }), 408
        except Exception as e:
            # Return current working directory even on error
            home = os.path.expanduser('~')
            if working_dir == home:
                display_dir = '~'
            elif working_dir.startswith(home + os.sep):
                display_dir = '~' + working_dir[len(home):]
            else:
                display_dir = working_dir
            return jsonify({
                'error': f'Error executing command: {str(e)}',
                'command': command,
                'cwd': display_dir
            }), 500
            
    except Exception as e:
        current_app.logger.error(f"Error in execute_terminal_command: {str(e)}", exc_info=True)
        # Try to get current directory from request if available
        try:
            data = request.get_json()
            current_dir = data.get('cwd', os.path.expanduser('~')) if data else os.path.expanduser('~')
            if current_dir == '~':
                display_dir = '~'
            else:
                display_dir = current_dir
        except:
            display_dir = '~'
        return jsonify({'error': f'Server error: {str(e)}', 'cwd': display_dir}), 500

@bp.route('/api/terminal/autocomplete', methods=['POST'])
@login_required
def terminal_autocomplete():
    """Get autocomplete suggestions for file/folder paths"""
    try:
        data = request.get_json()
        partial_path = data.get('path', '').strip()
        current_dir = data.get('cwd', os.path.expanduser('~'))
        
        if not partial_path:
            return jsonify({'matches': [], 'is_directory': False})
        
        # Determine the directory and partial filename
        if '/' in partial_path or '\\' in partial_path:
            # Has path separators
            dir_part = os.path.dirname(partial_path)
            file_part = os.path.basename(partial_path)
        else:
            # Just a filename
            dir_part = '.'
            file_part = partial_path
        
        # Resolve directory path
        if os.path.isabs(dir_part):
            search_dir = dir_part
        elif dir_part == '.':
            search_dir = current_dir
        else:
            search_dir = os.path.join(current_dir, dir_part)
        
        # Normalize and get absolute path
        search_dir = os.path.normpath(search_dir)
        search_dir_abs = os.path.abspath(search_dir)
        
        # Security: Only allow searching in safe directories
        safe_directories = [
            os.path.expanduser('~'),
            '/opt/appmanager',
            '/tmp',
        ]
        
        search_allowed = False
        for safe_dir in safe_directories:
            safe_dir_abs = os.path.abspath(safe_dir)
            if search_dir_abs.startswith(safe_dir_abs + os.sep) or search_dir_abs == safe_dir_abs:
                search_allowed = True
                break
        
        if not search_allowed:
            return jsonify({'matches': [], 'is_directory': False, 'error': 'Path not in allowed directories'})
        
        # Check if directory exists
        if not os.path.isdir(search_dir_abs):
            return jsonify({'matches': [], 'is_directory': False})
        
        # Get matching files/folders
        matches = []
        try:
            for item in os.listdir(search_dir_abs):
                if item.startswith(file_part):
                    item_path = os.path.join(search_dir_abs, item)
                    is_dir = os.path.isdir(item_path)
                    matches.append({
                        'name': item,
                        'is_directory': is_dir,
                        'full_path': item_path
                    })
        except PermissionError:
            return jsonify({'matches': [], 'is_directory': False, 'error': 'Permission denied'})
        except Exception as e:
            return jsonify({'matches': [], 'is_directory': False, 'error': str(e)})
        
        # Sort: directories first, then files, both alphabetically
        matches.sort(key=lambda x: (not x['is_directory'], x['name'].lower()))
        
        # Return matches
        return jsonify({
            'matches': matches,
            'directory': search_dir_abs,
            'partial': file_part
        })
        
    except Exception as e:
        current_app.logger.error(f"Error in terminal_autocomplete: {str(e)}", exc_info=True)
        return jsonify({'matches': [], 'is_directory': False, 'error': str(e)}), 500

# Simple in-memory cache for resource stats (to minimize server load)
_resource_cache = {
    'data': None,
    'timestamp': 0,
    'ttl': 5  # Cache for 5 seconds
}

def _get_appmanager_pid():
    """Get AppManager's process ID"""
    try:
        import psutil
        from app.utils.app_manager import _get_pid_by_port
        
        # Try to get PID by port (AppManager runs on port 5000 or 80)
        # Check common ports
        for port in [5000, 80, 443]:
            pid = _get_pid_by_port(port)
            if pid:
                # Verify it's actually AppManager by checking the process name
                try:
                    proc = psutil.Process(pid)
                    proc_name = proc.name().lower()
                    cmdline = ' '.join(proc.cmdline()).lower()
                    # Check if it's a Python process running AppManager
                    if 'python' in proc_name and ('appmanager' in cmdline or 'app.py' in cmdline or 'run.py' in cmdline):
                        return pid
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        # Fallback: use current process PID (if running directly)
        # This works when AppManager is run directly, but not with WSGI servers
        return os.getpid()
    except Exception:
        # Last resort: return current process PID
        try:
            return os.getpid()
        except:
            return None

def _get_directory_size(path):
    """Get the total size of a directory in bytes"""
    try:
        total_size = 0
        if not os.path.exists(path):
            return 0
        
        if os.path.isfile(path):
            return os.path.getsize(path)
        
        # Walk through directory tree
        for dirpath, dirnames, filenames in os.walk(path):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                try:
                    total_size += os.path.getsize(filepath)
                except (OSError, PermissionError, FileNotFoundError):
                    # Skip files we can't access
                    continue
        
        return total_size
    except (OSError, PermissionError, FileNotFoundError):
        # Return 0 if we can't access the directory
        return 0

def _get_process_tree_resources(pid):
    """Get memory and CPU usage for a process and all its children"""
    try:
        import psutil
        total_memory = 0
        total_cpu = 0
        
        try:
            proc = psutil.Process(pid)
            # Get memory info (RSS - Resident Set Size)
            mem_info = proc.memory_info()
            total_memory += mem_info.rss
            
            # Get CPU percent (non-blocking)
            total_cpu += proc.cpu_percent(interval=None) or 0
            
            # Get all children
            for child in proc.children(recursive=True):
                try:
                    child_mem = child.memory_info()
                    total_memory += child_mem.rss
                    total_cpu += child.cpu_percent(interval=None) or 0
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        
        return {
            'memory_bytes': total_memory,
            'memory_gb': round(total_memory / (1024**3), 3),
            'cpu_percent': round(total_cpu, 2)
        }
    except Exception:
        return {'memory_bytes': 0, 'memory_gb': 0, 'cpu_percent': 0}

def _get_app_process_pids(app_config):
    """Get all PIDs associated with an app (by port or service)"""
    import psutil
    from app.utils.app_manager import _get_pid_by_port, _get_service_by_pid
    
    pids = set()
    port = app_config.get('port')
    service_name = app_config.get('service_name')
    
    # Method 1: Get PID by port
    if port:
        pid = _get_pid_by_port(port)
        if pid:
            pids.add(pid)
    
    # Method 2: Get PID by service name
    if service_name:
        try:
            # Try to get main PID from systemd
            result = subprocess.run(
                ['systemctl', 'show', service_name, '--property=MainPID', '--value'],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0:
                pid_str = result.stdout.strip()
                if pid_str and pid_str.isdigit():
                    pids.add(int(pid_str))
        except:
            pass
    
    # Method 3: Find all processes that might belong to this app
    # (by checking if they're listening on the port)
    if port:
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr.port == port and conn.status == 'LISTEN' and conn.pid:
                    pids.add(conn.pid)
        except:
            pass
    
    return list(pids)

@bp.route('/api/traffic', methods=['GET'])
@login_required
def get_traffic_stats():
    """Get traffic statistics (visits, unique visitors, geography, per-app breakdown)"""
    try:
        from app.utils.traffic_tracker import get_traffic_stats, add_admin_ip
        
        # Track admin IP for filtering (update on each API call in case IP changes)
        ip_address = request.headers.get('X-Forwarded-For', request.headers.get('X-Real-IP', request.remote_addr))
        if ip_address:
            ip_address = ip_address.split(',')[0].strip()
        else:
            ip_address = request.remote_addr or None
        if ip_address:
            add_admin_ip(current_app.instance_path, ip_address)
        
        days = request.args.get('days', 30, type=int)
        if days < 1 or days > 365:
            days = 30
        
        # Get include_local parameter (default to True for backward compatibility)
        include_local = request.args.get('include_local', 'true').lower() == 'true'
        
        stats = get_traffic_stats(current_app.instance_path, days=days, include_local=include_local)
        
        return jsonify({
            'success': True,
            'stats': stats
        })
    except Exception as e:
        current_app.logger.error(f"Error getting traffic stats: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@bp.route('/api/admin-logins', methods=['GET'])
@login_required
def get_admin_logins():
    """Get admin login statistics"""
    try:
        from app.utils.traffic_tracker import get_admin_login_stats
        
        # Get current IP
        ip_address = request.headers.get('X-Forwarded-For', request.headers.get('X-Real-IP', request.remote_addr))
        if ip_address:
            ip_address = ip_address.split(',')[0].strip()
        else:
            ip_address = request.remote_addr or None
        
        stats = get_admin_login_stats(current_app.instance_path, current_ip=ip_address)
        
        return jsonify({
            'success': True,
            'logins': stats
        })
    except Exception as e:
        current_app.logger.error(f"Error getting admin login stats: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@bp.route('/api/opt-folders', methods=['GET'])
@login_required
def get_opt_folders():
    """Get list of folders in /opt directory"""
    try:
        opt_path = Path('/opt')
        folders = []
        
        if opt_path.exists() and opt_path.is_dir():
            for item in opt_path.iterdir():
                if item.is_dir():
                    # Skip hidden directories and system directories
                    if not item.name.startswith('.') and item.name not in ['lost+found']:
                        folders.append(item.name)
        
        folders.sort()
        return jsonify({
            'success': True,
            'folders': folders
        })
    except Exception as e:
        current_app.logger.error(f"Error listing /opt folders: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e),
            'folders': []
        }), 500

@bp.route('/api/resources', methods=['GET'])
@login_required
def get_resource_stats():
    """Get system resource statistics (memory, disk, network)
    
    Uses caching to minimize server load. Stats are cached for 5 seconds.
    """
    import time
    
    # Check cache first
    current_time = time.time()
    if (_resource_cache['data'] is not None and 
        current_time - _resource_cache['timestamp'] < _resource_cache['ttl']):
        # Return cached data
        cached_data = _resource_cache['data'].copy()
        cached_data['cached'] = True
        return jsonify(cached_data)
    
    try:
        import psutil
        
        # Memory stats (non-blocking)
        memory = psutil.virtual_memory()
        memory_stats = {
            'total_gb': round(memory.total / (1024**3), 2),
            'available_gb': round(memory.available / (1024**3), 2),
            'used_gb': round(memory.used / (1024**3), 2),
            'percent': memory.percent,
            'free_gb': round(memory.free / (1024**3), 2)
        }
        
        # Disk stats (root partition) - can be slow on some systems, but necessary
        disk = psutil.disk_usage('/')
        disk_stats = {
            'total_gb': round(disk.total / (1024**3), 2),
            'used_gb': round(disk.used / (1024**3), 2),
            'free_gb': round(disk.free / (1024**3), 2),
            'percent': round((disk.used / disk.total) * 100, 2)
        }
        
        # Network stats (non-blocking, cumulative counters)
        net_io = psutil.net_io_counters()
        network_stats = {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv,
            'bytes_sent_gb': round(net_io.bytes_sent / (1024**3), 2),
            'bytes_recv_gb': round(net_io.bytes_recv / (1024**3), 2),
            'errors_in': net_io.errin,
            'errors_out': net_io.errout,
            'drops_in': net_io.dropin,
            'drops_out': net_io.dropout
        }
        
        # CPU stats - use non-blocking call (interval=None)
        # This is instant and doesn't block. First call returns 0, but subsequent calls are accurate.
        # Since we cache for 5 seconds, the slight delay in accuracy is acceptable.
        cpu_percent = psutil.cpu_percent(interval=None)  # Non-blocking
        cpu_stats = {
            'percent': cpu_percent if cpu_percent > 0 else 0,  # Accept 0 on first call
            'count': psutil.cpu_count()
        }
        
        # Get per-application resource breakdown
        app_resources = []
        apps = AppConfig.get_all()
        total_app_memory = 0
        total_app_cpu = 0
        appmanager_memory = 0
        appmanager_cpu = 0
        
        # Get AppManager's own memory usage
        appmanager_pid = _get_appmanager_pid()
        if appmanager_pid:
            appmanager_resources = _get_process_tree_resources(appmanager_pid)
            appmanager_memory = appmanager_resources['memory_bytes']
            appmanager_cpu = appmanager_resources['cpu_percent']
        
        for app in apps:
            app_pids = _get_app_process_pids(app)
            if app_pids:
                app_memory_bytes = 0
                app_cpu_percent = 0
                
                for pid in app_pids:
                    resources = _get_process_tree_resources(pid)
                    app_memory_bytes += resources['memory_bytes']
                    app_cpu_percent += resources['cpu_percent']
                
                app_memory_gb = round(app_memory_bytes / (1024**3), 3)
                app_memory_percent = round((app_memory_bytes / memory.total) * 100, 2) if memory.total > 0 else 0
                
                total_app_memory += app_memory_bytes
                total_app_cpu += app_cpu_percent
                
                # Get disk usage for this app (check /opt/{folder_path} if specified)
                folder_path = app.get('folder_path')
                if folder_path:
                    app_disk_path = f'/opt/{folder_path}'
                else:
                    # Fallback: try to guess from app name
                    app_name = app.get('name', '').lower().replace(' ', '-')
                    app_disk_path = f'/opt/{app_name}'
                app_disk_bytes = _get_directory_size(app_disk_path)
                app_disk_gb = round(app_disk_bytes / (1024**3), 3)
                
                app_resources.append({
                    'app_id': app.get('id'),
                    'app_name': app.get('name'),
                    'port': app.get('port'),
                    'memory_gb': app_memory_gb,
                    'memory_percent': app_memory_percent,
                    'cpu_percent': round(app_cpu_percent, 2),
                    'disk_gb': app_disk_gb,
                    'disk_percent': round((app_disk_bytes / disk.total) * 100, 3) if disk.total > 0 else 0,
                    'pids': app_pids
                })
        
        # Get AppManager disk usage
        appmanager_disk_path = '/opt/appmanager'
        appmanager_disk_bytes = _get_directory_size(appmanager_disk_path)
        appmanager_disk_gb = round(appmanager_disk_bytes / (1024**3), 2)
        
        # Calculate system and other usage
        total_app_memory_gb = round(total_app_memory / (1024**3), 2)
        appmanager_memory_gb = round(appmanager_memory / (1024**3), 2)
        system_memory_gb = round(memory.total / (1024**3) * 0.1, 2)  # Estimate ~10% for system
        other_memory_gb = round((memory.used - total_app_memory - appmanager_memory) / (1024**3), 2)
        other_memory_gb = max(0, other_memory_gb - system_memory_gb)  # Subtract system estimate
        
        # Calculate disk breakdown
        total_app_disk = sum(r.get('disk_gb', 0) * (1024**3) for r in app_resources)
        other_disk_bytes = disk.used - total_app_disk - appmanager_disk_bytes
        other_disk_gb = round(max(0, other_disk_bytes) / (1024**3), 2)
        
        result = {
            'success': True,
            'memory': memory_stats,
            'disk': disk_stats,
            'network': network_stats,
            'cpu': cpu_stats,
            'timestamp': time.time(),
            'cached': False,
            'apps': app_resources,
            'appmanager': {
                'memory_gb': appmanager_memory_gb,
                'memory_percent': round((appmanager_memory / memory.total) * 100, 2) if memory.total > 0 else 0,
                'cpu_percent': round(appmanager_cpu, 2),
                'disk_gb': appmanager_disk_gb,
                'disk_percent': round((appmanager_disk_bytes / disk.total) * 100, 2) if disk.total > 0 else 0
            },
            'breakdown': {
                'apps': {
                    'memory_gb': total_app_memory_gb,
                    'memory_percent': round((total_app_memory / memory.total) * 100, 2) if memory.total > 0 else 0,
                    'cpu_percent': round(total_app_cpu, 2)
                },
                'system': {
                    'memory_gb': system_memory_gb,
                    'memory_percent': round((system_memory_gb * 1024**3 / memory.total) * 100, 2) if memory.total > 0 else 0,
                    'cpu_percent': round(max(0, cpu_percent - total_app_cpu - appmanager_cpu), 2)
                },
                'other': {
                    'memory_gb': other_memory_gb,
                    'memory_percent': round((other_memory_gb * 1024**3 / memory.total) * 100, 2) if memory.total > 0 else 0,
                    'cpu_percent': 0,  # Hard to track accurately
                    'disk_gb': other_disk_gb,
                    'disk_percent': round((other_disk_bytes / disk.total) * 100, 2) if disk.total > 0 else 0
                }
            }
        }
        
        # Update cache
        _resource_cache['data'] = result.copy()
        _resource_cache['timestamp'] = current_time
        
        return jsonify(result)
    except Exception as e:
        current_app.logger.error(f"Error getting resource stats: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@bp.route('/api/config/shutdown-timeout', methods=['GET'])
@login_required
def get_shutdown_timeout():
    """Get the auto-shutdown timeout in minutes"""
    try:
        tracker = get_tracker(current_app.instance_path)
        timeout = tracker.get_shutdown_timeout_minutes()
        return jsonify({
            'success': True,
            'timeout_minutes': timeout
        })
    except Exception as e:
        current_app.logger.error(f"Error getting shutdown timeout: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@bp.route('/api/config/shutdown-timeout', methods=['POST'])
@login_required
def set_shutdown_timeout():
    """Set the auto-shutdown timeout in minutes"""
    try:
        data = request.get_json()
        timeout = data.get('timeout_minutes')
        
        if timeout is None:
            return jsonify({
                'success': False,
                'error': 'timeout_minutes is required'
            }), 400
        
        try:
            timeout = int(timeout)
            if timeout < 1 or timeout > 1440:  # 1 minute to 24 hours
                return jsonify({
                    'success': False,
                    'error': 'timeout_minutes must be between 1 and 1440 (24 hours)'
                }), 400
        except (ValueError, TypeError):
            return jsonify({
                'success': False,
                'error': 'timeout_minutes must be a number'
            }), 400
        
        tracker = get_tracker(current_app.instance_path)
        tracker.set_shutdown_timeout_minutes(timeout)
        
        return jsonify({
            'success': True,
            'timeout_minutes': timeout,
            'message': f'Auto-shutdown timeout set to {timeout} minutes'
        })
    except Exception as e:
        current_app.logger.error(f"Error setting shutdown timeout: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@bp.route('/api/config/env-vars', methods=['GET'])
@login_required
def get_env_vars():
    """Get environment variables configuration"""
    try:
        # Load from manager_config.json
        config_path = Path(current_app.instance_path) / 'manager_config.json'
        env_vars = {}
        
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    env_vars = config.get('env_vars', {})
            except Exception as e:
                current_app.logger.warning(f"Error loading env vars: {e}")
        
        return jsonify({
            'success': True,
            'env_vars': env_vars
        })
    except Exception as e:
        current_app.logger.error(f"Error getting env vars: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@bp.route('/api/config/env-vars', methods=['POST'])
@login_required
def set_env_vars():
    """Set environment variables configuration"""
    try:
        data = request.get_json()
        env_vars = data.get('env_vars', {})
        
        if not isinstance(env_vars, dict):
            return jsonify({
                'success': False,
                'error': 'env_vars must be an object'
            }), 400
        
        # Load existing config
        config_path = Path(current_app.instance_path) / 'manager_config.json'
        config = {}
        
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
            except Exception as e:
                current_app.logger.warning(f"Error loading config: {e}")
        
        # Update env vars
        config['env_vars'] = env_vars
        
        # Save config
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        return jsonify({
            'success': True,
            'env_vars': env_vars,
            'message': 'Environment variables updated successfully'
        })
    except Exception as e:
        current_app.logger.error(f"Error setting env vars: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@bp.route('/uploads/<path:filename>')
def uploaded_file(filename):
    """Serve uploaded files (public access for logos)"""
    instance_path = Path(current_app.instance_path)
    # Route is /blackgrid/admin/uploads/<filename>, so filename should be relative to instance/uploads/
    # If filename is 'logos/file.png', we need to serve 'instance/uploads/logos/file.png'
    # If filename already includes 'uploads/', strip it (for backward compatibility)
    if filename.startswith('uploads/'):
        # Already has uploads/ prefix, use as-is
        return send_from_directory(instance_path, filename)
    else:
        # Prepend 'uploads/' to get correct path relative to instance directory
        return send_from_directory(instance_path, f'uploads/{filename}')

