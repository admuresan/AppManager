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
from pathlib import Path
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from app.models.user import User
from app.models.app_config import AppConfig
from app.utils.app_manager import test_app_port, restart_app_service, detect_service_name_by_port, get_active_ports_and_services, configure_firewall_port
from app.utils.ssl_manager import setup_ssl_for_app_port, setup_letsencrypt_certificate, regenerate_main_certificate, get_certificate_status_for_all_apps, _check_file_exists

bp = Blueprint('admin', __name__, url_prefix='/admin')

@bp.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    """Handle 413 Request Entity Too Large errors"""
    return jsonify({
        'error': 'File too large. Maximum file size is 20MB. If you\'re using nginx, ensure client_max_body_size is set to at least 20m in your nginx configuration.'
    }), 413

@bp.route('/login', methods=['GET', 'POST'])
def login():
    """Admin login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.get_by_username(username)
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('admin.dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
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
            logo_path = f"uploads/logos/{unique_filename}"
    
    try:
        app_config = AppConfig.create(
            name=name,
            port=port,
            logo=logo_path,
            service_name=service_name if service_name else None
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
            service_name=service_name if service_name else None
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

def test_url(url, timeout=3):
    """Test if a URL is accessible"""
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
        
        # Disable SSL verification warnings for self-signed certificates
        response = session.get(url, timeout=timeout, verify=False, allow_redirects=True)
        return True, response.status_code
    except requests.exceptions.SSLError:
        # SSL error but connection was attempted - port is open
        return True, 'SSL_ERROR'
    except requests.exceptions.ConnectionError:
        return False, 'CONNECTION_ERROR'
    except requests.exceptions.Timeout:
        return False, 'TIMEOUT'
    except Exception as e:
        return False, str(e)

@bp.route('/api/apps/<app_id>/test', methods=['POST'])
@login_required
def test_app(app_id):
    """Test if an app is listening on both HTTP and HTTPS ports"""
    app_config = AppConfig.get_by_id(app_id)
    if not app_config:
        return jsonify({'error': 'App not found'}), 404
    
    port = app_config['port']
    server_address = current_app.config.get('SERVER_ADDRESS', 'localhost')
    server_domain = current_app.config.get('SERVER_DOMAIN', None)
    
    # Test HTTP on original port (try server_address first, then localhost as fallback)
    http_url = f"http://{server_address}:{port}"
    http_accessible, http_status = test_url(http_url)
    http_test_url = http_url
    
    # If server_address test failed and it's not localhost, try localhost
    if not http_accessible and server_address != 'localhost':
        localhost_url = f"http://localhost:{port}"
        localhost_accessible, localhost_status = test_url(localhost_url)
        if localhost_accessible:
            http_accessible = True
            http_status = localhost_status
            http_test_url = localhost_url
    
    # Test HTTPS on port + 10000
    # Prefer domain over IP for HTTPS (matches SSL certificate configuration)
    https_port = port + 10000
    if server_domain and server_domain != 'localhost':
        https_host = server_domain
    else:
        https_host = server_address
    
    # Test HTTPS with domain first (if available)
    https_url = f"https://{https_host}:{https_port}"
    https_accessible, https_status = test_url(https_url)
    https_test_url = https_url
    
    # If domain test failed and we used domain, also try IP as fallback
    if not https_accessible and server_domain and server_domain != 'localhost' and server_address != 'localhost':
        https_url_ip = f"https://{server_address}:{https_port}"
        https_accessible_ip, https_status_ip = test_url(https_url_ip)
        if https_accessible_ip:
            https_accessible = True
            https_status = https_status_ip
            https_test_url = https_url_ip
    
    # Also test if port is listening (socket level)
    is_listening = test_app_port(port)
    
    # Check if nginx is configured for HTTPS
    from app.utils.ssl_manager import is_nginx_configured_for_port
    nginx_configured = is_nginx_configured_for_port(port)
    
    return jsonify({
        'success': True,
        'port': port,
        'http': {
            'accessible': http_accessible,
            'status': http_status,
            'url': http_test_url
        },
        'https': {
            'accessible': https_accessible,
            'status': https_status,
            'url': https_test_url,
            'port': https_port,
            'nginx_configured': nginx_configured
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
    app_config = AppConfig.get_by_id(app_id)
    if not app_config:
        return jsonify({'error': 'App not found'}), 404
    
    service_name = app_config.get('service_name', f"app-{app_config['port']}.service")
    success, message = restart_app_service(service_name)
    
    if success:
        return jsonify({'success': True, 'message': message})
    else:
        return jsonify({'error': message}), 500

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

@bp.route('/uploads/<path:filename>')
def uploaded_file(filename):
    """Serve uploaded files (public access for logos)"""
    instance_path = Path(current_app.instance_path)
    return send_from_directory(instance_path, filename)

