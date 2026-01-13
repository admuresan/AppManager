"""
Welcome page routes
"""
from flask import Blueprint, render_template, session, redirect, url_for, request, current_app, send_from_directory
from app.models.app_config import AppConfig
from app.utils.ssl_manager import is_nginx_configured_for_port
from pathlib import Path

bp = Blueprint('welcome', __name__)

def get_server_address():
    """Get the server address for direct port links"""
    # Check if SERVER_ADDRESS is configured
    server_address = current_app.config.get('SERVER_ADDRESS', 'localhost')
    
    # If it's localhost and we're in production, try to detect from request
    if server_address == 'localhost' and current_app.config.get('ENV') != 'development':
        # Use the request host (without port) as fallback
        host = request.host.split(':')[0]
        if host and host != '127.0.0.1':
            return host
    
    return server_address

@bp.route('/')
def index():
    """Welcome page showing available apps"""
    # Only show apps where serve_app is True
    apps = AppConfig.get_served_apps()
    server_address = get_server_address()
    
    # Always include the manager app
    manager_app = {
        'id': 'manager',
        'name': 'App Manager',
        'port': None,
        'logo': None,
        'is_manager': True
    }
    
    return render_template('welcome.html', apps=apps, manager_app=manager_app, server_address=server_address)

@bp.route('/media/<path:filename>')
def media_file(filename):
    """Serve media files from app/media directory"""
    media_path = Path(current_app.root_path) / 'media'
    response = send_from_directory(media_path, filename)
    # Ensure PNG files are served with correct content type to preserve transparency
    if filename.lower().endswith('.png'):
        response.headers['Content-Type'] = 'image/png'
    return response

@bp.route('/select/<app_id>')
def select_app(app_id):
    """Select an app to use - redirects to proxy route using app name (masks port)"""
    if app_id == 'manager':
        return redirect(url_for('admin.dashboard'))
    
    app_config = AppConfig.get_by_id(app_id)
    if not app_config:
        return redirect(url_for('welcome.index'))
    
    # Get URL-safe slug from app name
    app_slug = AppConfig._slugify(app_config['name'])
    
    # Get server domain/address for building URL
    server_address = get_server_address()
    server_domain = current_app.config.get('SERVER_DOMAIN', None)
    
    # Determine the host to use (prefer domain over IP)
    # In production, prefer domain name for better SSL trust and cleaner URLs
    if current_app.config.get('ENV') == 'development':
        host = server_address
    else:
        # Prefer domain over IP for production
        host = server_domain if server_domain and server_domain != 'localhost' else server_address
    
    # Build URL using domain name and app slug path (no port exposed)
    # Use the same protocol as the current request
    protocol = 'https' if request.is_secure else 'http'
    
    # If we have a domain and it's not localhost, use it
    # Otherwise use the server address
    if host and host != 'localhost' and host != '127.0.0.1':
        app_url = f"{protocol}://{host}/{app_slug}"
    else:
        # Fallback for development/localhost - use url_for to build URL
        app_url = url_for('proxy.proxy_path', app_slug=app_slug, path='', _external=True)
    
    return redirect(app_url)

