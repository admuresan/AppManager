"""
AppManager - Gateway application for managing multiple Flask apps
"""
from flask import Flask
from flask_login import LoginManager
import os
from pathlib import Path

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'admin.login'
login_manager.login_message = 'Please log in to access the admin panel.'

def create_app():
    """Create and configure the Flask application"""
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024  # 20MB max file size
    # Server address for direct port links (defaults to localhost for development)
    # Set SERVER_ADDRESS environment variable to override (e.g., your-domain.com or IP address)
    app.config['SERVER_ADDRESS'] = os.environ.get('SERVER_ADDRESS', 'localhost')
    # Server domain name for SSL certificates (defaults to blackgrid.ddns.net)
    # Set SERVER_DOMAIN environment variable to override
    app.config['SERVER_DOMAIN'] = os.environ.get('SERVER_DOMAIN', 'blackgrid.ddns.net')
    
    # Ensure Flask knows it's behind a proxy (for HTTPS detection)
    # This is important when running behind nginx with SSL termination
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=1,
        x_proto=1,
        x_host=1,
        x_port=1,
        x_prefix=1
    )
    
    # Ensure instance folder exists for config and uploads
    instance_path = Path(app.instance_path)
    instance_path.mkdir(exist_ok=True)
    (instance_path / 'uploads' / 'logos').mkdir(parents=True, exist_ok=True)
    
    # Initialize Flask-Login
    login_manager.init_app(app)
    
    # Register blueprints
    from app.routes import welcome, admin, proxy
    app.register_blueprint(welcome.bp)
    app.register_blueprint(admin.bp)
    app.register_blueprint(proxy.bp)
    
    # Import User model for login manager
    from app.models.user import User
    
    @login_manager.user_loader
    def load_user(user_id):
        """Load user by user_id (which is the username in this app)"""
        if not user_id:
            return None
        # user_id should be a string (username), not an integer
        # Handle any edge cases gracefully
        try:
            return User.get_by_username(str(user_id))
        except (ValueError, TypeError, AttributeError):
            return None
    
    @login_manager.unauthorized_handler
    def unauthorized():
        """Handle unauthorized access - return JSON for API routes, redirect for pages"""
        from flask import request, jsonify, redirect, url_for
        # Check if this is an API request (starts with /api/ or Accept header wants JSON)
        if request.path.startswith('/admin/api/') or request.accept_mimetypes.best_match(['application/json', 'text/html']) == 'application/json':
            return jsonify({
                'success': False,
                'error': 'Authentication required',
                'login_required': True
            }), 401
        # Otherwise redirect to login page
        return redirect(url_for('admin.login'))
    
    # Add traffic tracking hook
    @app.before_request
    def track_traffic():
        """Track all incoming requests for traffic statistics"""
        try:
            from app.utils.traffic_tracker import track_visit
            from flask import request
            
            # Skip tracking for static files and API endpoints that are called frequently
            if request.endpoint in ('static', 'admin.get_resource_stats', 'admin.get_traffic_stats'):
                return
            
            # Determine app name based on route
            # Default: group all non-mapped apps together as "App Manager"
            app_name = 'App Manager'
            
            if request.blueprint == 'proxy':
                # Extract app slug from path
                path_parts = request.path.strip('/').split('/')
                if path_parts:
                    app_slug = path_parts[0]
                    from app.models.app_config import AppConfig
                    try:
                        app_config = AppConfig.get_by_slug(app_slug)
                        if app_config:
                            # This is a mapped/proxied app - use its actual name
                            app_name = app_config.get('name', app_slug)
                        else:
                            # Unmapped proxy route - group with App Manager
                            app_name = 'App Manager'
                    except:
                        # Error looking up app - group with App Manager
                        app_name = 'App Manager'
            # All other routes (welcome, admin, etc.) are grouped as "App Manager"
            # No need for elif - app_name already defaults to 'App Manager'
            
            # Get client IP (handle proxy headers)
            ip_address = request.headers.get('X-Forwarded-For', request.headers.get('X-Real-IP', request.remote_addr))
            if ip_address:
                # X-Forwarded-For can contain multiple IPs, take the first one
                ip_address = ip_address.split(',')[0].strip()
            else:
                ip_address = request.remote_addr or 'unknown'
            
            # Get user agent
            user_agent = request.headers.get('User-Agent', 'unknown')
            
            # Get referrer
            referrer = request.headers.get('Referer') or request.referrer
            
            # Track the visit (non-blocking, runs in background)
            try:
                track_visit(
                    instance_path=app.instance_path,
                    app_name=app_name,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    path=request.path,
                    referrer=referrer
                )
            except Exception as e:
                # Don't fail the request if tracking fails
                app.logger.warning(f"Traffic tracking error: {e}")
        except Exception:
            # Silently fail - don't break the app if tracking has issues
            pass
    
    return app

