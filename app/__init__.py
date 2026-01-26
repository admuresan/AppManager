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
    
    # Root route: redirect domain (no slash) to welcome page
    @app.route('/')
    def root():
        """Redirect root to welcome page"""
        from flask import redirect, url_for
        return redirect(url_for('welcome.index'))
    
    # Handle favicon requests - serve app logo from manager based on Referer
    @app.route('/favicon.ico')
    def favicon():
        """Handle favicon requests by serving the app's logo from the manager based on Referer header"""
        from flask import request, send_from_directory, abort
        from urllib.parse import urlparse
        from pathlib import Path
        
        # Get Referer header to determine which app the user is viewing
        referer = request.headers.get('Referer') or request.referrer
        
        if referer:
            try:
                # Parse the referer URL to extract the app slug
                parsed = urlparse(referer)
                path = parsed.path.strip('/')
                
                # Extract first path segment as app slug
                if path:
                    path_parts = path.split('/')
                    app_slug = path_parts[0]
                    
                    # Verify it's not the manager prefix
                    if app_slug and app_slug != 'blackgrid':
                        # Check if app exists and get its logo
                        from app.models.app_config import AppConfig
                        try:
                            app_config = AppConfig.get_by_slug(app_slug)
                            if app_config and app_config.get('serve_app', True):
                                logo_path = app_config.get('logo')
                                
                                if logo_path:
                                    # Handle different logo path formats
                                    # Logo path can be: "logos/filename.png" or "uploads/logos/filename.png"
                                    instance_path = Path(app.instance_path)
                                    
                                    # Normalize the path
                                    if logo_path.startswith('uploads/'):
                                        # Already has uploads/ prefix
                                        file_path = instance_path / logo_path
                                    elif logo_path.startswith('logos/'):
                                        # Has logos/ prefix, add uploads/
                                        file_path = instance_path / 'uploads' / logo_path
                                    else:
                                        # Just filename, assume it's in uploads/logos/
                                        file_path = instance_path / 'uploads' / 'logos' / logo_path
                                    
                                    # Check if file exists and serve it
                                    if file_path.exists() and file_path.is_file():
                                        # Determine content type based on file extension
                                        ext = file_path.suffix.lower()
                                        content_type_map = {
                                            '.ico': 'image/x-icon',
                                            '.png': 'image/png',
                                            '.jpg': 'image/jpeg',
                                            '.jpeg': 'image/jpeg',
                                            '.gif': 'image/gif',
                                            '.svg': 'image/svg+xml',
                                            '.webp': 'image/webp'
                                        }
                                        content_type = content_type_map.get(ext, 'image/png')
                                        
                                        # Serve the logo file
                                        return send_from_directory(
                                            file_path.parent,
                                            file_path.name,
                                            mimetype=content_type
                                        )
                        except Exception:
                            # If lookup fails, fall through to 404
                            pass
            except Exception:
                # If parsing fails, fall through to 404
                pass
        
        # No valid referer, app not found, or no logo - return 404
        abort(404)
    
    # Register blueprints
    # IMPORTANT: Register /blackgrid/ routes BEFORE proxy routes
    # This ensures /blackgrid/ is handled by AppManager, not proxied
    from app.routes import welcome, admin, proxy
    app.register_blueprint(welcome.bp)  # /blackgrid/
    app.register_blueprint(admin.bp)    # /blackgrid/admin/
    app.register_blueprint(proxy.bp)    # /<app_slug>/ (catches everything else)
    
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
        if request.path.startswith('/blackgrid/admin/api/') or request.accept_mimetypes.best_match(['application/json', 'text/html']) == 'application/json':
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
            
            # Check if this is a proxied app (not /blackgrid/)
            if request.blueprint == 'proxy':
                # Extract app slug from path
                path_parts = request.path.strip('/').split('/')
                if path_parts:
                    app_slug = path_parts[0]
                    # Skip if it's blackgrid (shouldn't happen, but defensive)
                    if app_slug != 'blackgrid':
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
    
    # Auto-shutdown monitor disabled - apps will not be automatically shut down
    # Initialize and start auto-shutdown monitor
    # try:
    #     from app.utils.app_usage_tracker import get_tracker
    #     from app.utils.app_manager import stop_app_service, test_app_port
    #     
    #     tracker = get_tracker(app.instance_path)
    #     
    #     def shutdown_callback(app_config):
    #         """Callback to shut down an unused app"""
    #         service_name = app_config.get('service_name')
    #         if not service_name:
    #             return
    #         
    #         # Check if app is actually running
    #         port = app_config.get('port')
    #         if port and test_app_port(port):
    #             # App is running, shut it down
    #             success, message = stop_app_service(service_name)
    #             if success:
    #                 app.logger.info(f"Auto-shutdown: Stopped {app_config.get('name')} ({service_name})")
    #             else:
    #                 app.logger.warning(f"Auto-shutdown: Failed to stop {app_config.get('name')}: {message}")
    #     
    #     # Start the monitor
    #     tracker.start_auto_shutdown_monitor(shutdown_callback)
    # except Exception as e:
    #     app.logger.error(f"Error initializing auto-shutdown monitor: {e}")
    
    return app

# Create app instance for WSGI servers (gunicorn, etc.)
# This allows gunicorn to load 'app:app' where 'app' is the package and 'app' is the Flask instance
app = create_app()

