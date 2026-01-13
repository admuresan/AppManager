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
    
    return app

