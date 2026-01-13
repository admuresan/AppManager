"""
Main entry point for AppManager
"""
import os
from app import create_app

app = create_app()

if __name__ == '__main__':
    # Get port from environment
    # Default to 5000 for local development, 80 for production
    # Set PORT environment variable to override
    default_port = 5000 if os.environ.get('FLASK_ENV') == 'development' else 80
    port = int(os.environ.get('PORT', default_port))
    
    # Enable debug mode by default for local development
    # Set FLASK_ENV=production to disable debug mode
    debug = os.environ.get('FLASK_ENV') != 'production'
    
    # For local development, use localhost; for production, use 0.0.0.0
    host = '127.0.0.1' if debug else '0.0.0.0'
    
    print(f"Starting AppManager on http://{host}:{port}")
    print(f"Environment: {'Development' if debug else 'Production'}")
    print(f"Debug mode: {'ON' if debug else 'OFF'} (auto-reload enabled)")
    
    app.run(host=host, port=port, debug=debug)

