"""
Main entry point for AppManager.

IMPORTANT: Read `instructions/architecture` before making changes.
"""
import os
import logging
from app import create_app

app = create_app()

if __name__ == '__main__':
    # Port: PORT env only. deploy_config.json is shared (server/user/password) and has no port.
    port = int(os.environ.get("PORT", 80))
    
    # Enable debug mode by default for local development
    # Set FLASK_ENV=production to disable debug mode
    debug = os.environ.get('FLASK_ENV') != 'production'
    
    # For local development, use localhost; for production, use 0.0.0.0
    host = '127.0.0.1' if debug else '0.0.0.0'
    
    logging.basicConfig(level=logging.INFO)
    logging.getLogger(__name__).info("Starting AppManager on http://%s:%s", host, port)
    logging.getLogger(__name__).info("Environment: %s", "Development" if debug else "Production")
    logging.getLogger(__name__).info("Debug mode: %s (auto-reload enabled)", "ON" if debug else "OFF")
    
    app.run(host=host, port=port, debug=debug)

