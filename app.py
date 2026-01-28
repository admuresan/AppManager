"""
Main entry point for AppManager.

IMPORTANT: Read `instructions/architecture` before making changes.
"""
import os
import json
from pathlib import Path
import logging
from app import create_app

app = create_app()

if __name__ == '__main__':
    # Port configuration must come from ssh/deploy_config.json (architecture requirement).
    # Environment variable PORT can override for local/dev convenience.
    cfg_path = Path(__file__).resolve().parent / "ssh" / "deploy_config.json"
    cfg = {}
    try:
        if cfg_path.exists():
            cfg = json.loads(cfg_path.read_text(encoding="utf-8")) or {}
    except Exception:
        cfg = {}

    default_port = int(cfg.get("server_port", 5000))
    port = int(os.environ.get("PORT", default_port))
    
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

