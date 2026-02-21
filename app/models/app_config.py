"""
App configuration model for managing registered apps.

IMPORTANT: Read `instructions/architecture` before making changes.
"""
import json
import os
from pathlib import Path
from typing import List, Dict, Optional
import uuid
import re

class AppConfig:
    """Model for managing app configurations"""
    
    _config_file = None
    
    @staticmethod
    def _slugify(name: str) -> str:
        """Convert app name to URL-safe slug"""
        # Convert to lowercase
        slug = name.lower()
        # Replace spaces and special characters with hyphens
        slug = re.sub(r'[^\w\s-]', '', slug)
        slug = re.sub(r'[-\s]+', '-', slug)
        # Remove leading/trailing hyphens
        slug = slug.strip('-')
        return slug

    # URL-safe slug: only lowercase letters, numbers, hyphens; no leading/trailing hyphen
    _URL_SAFE_SLUG_RE = re.compile(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?$')

    @classmethod
    def _is_url_safe_slug(cls, s: str) -> bool:
        """Return True if s is empty or a URL-safe slug (only a-z, 0-9, hyphens)."""
        s = (s or '').strip()
        if not s:
            return True
        return bool(cls._URL_SAFE_SLUG_RE.match(s))

    @classmethod
    def get_effective_slug(cls, app: Dict) -> str:
        """Return the slug used for routing: explicit slug if set, else slugify(name)."""
        explicit = (app.get('slug') or '').strip()
        if explicit:
            return explicit
        return cls._slugify(app.get('name', ''))

    @classmethod
    def _get_config_path(cls):
        """Get path to app config file"""
        if cls._config_file is None:
            instance_path = Path(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
            instance_path = instance_path / 'instance'
            instance_path.mkdir(exist_ok=True)
            cls._config_file = instance_path / 'apps_config.json'
        return cls._config_file
    
    @classmethod
    def _load_config(cls) -> Dict:
        """Load app configurations from file"""
        config_path = cls._get_config_path()
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    data = json.load(f)
                    return data if isinstance(data, dict) else {'apps': []}
            except:
                pass
        
        return {'apps': []}
    
    @classmethod
    def _save_config(cls, config: Dict):
        """Save app configurations to file"""
        config_path = cls._get_config_path()
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
    
    @classmethod
    def get_all(cls) -> List[Dict]:
        """Get all app configurations"""
        config = cls._load_config()
        apps = config.get('apps', [])
        # Ensure serve_app and auto_start fields exist for existing apps
        for app in apps:
            if 'serve_app' not in app:
                app['serve_app'] = True
            if 'auto_start' not in app:
                app['auto_start'] = False
        return apps
    
    @classmethod
    def get_served_apps(cls) -> List[Dict]:
        """Get all app configurations where serve_app is True"""
        apps = cls.get_all()
        return [app for app in apps if app.get('serve_app', True)]
    
    @classmethod
    def get_by_id(cls, app_id: str) -> Optional[Dict]:
        """Get app configuration by ID"""
        apps = cls.get_all()
        for app in apps:
            if app.get('id') == app_id:
                return app
        return None
    
    @classmethod
    def get_by_slug(cls, slug: str) -> Optional[Dict]:
        """Get app configuration by URL-safe slug (explicit slug or slugify(name))."""
        apps = cls.get_all()
        for app in apps:
            if cls.get_effective_slug(app) == slug:
                return app
        return None
    
    @classmethod
    def get_by_port(cls, port: int) -> Optional[Dict]:
        """Get app configuration by port number"""
        apps = cls.get_all()
        for app in apps:
            app_port = app.get('port')
            if app_port and int(app_port) == port:
                return app
        return None
    
    @classmethod
    def create(cls, name: str, port: int, logo: Optional[str] = None, service_name: Optional[str] = None, serve_app: bool = True, folder_path: Optional[str] = None, windows_path: Optional[str] = None, windows_start_command: Optional[str] = None, slug: Optional[str] = None) -> Dict:
        """Create a new app configuration. Slug defaults to slugify(name) if not provided."""
        apps = cls.get_all()
        new_slug = (slug or '').strip() or cls._slugify(name)
        new_slug = cls._slugify(new_slug)  # normalize user-entered slug
        if not new_slug:
            raise ValueError("Slug cannot be empty.")
        if new_slug == 'blackgrid':
            raise ValueError("'blackgrid' is a reserved slug and cannot be used.")
        for app in apps:
            if cls.get_effective_slug(app) == new_slug:
                raise ValueError(f"An app with slug '{new_slug}' already exists. Please choose a different slug or name.")
        app_config = {
            'id': str(uuid.uuid4()),
            'name': name,
            'port': int(port),
            'logo': logo,
            'service_name': service_name or f"app-{port}.service",
            'serve_app': serve_app,
            'auto_start': False,
            'folder_path': folder_path,
            'windows_path': windows_path,
            'windows_start_command': windows_start_command or 'python app.py',
            'slug': new_slug,
        }
        apps.append(app_config)
        config = cls._load_config()
        config['apps'] = apps
        cls._save_config(config)
        return app_config
    
    @classmethod
    def update(cls, app_id: str, name: str = None, port: int = None, logo: str = None, service_name: str = None, serve_app: bool = None, auto_start: bool = None, folder_path: str = None, windows_path: str = None, windows_start_command: str = None, slug: str = None) -> Optional[Dict]:
        """Update an existing app configuration. Slug is independent of name and used for path-based URLs."""
        apps = cls.get_all()
        for app in apps:
            if app.get('id') == app_id:
                if name is not None:
                    app['name'] = name
                if slug is not None:
                    raw = (slug or '').strip()
                    if not raw:
                        app['slug'] = None  # use derived from name
                    else:
                        new_slug = cls._slugify(raw)
                        if not new_slug:
                            raise ValueError("Slug cannot be empty.")
                        if not cls._is_url_safe_slug(new_slug):
                            raise ValueError("Slug must be URL-safe: only lowercase letters, numbers, and hyphens (no spaces or special characters).")
                        if new_slug == 'blackgrid':
                            raise ValueError("'blackgrid' is a reserved slug and cannot be used.")
                        for other_app in apps:
                            if other_app.get('id') != app_id and cls.get_effective_slug(other_app) == new_slug:
                                raise ValueError(f"Another app already uses slug '{new_slug}'. Please choose a different slug.")
                        app['slug'] = new_slug
                if port is not None:
                    app['port'] = int(port)
                if logo is not None:
                    app['logo'] = logo
                if service_name is not None:
                    app['service_name'] = service_name
                if serve_app is not None:
                    app['serve_app'] = serve_app
                if auto_start is not None:
                    app['auto_start'] = auto_start
                if folder_path is not None:
                    app['folder_path'] = folder_path
                if windows_path is not None:
                    app['windows_path'] = windows_path
                if windows_start_command is not None:
                    app['windows_start_command'] = windows_start_command
                
                config = cls._load_config()
                config['apps'] = apps
                cls._save_config(config)
                
                return app
        
        return None
    
    @classmethod
    def toggle_serve_app(cls, app_id: str) -> Optional[Dict]:
        """Toggle the serve_app status for an app"""
        app = cls.get_by_id(app_id)
        if app:
            current_status = app.get('serve_app', True)
            return cls.update(app_id, serve_app=not current_status)
        return None
    
    @classmethod
    def delete(cls, app_id: str) -> bool:
        """Delete an app configuration"""
        apps = cls.get_all()
        original_count = len(apps)
        
        apps = [app for app in apps if app.get('id') != app_id]
        
        if len(apps) < original_count:
            config = cls._load_config()
            config['apps'] = apps
            cls._save_config(config)
            return True
        
        return False

