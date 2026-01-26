"""
App configuration model for managing registered apps
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
        # Ensure serve_app field exists for existing apps (defaults to True)
        for app in apps:
            if 'serve_app' not in app:
                app['serve_app'] = True
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
        """Get app configuration by URL-safe slug (app name)"""
        apps = cls.get_all()
        for app in apps:
            app_slug = cls._slugify(app.get('name', ''))
            if app_slug == slug:
                return app
        return None
    
    @classmethod
    def create(cls, name: str, port: int, logo: Optional[str] = None, service_name: Optional[str] = None, serve_app: bool = True, folder_path: Optional[str] = None) -> Dict:
        """Create a new app configuration"""
        apps = cls.get_all()
        
        # Prevent apps from being named "blackgrid" (reserved for AppManager)
        if cls._slugify(name) == 'blackgrid':
            raise ValueError("'blackgrid' is a reserved name and cannot be used for app names.")
        
        # Check for duplicate slugs
        new_slug = cls._slugify(name)
        for app in apps:
            if cls._slugify(app.get('name', '')) == new_slug:
                raise ValueError(f"An app with a similar name already exists. Please choose a different name.")
        
        app_config = {
            'id': str(uuid.uuid4()),
            'name': name,
            'port': int(port),
            'logo': logo,
            'service_name': service_name or f"app-{port}.service",
            'serve_app': serve_app,
            'folder_path': folder_path
        }
        
        apps.append(app_config)
        config = cls._load_config()
        config['apps'] = apps
        cls._save_config(config)
        
        return app_config
    
    @classmethod
    def update(cls, app_id: str, name: str = None, port: int = None, logo: str = None, service_name: str = None, serve_app: bool = None, folder_path: str = None) -> Optional[Dict]:
        """Update an existing app configuration"""
        apps = cls.get_all()
        
        for app in apps:
            if app.get('id') == app_id:
                if name is not None:
                    # Prevent apps from being named "blackgrid" (reserved for AppManager)
                    if cls._slugify(name) == 'blackgrid':
                        raise ValueError("'blackgrid' is a reserved name and cannot be used for app names.")
                    
                    # Check for duplicate slugs (excluding current app)
                    new_slug = cls._slugify(name)
                    for other_app in apps:
                        if other_app.get('id') != app_id and cls._slugify(other_app.get('name', '')) == new_slug:
                            raise ValueError(f"An app with a similar name already exists. Please choose a different name.")
                    app['name'] = name
                if port is not None:
                    app['port'] = int(port)
                if logo is not None:
                    app['logo'] = logo
                if service_name is not None:
                    app['service_name'] = service_name
                if serve_app is not None:
                    app['serve_app'] = serve_app
                if folder_path is not None:
                    app['folder_path'] = folder_path
                
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

