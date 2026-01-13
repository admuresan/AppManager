"""
User model for authentication
"""
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
import json
import os
from pathlib import Path

class User(UserMixin):
    """User model for admin authentication"""
    
    _config_file = None
    
    @classmethod
    def _get_config_path(cls):
        """Get path to user config file"""
        if cls._config_file is None:
            # Use instance folder (not git-backed)
            instance_path = Path(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
            instance_path = instance_path / 'instance'
            instance_path.mkdir(exist_ok=True)
            cls._config_file = instance_path / 'admin_config.json'
        return cls._config_file
    
    @classmethod
    def _load_config(cls):
        """Load user configuration from file"""
        config_path = cls._get_config_path()
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    return json.load(f)
            except:
                pass
        
        # Default configuration
        default_config = {
            'username': 'LastTerminal',
            'password_hash': generate_password_hash('WhiteMage')
        }
        cls._save_config(default_config)
        return default_config
    
    @classmethod
    def _save_config(cls, config):
        """Save user configuration to file"""
        config_path = cls._get_config_path()
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
    
    @classmethod
    def get_by_username(cls, username):
        """Get user by username"""
        config = cls._load_config()
        if config.get('username') == username:
            user = User()
            user.id = username  # Flask-Login uses 'id' attribute
            user.username = username
            user.password_hash = config.get('password_hash')
            # UserMixin provides: is_active, is_authenticated, is_anonymous, get_id()
            return user
        return None
    
    def check_password(self, password):
        """Check if password matches"""
        return check_password_hash(self.password_hash, password)
    
    @classmethod
    def update_password(cls, username, new_password):
        """Update user password"""
        config = cls._load_config()
        if config.get('username') == username:
            config['password_hash'] = generate_password_hash(new_password)
            cls._save_config(config)
            return True
        return False

