"""
User model for authentication.

IMPORTANT: Read `instructions/architecture` before making changes.
"""
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
import json
import os
from pathlib import Path

class User(UserMixin):
    """User model for admin authentication"""
    
    # Default bootstrap credentials (created only if instance/admin_config.json is missing).
    # NOTE: This is a security risk for production. Change immediately after first run.
    _DEFAULT_ADMIN_USERNAME = "LastTerminal"
    # Hash for password "WhiteMage" (pbkdf2:sha256). Stored as a hash (not plaintext).
    _DEFAULT_ADMIN_PASSWORD_HASH = "pbkdf2:sha256:600000$Sa5OLzkyXmKq7Wvy$54863281fa88a576c3fc39da43fcb0d3ae15a274873a0501fec2ac77c36ad56e"
    
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

        # Bootstrap configuration:
        # 1) Environment variables (preferred)
        username = (os.environ.get("APP_MANAGER_ADMIN_USERNAME") or cls._DEFAULT_ADMIN_USERNAME).strip()
        password = os.environ.get("APP_MANAGER_ADMIN_PASSWORD")
        password_hash = os.environ.get("APP_MANAGER_ADMIN_PASSWORD_HASH")

        if password_hash:
            cfg = {"username": username, "password_hash": password_hash}
            cls._save_config(cfg)
            return cfg

        if password:
            cfg = {"username": username, "password_hash": generate_password_hash(password)}
            cls._save_config(cfg)
            return cfg

        # 2) Default credentials (backwards-compatible behavior)
        cfg = {"username": cls._DEFAULT_ADMIN_USERNAME, "password_hash": cls._DEFAULT_ADMIN_PASSWORD_HASH}
        cls._save_config(cfg)
        return cfg
    
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

