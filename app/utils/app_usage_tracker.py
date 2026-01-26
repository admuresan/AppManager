"""
App usage tracker for monitoring app access and managing auto-shutdown
"""
import json
import time
import threading
from pathlib import Path
from typing import Dict, Optional
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class AppUsageTracker:
    """Tracks app usage and manages auto-shutdown"""
    
    def __init__(self, instance_path: str):
        self.instance_path = Path(instance_path)
        self.data_file = self.instance_path / 'data' / 'app_usage.json'
        self.data_file.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._data = self._load_data()
        self._shutdown_thread = None
        self._running = False
    
    def _load_data(self) -> Dict:
        """Load usage data from file"""
        if self.data_file.exists():
            try:
                with open(self.data_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading app usage data: {e}")
        return {
            'last_access': {},
            'active_tabs': {},
            'shutdown_timeout_minutes': 15
        }
    
    def _save_data(self):
        """Save usage data to file"""
        try:
            with open(self.data_file, 'w') as f:
                json.dump(self._data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving app usage data: {e}")
    
    def record_access(self, app_slug: str):
        """Record that an app was accessed"""
        with self._lock:
            self._data['last_access'][app_slug] = time.time()
            self._save_data()
    
    def get_last_access(self, app_slug: str) -> Optional[float]:
        """Get last access time for an app (Unix timestamp)"""
        with self._lock:
            return self._data['last_access'].get(app_slug)
    
    def register_active_tab(self, app_slug: str, session_id: str):
        """Register that a browser tab is active for an app"""
        with self._lock:
            if app_slug not in self._data['active_tabs']:
                self._data['active_tabs'][app_slug] = {}
            self._data['active_tabs'][app_slug][session_id] = time.time()
            # Also update last access
            self._data['last_access'][app_slug] = time.time()
            self._save_data()
    
    def unregister_active_tab(self, app_slug: str, session_id: str):
        """Unregister a browser tab for an app"""
        with self._lock:
            if app_slug in self._data['active_tabs']:
                if session_id in self._data['active_tabs'][app_slug]:
                    del self._data['active_tabs'][app_slug][session_id]
                if not self._data['active_tabs'][app_slug]:
                    del self._data['active_tabs'][app_slug]
            self._save_data()
    
    def has_active_tabs(self, app_slug: str) -> bool:
        """Check if an app has any active browser tabs"""
        with self._lock:
            tabs = self._data['active_tabs'].get(app_slug, {})
            # Clean up stale tabs (older than 2 minutes without heartbeat)
            current_time = time.time()
            active_tabs = {
                sid: last_heartbeat 
                for sid, last_heartbeat in tabs.items()
                if current_time - last_heartbeat < 120  # 2 minutes
            }
            # Update if we removed stale tabs
            if len(active_tabs) != len(tabs):
                if active_tabs:
                    self._data['active_tabs'][app_slug] = active_tabs
                elif app_slug in self._data['active_tabs']:
                    del self._data['active_tabs'][app_slug]
                self._save_data()
            return len(active_tabs) > 0
    
    def get_shutdown_timeout_minutes(self) -> int:
        """Get the shutdown timeout in minutes"""
        with self._lock:
            return self._data.get('shutdown_timeout_minutes', 15)
    
    def set_shutdown_timeout_minutes(self, minutes: int):
        """Set the shutdown timeout in minutes"""
        with self._lock:
            self._data['shutdown_timeout_minutes'] = minutes
            self._save_data()
    
    def should_shutdown(self, app_slug: str) -> bool:
        """Check if an app should be shut down"""
        with self._lock:
            # Don't shutdown if there are active tabs
            if self.has_active_tabs(app_slug):
                return False
            
            # Check last access time
            last_access = self._data['last_access'].get(app_slug)
            if not last_access:
                return False
            
            timeout_seconds = self.get_shutdown_timeout_minutes() * 60
            time_since_access = time.time() - last_access
            
            return time_since_access >= timeout_seconds
    
    def start_auto_shutdown_monitor(self, shutdown_callback):
        """Start the background thread that monitors and shuts down unused apps"""
        if self._running:
            return
        
        self._running = True
        
        def monitor_loop():
            while self._running:
                try:
                    # Check every minute
                    time.sleep(60)
                    
                    if not self._running:
                        break
                    
                    # Get all apps that should be shut down
                    from app.models.app_config import AppConfig
                    apps = AppConfig.get_all()
                    
                    for app in apps:
                        if not app.get('serve_app', True):
                            continue
                        
                        app_slug = AppConfig._slugify(app.get('name', ''))
                        if not app_slug:
                            continue
                        
                        if self.should_shutdown(app_slug):
                            # Call the shutdown callback
                            try:
                                shutdown_callback(app)
                            except Exception as e:
                                logger.error(f"Error shutting down app {app_slug}: {e}")
                
                except Exception as e:
                    logger.error(f"Error in auto-shutdown monitor: {e}")
        
        self._shutdown_thread = threading.Thread(target=monitor_loop, daemon=True)
        self._shutdown_thread.start()
        logger.info("Auto-shutdown monitor started")
    
    def stop_auto_shutdown_monitor(self):
        """Stop the background thread"""
        self._running = False
        if self._shutdown_thread:
            self._shutdown_thread.join(timeout=5)
        logger.info("Auto-shutdown monitor stopped")

# Global instance
_tracker_instance = None

def get_tracker(instance_path: str) -> AppUsageTracker:
    """Get or create the global tracker instance"""
    global _tracker_instance
    if _tracker_instance is None:
        _tracker_instance = AppUsageTracker(instance_path)
    return _tracker_instance

