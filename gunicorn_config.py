"""
Gunicorn configuration for AppManager production deployment
"""
import multiprocessing
import os

# Server socket
bind = f"0.0.0.0:{os.environ.get('PORT', '5000')}"
backlog = 2048

# Worker processes
# For I/O-bound apps (like proxying), use async workers (gevent)
# Each gevent worker can handle many concurrent connections (up to worker_connections)
# With async workers, we need fewer processes since each handles many requests concurrently
# Formula: CPU cores + 1 is typical for gevent (each worker handles up to worker_connections requests)
workers = multiprocessing.cpu_count() + 1
worker_class = 'gevent'  # Use async workers for I/O-bound operations (proxying, network I/O)
worker_connections = 1000  # Max concurrent connections per worker
timeout = 60
keepalive = 5

# Logging
accesslog = '-'  # Log to stdout
errorlog = '-'   # Log to stderr
loglevel = os.environ.get('LOG_LEVEL', 'info').lower()
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = 'appmanager'

# Server mechanics
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

# SSL (if needed - usually handled by nginx)
keyfile = None
certfile = None

