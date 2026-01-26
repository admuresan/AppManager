# Configuring Your App for AppManager Proxy

This guide explains how to configure your application to work properly when proxied by AppManager. AppManager uses a reverse proxy that forwards requests from `https://domain.com/appname/path` to `http://localhost:PORT/path`, and your app needs to be configured to handle this correctly.

## Overview

When AppManager proxies requests to your app, it:
- Rewrites URLs from `domain.com/appname/path` → `localhost:PORT/path`
- Sets X-Forwarded-* headers to inform your app about the original request
- Handles WebSocket upgrades
- Manages SSL/HTTPS termination

Your app must use **ProxyFix middleware** to read these headers and generate correct URLs.

---

## Step 1: Install ProxyFix Middleware

### For Flask Applications

If your app uses Flask, install Werkzeug (which includes ProxyFix):

```bash
pip install werkzeug
```

Or if using requirements.txt:

```txt
werkzeug>=2.0.0
```

### For Other Python Frameworks

- **Django**: Use `django.middleware.security.SecurityMiddleware` with `SECURE_PROXY_SSL_HEADER`
- **FastAPI**: Use `ProxyHeadersMiddleware` from `starlette.middleware`
- **Other frameworks**: Check for proxy-aware middleware or implement X-Forwarded-* header handling

---

## Step 2: Configure ProxyFix Middleware

### Flask/Werkzeug Configuration

Add ProxyFix middleware to your Flask application **before** creating routes:

```python
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)

# Configure ProxyFix middleware - MUST be before routes
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,      # Number of proxies in front (AppManager = 1)
    x_proto=1,    # Trust X-Forwarded-Proto header
    x_host=1,     # Trust X-Forwarded-Host header
    x_port=1,     # Trust X-Forwarded-Port header
    x_prefix=1    # Trust X-Forwarded-Prefix header
)

# Now define your routes
@app.route('/')
def index():
    return 'Hello, World!'
```

### Complete Example

Here's a complete example of a Flask app configured for AppManager:

```python
from flask import Flask, url_for, request
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'

# CRITICAL: Configure ProxyFix BEFORE defining routes
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1,
    x_port=1,
    x_prefix=1
)

@app.route('/')
def index():
    # These will now generate correct URLs based on X-Forwarded-* headers
    home_url = url_for('index', _external=True)
    api_url = url_for('api_endpoint', _external=True)
    
    return f'''
    <h1>My App</h1>
    <p>Home URL: {home_url}</p>
    <p>API URL: {api_url}</p>
    <p>Current URL: {request.url}</p>
    <p>Is Secure: {request.is_secure}</p>
    '''
    
@app.route('/api/data')
def api_endpoint():
    return {'status': 'ok', 'url': request.url}

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5001, debug=True)
```

---

## Step 3: Understanding URL Generation

### How URLs Are Generated

With ProxyFix configured, your app will automatically:

1. **Detect HTTPS**: `request.is_secure` will be `True` when accessed via HTTPS
2. **Use correct domain**: `url_for(..., _external=True)` will use the public domain
3. **Include prefix**: URLs will include the `/appname` prefix automatically
4. **Use correct port**: Port 443 (HTTPS) or 80 (HTTP) will be used

### Example URL Generation

If your app is registered as "My App" (slug: `my-app`) and accessed via `https://example.com/my-app/`:

```python
# Without ProxyFix (WRONG):
url_for('index', _external=True)
# → http://localhost:5001/  ❌

# With ProxyFix (CORRECT):
url_for('index', _external=True)
# → https://example.com/my-app/  ✅
```

### Static Files and Assets

For static files, use Flask's `url_for`:

```python
# In templates
<img src="{{ url_for('static', filename='logo.png') }}">

# In Python code
logo_url = url_for('static', filename='logo.png', _external=True)
```

---

## Step 4: WebSocket Support

If your app uses WebSocket (e.g., Socket.IO), ensure:

### 1. ProxyFix is Configured

ProxyFix handles WebSocket upgrade headers automatically.

### 2. Use Correct WebSocket URLs

```python
# Flask-SocketIO example
from flask_socketio import SocketIO

socketio = SocketIO(app, cors_allowed_origins="*")

@socketio.on('connect')
def handle_connect():
    print('Client connected')
```

### 3. Client-Side Configuration

In your JavaScript, use relative URLs or generate URLs server-side:

```javascript
// ❌ WRONG - hardcoded localhost
const socket = io('http://localhost:5001');

// ✅ CORRECT - relative URL (works with proxy)
const socket = io();

// ✅ CORRECT - generate URL server-side
const socket = io('{{ url_for("socketio_connect", _external=True) }}');
```

---

## Step 5: Testing Your Configuration

### Test 1: Check ProxyFix is Working

Create a test route to verify headers:

```python
@app.route('/debug/proxy')
def debug_proxy():
    """Debug endpoint to check proxy headers"""
    return {
        'remote_addr': request.remote_addr,
        'is_secure': request.is_secure,
        'host': request.host,
        'url': request.url,
        'base_url': request.base_url,
        'headers': dict(request.headers)
    }
```

Access via AppManager: `https://domain.com/appname/debug/proxy`

Expected results:
- `is_secure`: `True` (if using HTTPS)
- `host`: Should show the public domain
- `url`: Should include the `/appname` prefix

### Test 2: Verify URL Generation

```python
@app.route('/test/urls')
def test_urls():
    """Test URL generation"""
    return {
        'index_url': url_for('index', _external=True),
        'current_url': request.url,
        'base_url': request.base_url
    }
```

All URLs should use the public domain and include the app prefix.

### Test 3: Check Redirects

```python
from flask import redirect, url_for

@app.route('/redirect-test')
def redirect_test():
    # This should redirect to the correct public URL
    return redirect(url_for('index', _external=True))
```

---

## Step 6: Common Issues and Solutions

### Issue 1: URLs Still Show localhost

**Problem**: `url_for(..., _external=True)` returns `http://localhost:PORT`

**Solution**: 
- Ensure ProxyFix is configured **before** routes are defined
- Check that `x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1` are all set
- Verify AppManager is sending X-Forwarded-* headers (check `/debug/proxy`)

### Issue 2: HTTPS Not Detected

**Problem**: `request.is_secure` returns `False` even when accessing via HTTPS

**Solution**:
- Ensure `x_proto=1` is set in ProxyFix configuration
- Check that AppManager is setting `X-Forwarded-Proto: https` header

### Issue 3: Missing App Prefix in URLs

**Problem**: URLs don't include `/appname` prefix

**Solution**:
- Ensure `x_prefix=1` is set in ProxyFix configuration
- Verify AppManager is setting `X-Forwarded-Prefix: /appname` header

### Issue 4: WebSocket Connections Fail

**Problem**: WebSocket upgrade requests fail

**Solution**:
- Ensure ProxyFix is configured (it handles upgrade headers)
- Use relative URLs for WebSocket connections
- Check that AppManager is passing through `Upgrade` and `Connection` headers

### Issue 5: Static Files Return 404

**Problem**: CSS/JS/images don't load

**Solution**:
- Use `url_for('static', filename='...')` instead of hardcoded paths
- Ensure static files are in the `static/` directory
- Check that URLs include the app prefix

---

## Step 7: Production Checklist

Before deploying, verify:

- [ ] ProxyFix middleware is configured with all 5 parameters (`x_for`, `x_proto`, `x_host`, `x_port`, `x_prefix`)
- [ ] ProxyFix is configured **before** routes are defined
- [ ] All `url_for(..., _external=True)` calls generate correct public URLs
- [ ] `request.is_secure` correctly detects HTTPS
- [ ] Static files load correctly (check browser DevTools Network tab)
- [ ] Redirects use correct URLs (no localhost in Location header)
- [ ] WebSocket connections work (if applicable)
- [ ] Forms submit to correct URLs
- [ ] API endpoints return correct URLs in responses

---

## Step 8: Register with AppManager

After configuring your app:

1. **Start your app** on a specific port (e.g., `127.0.0.1:5001`)
2. **Access AppManager** admin dashboard
3. **Add your app** with:
   - **Name**: Display name (will be converted to URL slug)
   - **Port**: The port your app is listening on
   - **Service Name**: Optional systemd service name
4. **Test access** via `https://domain.com/appname/`

---

## Additional Notes

### Port Configuration

- Your app should listen on `127.0.0.1` or `localhost` (not `0.0.0.0`)
- Use any port except: 80, 443, 5000 (reserved)
- AppManager handles firewall rules and SSL automatically

### Security Considerations

- ProxyFix validates X-Forwarded-* headers based on `x_for=1` (trusts 1 proxy)
- Never trust X-Forwarded-* headers from untrusted sources
- AppManager validates and sets these headers securely

### Performance

- ProxyFix has minimal performance impact
- URL generation is cached by Flask
- Static files are served efficiently through the proxy

---

## Example: Complete Flask App Template

```python
from flask import Flask, render_template, url_for, request, redirect
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.config['SECRET_KEY'] = 'change-this-in-production'

# CRITICAL: Configure ProxyFix FIRST
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1,
    x_port=1,
    x_prefix=1
)

@app.route('/')
def index():
    return render_template('index.html', 
                         home_url=url_for('index', _external=True))

@app.route('/api/status')
def api_status():
    return {
        'status': 'ok',
        'url': request.url,
        'is_secure': request.is_secure
    }

@app.route('/redirect')
def redirect_example():
    # This will redirect to the correct public URL
    return redirect(url_for('index', _external=True))

if __name__ == '__main__':
    # Listen on localhost only
    app.run(host='127.0.0.1', port=5001, debug=False)
```

---

## Support

If you encounter issues:

1. Check the `/debug/proxy` endpoint to verify headers
2. Review AppManager logs for proxy errors
3. Verify your app is listening on the correct port
4. Test direct access: `http://localhost:PORT` (should work)
5. Test proxied access: `https://domain.com/appname/` (should work with ProxyFix)

For more information, see the AppManager documentation or contact your system administrator.


