# Proxy Flow Analysis: App "quizia" with Routes `/quizia/alpha` and `/alpha`

## Scenario Setup

- **App name:** "quizia" (slug: `quizia`)
- **App port:** 6005
- **App internal routes:**
  - `@app.route('/quizia/alpha')` → Handler for `/quizia/alpha`
  - `@app.route('/alpha')` → Handler for `/alpha`
- **ProxyFix:** Configured with `x_prefix=1`

## Desired Behavior

1. **Route `/quizia/alpha`:**
   - Browser URL: `https://domain.com/quizia/quizia/alpha`
   - Proxy strips first prefix: `/quizia/alpha`
   - App receives: `/quizia/alpha` ✅

2. **Route `/alpha`:**
   - Browser URL: `https://domain.com/quizia/alpha`
   - Proxy strips prefix: `/alpha`
   - App receives: `/alpha` ✅

---

## Step-by-Step Flow WITHOUT Our Rewriting

### Request 1: Browser → `https://domain.com/quizia/quizia/alpha`

**Step 1: Browser makes request**
- URL: `https://domain.com/quizia/quizia/alpha`
- Method: GET

**Step 2: AppManager proxy receives request**
- Route matches: `/<app_slug>/<path:path>` where `app_slug='quizia'`, `path='quizia/alpha'`
- Proxy extracts: `app_slug = 'quizia'`, `path = 'quizia/alpha'`

**Step 3: Proxy forwards to app**
- Target URL: `http://localhost:6005/quizia/alpha`
- Sets headers:
  - `X-Forwarded-Prefix: /quizia`
  - `X-Forwarded-Host: domain.com`
  - `X-Forwarded-Proto: https`
  - `Host: localhost:6005`

**Step 4: App receives request (with ProxyFix)**
- ProxyFix reads `X-Forwarded-Prefix: /quizia`
- ProxyFix modifies `request.path`: Strips `/quizia` prefix → `request.path = '/quizia/alpha'`
- App sees: `request.path = '/quizia/alpha'`
- Matches route: `@app.route('/quizia/alpha')` ✅

**Step 5: App generates HTML response**
```python
# In template or Python code:
url_for('quizia_alpha_route')  # Route name for /quizia/alpha
```
- ProxyFix processes `url_for()`:
  - Reads `X-Forwarded-Prefix: /quizia`
  - Takes route path: `/quizia/alpha`
  - Adds prefix: `/quizia` + `/quizia/alpha` = `/quizia/quizia/alpha` ✅
- HTML generated: `<a href="/quizia/quizia/alpha">Link to Alpha</a>` ✅

**Step 6: Browser receives HTML**
- Sees: `<a href="/quizia/quizia/alpha">`
- When user clicks: Browser makes request to `/quizia/quizia/alpha` ✅
- Works correctly! (No rewriting needed - ProxyFix handled it)

### Request 2: Browser → `https://domain.com/quizia/alpha`

**Step 1: Browser makes request**
- URL: `https://domain.com/quizia/alpha`
- Method: GET

**Step 2: AppManager proxy receives request**
- Route matches: `/<app_slug>/<path:path>` where `app_slug='quizia'`, `path='alpha'`
- Proxy extracts: `app_slug = 'quizia'`, `path = 'alpha'`

**Step 3: Proxy forwards to app**
- Target URL: `http://localhost:6005/alpha`
- Sets headers:
  - `X-Forwarded-Prefix: /quizia`
  - `X-Forwarded-Host: domain.com`
  - `X-Forwarded-Proto: https`
  - `Host: localhost:6005`

**Step 4: App receives request (with ProxyFix)**
- ProxyFix reads `X-Forwarded-Prefix: /quizia`
- ProxyFix modifies `request.path`: Strips `/quizia` prefix → `request.path = '/alpha'`
- App sees: `request.path = '/alpha'`
- Matches route: `@app.route('/alpha')` ✅

**Step 5: App generates HTML response**
```python
# In template or Python code:
url_for('alpha_route')  # Route name for /alpha
```
- ProxyFix processes `url_for()`:
  - Reads `X-Forwarded-Prefix: /quizia`
  - Takes route path: `/alpha`
  - Adds prefix: `/quizia` + `/alpha` = `/quizia/alpha` ✅
- HTML generated: `<a href="/quizia/alpha">Link to Alpha</a>` ✅

**Step 6: Browser receives HTML**
- Sees: `<a href="/quizia/alpha">`
- When user clicks: Browser makes request to `/quizia/alpha` ✅
- Works correctly! (No rewriting needed - ProxyFix handled it)

### JavaScript Code: `fetch('/api/calculate')`

**Step 1: App's JavaScript code (in HTML or .js file)**
```javascript
// This is hardcoded in JavaScript - ProxyFix does NOT process this
fetch('/api/calculate', {
    method: 'POST',
    body: JSON.stringify(data)
})
```

**Step 2: Browser executes JavaScript**
- JavaScript calls `fetch('/api/calculate')`
- Browser makes request to: `/api/calculate` ❌ (WRONG - missing `/quizia/` prefix)
- Request goes to: `https://domain.com/api/calculate` (not `https://domain.com/quizia/api/calculate`)

**Step 3: AppManager proxy receives request**
- Request URL: `https://domain.com/api/calculate`
- This doesn't match proxy route `/<app_slug>/<path>` (no app slug)
- Returns 404 or routes to wrong handler ❌

**PROBLEM:** Client-side JavaScript URLs are NOT processed by ProxyFix!

---

## Where We Need Rewriting

### ✅ Server-Side URLs (Already Correct - No Rewriting Needed)

**HTML attributes from templates:**
- `<a href="{{ url_for('route') }}">` → ProxyFix adds prefix → Already correct ✅
- `<form action="{{ url_for('submit') }}">` → ProxyFix adds prefix → Already correct ✅
- `<img src="{{ url_for('static', filename='logo.png') }}">` → ProxyFix adds prefix → Already correct ✅

**Python redirects:**
- `redirect(url_for('index'))` → ProxyFix adds prefix → Already correct ✅

**Action:** Do NOT rewrite these - they're already correct from ProxyFix. We don't touch HTML content.

### ❌ Client-Side JavaScript URLs (Need Rewriting)

**JavaScript fetch/XHR calls:**
- `fetch('/api/calculate')` → Should be `/quizia/api/calculate` ❌
- `XMLHttpRequest.open('GET', '/api/data')` → Should be `/quizia/api/data` ❌
- `window.location.href = '/dashboard'` → Should be `/quizia/dashboard` ❌
- `element.setAttribute('href', '/page')` → Should be `/quizia/page` ❌

**Action:** Intercept these JavaScript functions and add prefix.

---

## Our Rewriting Logic (Where It Happens)

### Step-by-Step with Our Rewriting:

**Step 1: App generates HTML**
```html
<!-- Server-side (from template) - ProxyFix handles this -->
<a href="/quizia/alpha">Link</a>  ✅ Already correct

<!-- JavaScript code - ProxyFix does NOT handle this -->
<script>
    fetch('/api/calculate', {...})  ❌ Needs prefix
</script>
```

**Step 2: AppManager injects our script**
- We inject client-side script into HTML `<head>`
- Script overrides `window.fetch`, `XMLHttpRequest`, etc.

**Step 3: Browser loads page**
- HTML link: `<a href="/quizia/alpha">` → Works correctly (already has prefix)
- JavaScript executes: `fetch('/api/calculate')`

**Step 4: Our script intercepts (THIS IS WHERE WE REWRITE)**
```javascript
// Our override intercepts the fetch call
window.fetch = function(url, ...args) {
    url = rewriteUrl(url);  // <-- HERE: We rewrite the URL
    return originalFetch.call(this, url, ...args);
};

function rewriteUrl(url) {
    // url = '/api/calculate'
    // Check: Does it start with '/quizia/'? No
    // Add prefix: '/quizia/api/calculate' ✅
    return '/quizia/api/calculate';
}
```

**Step 5: Browser makes request**
- Request to: `https://domain.com/quizia/api/calculate` ✅ (now has prefix)

**Step 6: Proxy receives request**
- Route matches: `/<app_slug>/<path>` where `app_slug='quizia'`, `path='api/calculate'`
- Strips prefix: `/api/calculate`
- Forwards to app: `http://localhost:6005/api/calculate` ✅

**Step 7: App receives request**
- App sees: `request.path = '/api/calculate'` ✅
- Matches route: `@app.route('/api/calculate')` ✅

---

## Summary

**Without our rewriting:**
- ✅ Server-side URLs work (ProxyFix handles `url_for()`)
- ❌ Client-side JavaScript URLs fail (ProxyFix can't process hardcoded JS strings)

**With our rewriting:**
- ✅ Server-side URLs work (we don't touch HTML - ProxyFix already handled them)
- ✅ Client-side JavaScript URLs work (we intercept JS functions and add prefix)

**Key Point:** We only rewrite URLs that come from client-side JavaScript function calls (`fetch`, `XHR`, `location.href`, `setAttribute`), not from server-side HTML generation.
