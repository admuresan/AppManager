# URL Prefix Logic Analysis - Based on Function Processing

## Specific Case Analysis: `/investmentcalculator/investmentcalculator/api/calculate`

**URL Type:** Client-side JavaScript `fetch()` call
- **Original URL in app code:** `fetch('/api/calculate', ...)` (hardcoded relative URL in JavaScript)
- **What changed it on app side:** ❌ NOTHING - ProxyFix does NOT process client-side JavaScript code. ProxyFix only affects server-side URL generation via `url_for()`.
- **What changed it on AppManager side:** ✅ The client-side script's `rewriteUrl()` function intercepted the fetch call and added prefix. However, it was added TWICE, resulting in double-prefixing.

**Root Cause:** The `rewriteUrl()` function is checking if a URL already has a prefix using string matching, but this check is unreliable. Instead, we should track whether a URL has been processed by our function, not whether it contains a prefix string.

## Complete Table: All URL Types and Processing

| URL Type | Source | App Function That Processes It | AppManager Function That Processes It | Should AppManager Process? | How to Prevent Double-Processing |
|----------|--------|-------------------------------|--------------------------------------|----------------------------|----------------------------------|
| **HTML href attribute** | Server-side template | `url_for()` → ProxyFix adds prefix | `rewrite_urls_in_content()` (server-side regex) | ❌ NO - Already processed by ProxyFix | Don't process server-side HTML at all |
| **HTML src attribute** | Server-side template | `url_for()` → ProxyFix adds prefix | `rewrite_urls_in_content()` (server-side regex) | ❌ NO - Already processed by ProxyFix | Don't process server-side HTML at all |
| **HTML action attribute** | Server-side template | `url_for()` → ProxyFix adds prefix | `rewrite_urls_in_content()` (server-side regex) | ❌ NO - Already processed by ProxyFix | Don't process server-side HTML at all |
| **CSS url() in stylesheet** | Server-side template or CSS file | `url_for('static', ...)` → ProxyFix adds prefix | `rewrite_urls_in_content()` (server-side regex) | ❌ NO - Already processed by ProxyFix | Don't process CSS at all |
| **JavaScript fetch() call** | Client-side JavaScript code | ❌ NONE - ProxyFix doesn't process JS | `window.fetch` override → `rewriteUrl()` | ✅ YES - Must process | Track processed URLs, don't process same URL twice |
| **JavaScript XMLHttpRequest** | Client-side JavaScript code | ❌ NONE - ProxyFix doesn't process JS | `XMLHttpRequest.prototype.open` override → `rewriteUrl()` | ✅ YES - Must process | Track processed URLs, don't process same URL twice |
| **JavaScript location.href** | Client-side JavaScript code | ❌ NONE - ProxyFix doesn't process JS | `window.location.href` setter → `rewriteUrl()` | ✅ YES - Must process | Track processed URLs, don't process same URL twice |
| **JavaScript setAttribute()** | Client-side JavaScript code | ❌ NONE - ProxyFix doesn't process JS | `Element.prototype.setAttribute` override → `rewriteUrl()` | ✅ YES - Must process | Track processed URLs, don't process same URL twice |
| **Redirect Location header** | Server-side redirect | `redirect(url_for(...))` → ProxyFix adds prefix | `rewrite_url()` in response header processing | ❌ NO - Already processed by ProxyFix | Check if already processed, or don't process redirects |
| **Static file in HTML** | Server-side template | `url_for('static', ...)` → ProxyFix adds prefix | `rewrite_urls_in_content()` (server-side regex) | ❌ NO - Already processed by ProxyFix | Don't process server-side HTML at all |
| **JavaScript in <script> tag** | Server-side template (static JS) | ❌ NONE - ProxyFix doesn't process JS code | Client-side script injection handles at runtime | ✅ YES - Handled by injected script | Script only processes URLs from JS functions, not static code |
| **JavaScript in external .js file** | External JavaScript file | ❌ NONE - ProxyFix doesn't process JS | Client-side script injection handles at runtime | ✅ YES - Handled by injected script | Script only processes URLs from JS functions, not static code |
| **Form action (server-side)** | Server-side template | `url_for()` → ProxyFix adds prefix | `rewrite_urls_in_content()` (server-side regex) | ❌ NO - Already processed by ProxyFix | Don't process server-side HTML at all |
| **AJAX from JavaScript** | Client-side JavaScript code | ❌ NONE - ProxyFix doesn't process JS | `window.fetch` or `XMLHttpRequest` override → `rewriteUrl()` | ✅ YES - Must process | Track processed URLs, don't process same URL twice |

## Key Principles

1. **Server-side URLs (HTML attributes, redirects, static files):**
   - ✅ Processed by ProxyFix via `url_for()` → Already have prefix
   - ❌ AppManager should NOT process these (don't touch server-side content)

2. **Client-side JavaScript URLs (fetch, XHR, location, setAttribute):**
   - ❌ NOT processed by ProxyFix (ProxyFix only affects server-side)
   - ✅ AppManager MUST process these via client-side script
   - ⚠️ Must track which URLs have been processed to prevent double-processing

## Solution: Track Processing, Not Prefix Strings

Instead of checking if a URL string contains a prefix, we should:
1. Mark URLs that have been processed by our `rewriteUrl()` function
2. Never process the same URL twice
3. Use a WeakMap or Set to track processed URLs
