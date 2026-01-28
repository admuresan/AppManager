{# IMPORTANT: Read `instructions/architecture` before making changes. #}
// Override XMLHttpRequest for dynamic API calls
// Only override XHR.open ONCE, and always use the TRUE native XHR.open
if (!window.__APP_MANAGER_ORIGINAL_XHR_OPEN) {
  window.__APP_MANAGER_ORIGINAL_XHR_OPEN = XMLHttpRequest.prototype.open;
}
if (!window.__APP_MANAGER_REWRITE_XHR_OPEN) {
  window.__APP_MANAGER_REWRITE_XHR_OPEN = function (method, url, ...rest) {
    if (typeof url === 'string') {
      const originalUrl = url;
      const expected = expectedRewrite(originalUrl);
      const actual = rewriteUrl(originalUrl);
      _traceLog('log', {
        step: 'XMLHttpRequest.open',
        input: originalUrl,
        expected,
        actual,
        ok: expected === actual,
        httpMethod: method,
      });
      url = actual;
    }
    return window.__APP_MANAGER_ORIGINAL_XHR_OPEN.call(this, method, url, ...rest);
  };
}
if (XMLHttpRequest.prototype.open !== window.__APP_MANAGER_REWRITE_XHR_OPEN) {
  XMLHttpRequest.prototype.open = window.__APP_MANAGER_REWRITE_XHR_OPEN;
}

// Override fetch() for dynamic API calls (Quizia login uses fetch('/api/auth/login', ...))
try {
  if (typeof window.fetch === 'function' && !window.__APP_MANAGER_ORIGINAL_FETCH) {
    window.__APP_MANAGER_ORIGINAL_FETCH = window.fetch.bind(window);
  }
  if (!window.__APP_MANAGER_REWRITE_FETCH && window.__APP_MANAGER_ORIGINAL_FETCH) {
    window.__APP_MANAGER_REWRITE_FETCH = function (input, init) {
      try {
        let inputUrl = null;
        if (typeof input === 'string') {
          inputUrl = input;
        } else if (input && typeof input.url === 'string') {
          inputUrl = input.url;
        } else {
          inputUrl = String(input);
        }

        const expected = expectedRewrite(inputUrl);
        const actual = rewriteUrl(inputUrl);
        _traceLog('log', { step: 'fetch', input: inputUrl, expected, actual, ok: expected === actual });

        // If a Request was provided, try to preserve it
        if (input && typeof input === 'object' && typeof input.url === 'string') {
          try {
            const rewrittenRequest = new Request(actual, input);
            return window.__APP_MANAGER_ORIGINAL_FETCH(rewrittenRequest, init);
          } catch (eReq) {
            return window.__APP_MANAGER_ORIGINAL_FETCH(actual, init);
          }
        }
        return window.__APP_MANAGER_ORIGINAL_FETCH(actual, init);
      } catch (e) {
        _traceLog('warn', { step: 'fetch', error: String(e) });
        return window.__APP_MANAGER_ORIGINAL_FETCH(input, init);
      }
    };
  }
  if (window.__APP_MANAGER_REWRITE_FETCH && window.fetch !== window.__APP_MANAGER_REWRITE_FETCH) {
    try {
      window.fetch = window.__APP_MANAGER_REWRITE_FETCH;
    } catch (eSet) {
      _traceLog('warn', { step: 'fetch.override_failed', error: String(eSet) });
    }
  }
} catch (eFetch) {
  _traceLog('warn', { step: 'fetch.setup_failed', error: String(eFetch) });
}

