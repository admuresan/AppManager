{# IMPORTANT: Read `instructions/architecture` before making changes. #}
// ------------------------------------------------------------------------
// NAVIGATION INTERCEPTS
// ------------------------------------------------------------------------
// Override location assignments for dynamic navigation
if (!window.__APP_MANAGER_LOCATION_HREF_OVERRIDDEN) {
  if (!window.__APP_MANAGER_ORIGINAL_LOCATION_ASSIGN) {
    window.__APP_MANAGER_ORIGINAL_LOCATION_ASSIGN = window.location.assign.bind(window.location);
  }
  if (!window.__APP_MANAGER_ORIGINAL_LOCATION_REPLACE) {
    window.__APP_MANAGER_ORIGINAL_LOCATION_REPLACE = window.location.replace.bind(window.location);
  }

  // Try to override location.href using property descriptor
  const locationProto = Object.getPrototypeOf(window.location);
  const locationHrefDesc =
    Object.getOwnPropertyDescriptor(locationProto, 'href') || Object.getOwnPropertyDescriptor(Location.prototype, 'href');

  if (locationHrefDesc && locationHrefDesc.set) {
    window.__APP_MANAGER_ORIGINAL_LOCATION_HREF_SET = locationHrefDesc.set;
    try {
      Object.defineProperty(window.location, 'href', {
        set: function (value) {
          const originalUrl = value;
          const expected = expectedRewrite(originalUrl);
          const actual = rewriteUrl(originalUrl);
          _traceLog('log', {
            step: 'location.href',
            input: originalUrl,
            expected,
            actual,
            ok: expected === actual,
          });
          window.__APP_MANAGER_ORIGINAL_LOCATION_HREF_SET.call(window.location, actual);
        },
        get: locationHrefDesc.get,
        configurable: true,
        enumerable: true,
      });
      window.__APP_MANAGER_LOCATION_HREF_OVERRIDDEN = true;
    } catch (e) {
      // Some browsers disallow overriding location.href.
      _traceLog('warn', { step: 'location.href.override_failed', error: String(e) });
    }
  }

  // Always TRY to override location.assign and location.replace as fallbacks.
  function _tryOverrideLocationMethod(methodName, fn) {
    try {
      const loc = window.location;
      // 1) direct assignment
      try {
        loc[methodName] = fn;
        return true;
      } catch (e1) {}
      // 2) defineProperty on instance
      try {
        Object.defineProperty(loc, methodName, {
          value: fn,
          configurable: true,
        });
        return true;
      } catch (e2) {}
      // 3) defineProperty on prototype
      try {
        const proto = Object.getPrototypeOf(loc) || Location.prototype;
        Object.defineProperty(proto, methodName, {
          value: fn,
          configurable: true,
        });
        return true;
      } catch (e3) {}
    } catch (e0) {}
    return false;
  }

  const _assignWrapper = function (url) {
    const expected = expectedRewrite(url);
    const actual = rewriteUrl(url);
    _traceLog('log', { step: 'location.assign', input: url, expected, actual, ok: expected === actual });
    return window.__APP_MANAGER_ORIGINAL_LOCATION_ASSIGN(actual);
  };

  const _replaceWrapper = function (url) {
    const expected = expectedRewrite(url);
    const actual = rewriteUrl(url);
    _traceLog('log', { step: 'location.replace', input: url, expected, actual, ok: expected === actual });
    return window.__APP_MANAGER_ORIGINAL_LOCATION_REPLACE(actual);
  };

  if (!_tryOverrideLocationMethod('assign', _assignWrapper)) {
    _traceLog('warn', { step: 'location.assign.override_failed', input: 'assign', actual: 'read-only' });
  }
  if (!_tryOverrideLocationMethod('replace', _replaceWrapper)) {
    _traceLog('warn', { step: 'location.replace.override_failed', input: 'replace', actual: 'read-only' });
  }

  window.__APP_MANAGER_LOCATION_HREF_OVERRIDDEN = true;
}

// ------------------------------------------------------------------------
// LINK + FORM INTERCEPTS
// ------------------------------------------------------------------------
document.addEventListener(
  'click',
  function (e) {
    try {
      const a = e.target && e.target.closest ? e.target.closest('a') : null;
      if (!a) return;
      const hrefAttr = a.getAttribute('href');
      if (!hrefAttr || typeof hrefAttr !== 'string') return;
      // ignore modifier clicks / new tab behavior
      if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
      // ignore downloads / external targets
      if (a.hasAttribute('download')) return;
      const target = (a.getAttribute('target') || '').toLowerCase();
      if (target && target !== '_self') return;

      const expected = expectedRewrite(hrefAttr);
      const actual = rewriteUrl(hrefAttr);
      _traceLog('log', { step: 'anchor.click', input: hrefAttr, expected, actual, ok: expected === actual });

      if (actual !== hrefAttr) {
        e.preventDefault();
        window.location.href = actual;
      }
    } catch (err) {
      _traceLog('warn', { step: 'anchor.click', error: String(err) });
    }
  },
  true
);

document.addEventListener(
  'submit',
  function (e) {
    try {
      const form = e.target;
      if (!form || !form.getAttribute) return;
      const actionAttr = form.getAttribute('action') || '';
      if (!actionAttr) return;
      const expected = expectedRewrite(actionAttr);
      const actual = rewriteUrl(actionAttr);
      _traceLog('log', { step: 'form.submit', input: actionAttr, expected, actual, ok: expected === actual });
      if (actual !== actionAttr) {
        form.setAttribute('action', actual);
      }
    } catch (err) {
      _traceLog('warn', { step: 'form.submit', error: String(err) });
    }
  },
  true
);

_traceLog('log', {
  step: 'script.loaded',
  appSlug: APP_SLUG_NORMALIZED,
  href: window.location.href,
});

