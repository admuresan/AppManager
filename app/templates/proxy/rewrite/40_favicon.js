{# IMPORTANT: Read `instructions/architecture` before making changes. #}
// ------------------------------------------------------------------------
// FAVICON NORMALIZATION (use AppManager-configured per-app logo)
// ------------------------------------------------------------------------
(function ensurePerAppFavicon() {
  try {
    // Use per-app logo from AppManager config (NOT hardcoded).
    // This avoids relying on Referer-based /favicon.ico and prevents cross-app caching.
    const desired = `/blackgrid/app-icon/${encodeURIComponent(APP_SLUG_BARE)}`;
    const head = document.head || document.getElementsByTagName('head')[0];
    if (!head) return;

    let link = head.querySelector('link[rel="icon"], link[rel="shortcut icon"], link[rel="apple-touch-icon"]');
    const prev = link ? link.getAttribute('href') || '' : '';

    if (!link) {
      link = document.createElement('link');
      link.setAttribute('rel', 'icon');
      head.appendChild(link);
    }
    link.setAttribute('href', desired);

    _traceLog('log', { step: 'favicon.set', input: prev, expected: desired, actual: desired, ok: true });
  } catch (e) {
    _traceLog('warn', { step: 'favicon.set', error: String(e) });
  }
})();

