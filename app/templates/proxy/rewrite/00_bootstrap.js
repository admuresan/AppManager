{# IMPORTANT: Read `instructions/architecture` before making changes. #}
// CRITICAL: This script must run IMMEDIATELY before any other scripts
// It intercepts navigation + API calls to add the app prefix.
(function () {
  'use strict';

  // Prevent double-injection if script is already loaded
  if (window.__APP_MANAGER_REWRITE_LOADED) {
    return;
  }
  window.__APP_MANAGER_REWRITE_LOADED = true;

  const APP_SLUG = '/{{ app_slug }}';
  const APP_SLUG_NORMALIZED = APP_SLUG.startsWith('/') ? APP_SLUG : '/' + APP_SLUG;
  const APP_SLUG_BARE = APP_SLUG_NORMALIZED.startsWith('/') ? APP_SLUG_NORMALIZED.slice(1) : APP_SLUG_NORMALIZED;
  const APP_SLUG_COOKIE_PREFIX = '{{ app_slug }}_'; // Prefix for cookie names to isolate per app

  // Expose slug so app JS can log expected URLs.
  window.__APP_MANAGER_APP_SLUG = APP_SLUG_NORMALIZED;

  // Trace logging toggle:
  // - enable by adding ?__bg_trace=1 to the URL (recommended)
  // - persists automatically via localStorage + cookie
  // - disable by setting localStorage.__bg_trace = '0'
  const traceParam = new URLSearchParams(window.location.search).get('__bg_trace');
  if (traceParam === '1') {
    try {
      localStorage.setItem('__bg_trace', '1');
    } catch (e) {}
    try {
      document.cookie = '__bg_trace=1; path=/; SameSite=Lax';
    } catch (e) {}
  }
  const cookieHasTrace =
    typeof document !== 'undefined' && typeof document.cookie === 'string'
      ? document.cookie.split(';').some((c) => c.trim() === '__bg_trace=1')
      : false;
  const traceSetting = (() => {
    try {
      return localStorage.getItem('__bg_trace');
    } catch (e) {
      return null;
    }
  })();
  const TRACE = traceSetting === '1' || cookieHasTrace || traceParam === '1';

  // Always emit one line so we can confirm injection happened.
  try {
    console.log('[BG TRACE] injected', { trace: TRACE, appSlug: APP_SLUG_NORMALIZED, href: window.location.href });
  } catch (e) {}

  function _traceLog(level, payload) {
    if (!TRACE) return;
    const fn = console && console[level] ? console[level] : console.log;
    try {
      fn.call(console, '[BG TRACE]', payload);
    } catch (e) {
      // ignore logging failures
    }
  }

  // Configuration: Marker to identify URLs that have been processed by our rewrite function
  // This marker is added to processed URLs and stripped by the proxy when forwarding to localhost
  const PROCESSED_MARKER = '__bg_rw=1'; // BlackGrid Rewrite marker

