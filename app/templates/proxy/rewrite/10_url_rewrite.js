{# IMPORTANT: Read `instructions/architecture` before making changes. #}
/**
 * Check if a URL contains the processed marker
 * @param {string} url - URL to check
 * @returns {boolean} - True if URL has been processed
 */
function hasProcessedMarker(url) {
  if (!url || typeof url !== 'string') return false;
  return url.includes(PROCESSED_MARKER);
}

/**
 * Add the processed marker to a URL
 * @param {string} url - URL to mark
 * @returns {string} - URL with marker added
 */
function addProcessedMarker(url) {
  if (!url || typeof url !== 'string') return url;
  if (hasProcessedMarker(url)) return url; // Already marked

  const separator = url.includes('?') ? '&' : '?';
  return url + separator + PROCESSED_MARKER;
}

// Compute "expected" rewrite output (per QUIZIA_LOGIN_FLOW_ANALYSIS.md) without mutating state.
function expectedRewrite(url) {
  if (!url || typeof url !== 'string') return url;
  if (hasProcessedMarker(url)) return url; // already processed => expected unchanged

  // Skip special URLs that should never be rewritten
  if (
    url.startsWith('data:') ||
    url.startsWith('javascript:') ||
    url.startsWith('mailto:') ||
    url.startsWith('tel:') ||
    url.startsWith('#')
  ) {
    return url;
  }

  // protocol-relative
  if (url.startsWith('//')) return url;

  // absolute URLs: rewrite only if same host and missing prefix; never rewrite external domains
  if (url.match(/^https?:\/\/[^\/]+/)) {
    try {
      const u = new URL(url);
      if (u.hostname !== window.location.hostname) return url;
      const p = u.pathname || '/';
      if (p === APP_SLUG_NORMALIZED || p.startsWith(APP_SLUG_NORMALIZED + '/')) return url;
      u.pathname = APP_SLUG_NORMALIZED + (p.startsWith('/') ? p : '/' + p);
      return addProcessedMarker(u.toString());
    } catch (e) {
      return url;
    }
  }

  // root-relative
  if (url.startsWith('/')) {
    if (url === APP_SLUG_NORMALIZED || url.startsWith(APP_SLUG_NORMALIZED + '/')) {
      return addProcessedMarker(url);
    }
    return addProcessedMarker(APP_SLUG_NORMALIZED + url);
  }

  // relative without leading slash
  // If already starts with app slug (without leading slash), just normalize to "/<slug>/..."
  if (url === APP_SLUG_BARE || url.startsWith(APP_SLUG_BARE + '/')) {
    return addProcessedMarker('/' + url);
  }
  return addProcessedMarker(APP_SLUG_NORMALIZED + '/' + url);
}

function rewriteUrl(url) {
  if (!url || typeof url !== 'string') return url;

  // If URL has our processed marker, it's already been processed - return as-is (keep marker)
  // The marker will be stripped by the proxy when forwarding to localhost
  if (hasProcessedMarker(url)) {
    return url; // Return with marker still attached to prevent re-processing
  }

  // Skip special URLs that should never be rewritten
  if (
    url.startsWith('data:') ||
    url.startsWith('javascript:') ||
    url.startsWith('mailto:') ||
    url.startsWith('tel:') ||
    url.startsWith('#')
  ) {
    return url;
  }

  // Skip protocol-relative URLs (external CDNs)
  if (url.startsWith('//')) return url;

  // Skip absolute URLs to external domains
  if (url.match(/^https?:\/\/[^\/]+/) && !url.includes('localhost')) {
    return url;
  }

  // If URL is already absolute with our domain, check if it already has the app prefix
  if (url.match(/^https?:\/\/[^\/]+/)) {
    if (url.includes(window.location.hostname)) {
      try {
        const urlObj = new URL(url);
        const path = urlObj.pathname;
        // If path already starts with the app slug, don't rewrite
        if (path.startsWith(APP_SLUG_NORMALIZED + '/') || path === APP_SLUG_NORMALIZED) {
          return url;
        }
      } catch (e) {
        // URL parsing failed, continue with rewrite logic
      }
    } else {
      // External domain, don't rewrite
      return url;
    }
  }

  let rewritten;

  // Handle relative URLs (starting with /)
  if (url.startsWith('/')) {
    // Check if URL already starts with the app slug prefix
    if (url.startsWith(APP_SLUG_NORMALIZED + '/') || url === APP_SLUG_NORMALIZED) {
      rewritten = url;
    } else {
      rewritten = APP_SLUG_NORMALIZED + url;
    }
  } else {
    // Handle relative URLs without leading slash (e.g., "api/calculate")
    // If url already begins with the app slug (e.g. "quizia/quizmaster/login"), don't double-prefix.
    if (url === APP_SLUG_BARE || url.startsWith(APP_SLUG_BARE + '/')) {
      rewritten = '/' + url;
    } else {
      rewritten = APP_SLUG_NORMALIZED + '/' + url;
    }
  }

  const expected = expectedRewrite(url);
  const actual = addProcessedMarker(rewritten);
  _traceLog('log', {
    step: 'rewriteUrl()',
    input: url,
    expected,
    actual,
    ok: expected === actual,
    appSlug: APP_SLUG_NORMALIZED,
  });
  return actual;
}

