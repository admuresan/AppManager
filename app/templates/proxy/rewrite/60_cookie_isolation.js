{# IMPORTANT: Read `instructions/architecture` before making changes. #}
// ============================================================================
// COOKIE ISOLATION: Each app should have its own isolated cookies
// ============================================================================

/**
 * Parse a cookie string into an object
 * @param {string} cookieString - Cookie string (e.g., "name=value; name2=value2")
 * @returns {Object} - Object with cookie names as keys
 */
function parseCookies(cookieString) {
  const cookies = {};
  if (!cookieString) return cookies;

  cookieString.split(';').forEach((cookie) => {
    const parts = cookie.trim().split('=');
    if (parts.length >= 2) {
      const name = parts[0].trim();
      const value = parts.slice(1).join('='); // Handle values with = in them
      cookies[name] = value;
    }
  });
  return cookies;
}

/**
 * Serialize cookies object to cookie string
 * @param {Object} cookies - Object with cookie names as keys
 * @returns {string} - Cookie string
 */
function serializeCookies(cookies) {
  return Object.entries(cookies)
    .map(([name, value]) => `${name}=${value}`)
    .join('; ');
}

/**
 * Check if a cookie name belongs to this app
 * @param {string} cookieName - Cookie name to check
 * @returns {boolean} - True if cookie belongs to this app
 */
function isAppCookie(cookieName) {
  return cookieName.startsWith(APP_SLUG_COOKIE_PREFIX);
}

/**
 * Add app prefix to cookie name
 * @param {string} cookieName - Original cookie name
 * @returns {string} - Prefixed cookie name
 */
function prefixCookieName(cookieName) {
  if (isAppCookie(cookieName)) {
    return cookieName;
  }
  return APP_SLUG_COOKIE_PREFIX + cookieName;
}

/**
 * Remove app prefix from cookie name
 * @param {string} cookieName - Prefixed cookie name
 * @returns {string} - Original cookie name (without prefix)
 */
function unprefixCookieName(cookieName) {
  if (cookieName.startsWith(APP_SLUG_COOKIE_PREFIX)) {
    return cookieName.substring(APP_SLUG_COOKIE_PREFIX.length);
  }
  return cookieName;
}

/**
 * Parse a cookie assignment string (e.g., "name=value; path=/; domain=example.com")
 * @param {string} cookieString - Cookie assignment string
 * @returns {Object} - Parsed cookie with name, value, and attributes
 */
function parseCookieAssignment(cookieString) {
  const parts = cookieString.split(';').map((p) => p.trim());
  const nameValue = parts[0].split('=');
  const name = nameValue[0].trim();
  const value = nameValue.slice(1).join('='); // Handle values with = in them

  const cookie = { name, value };

  // Parse attributes (path, domain, expires, max-age, secure, httponly, samesite)
  for (let i = 1; i < parts.length; i++) {
    const part = parts[i].toLowerCase();
    if (part.startsWith('path=')) {
      cookie.path = part.substring(5);
    } else if (part.startsWith('domain=')) {
      cookie.domain = part.substring(7);
    } else if (part.startsWith('expires=')) {
      cookie.expires = part.substring(8);
    } else if (part.startsWith('max-age=')) {
      cookie.maxAge = part.substring(8);
    } else if (part === 'secure') {
      cookie.secure = true;
    } else if (part === 'httponly') {
      cookie.httpOnly = true;
    } else if (part.startsWith('samesite=')) {
      cookie.sameSite = part.substring(9);
    }
  }

  return cookie;
}

/**
 * Serialize cookie object to cookie assignment string
 * @param {Object} cookie - Cookie object with name, value, and attributes
 * @returns {string} - Cookie assignment string
 */
function serializeCookieAssignment(cookie) {
  let result = `${cookie.name}=${cookie.value}`;
  if (cookie.path) result += `; path=${cookie.path}`;
  if (cookie.domain) result += `; domain=${cookie.domain}`;
  if (cookie.expires) result += `; expires=${cookie.expires}`;
  if (cookie.maxAge) result += `; max-age=${cookie.maxAge}`;
  if (cookie.secure) result += '; secure';
  if (cookie.httpOnly) result += '; httponly';
  if (cookie.sameSite) result += `; samesite=${cookie.sameSite}`;
  return result;
}

// Override document.cookie getter and setter
// Only override once per app
if (!window.__APP_MANAGER_COOKIE_OVERRIDDEN) {
  const cookieDescriptor =
    Object.getOwnPropertyDescriptor(Document.prototype, 'cookie') ||
    Object.getOwnPropertyDescriptor(HTMLDocument.prototype, 'cookie');

  if (cookieDescriptor) {
    const originalCookieGetter = cookieDescriptor.get;
    const originalCookieSetter = cookieDescriptor.set;

    Object.defineProperty(document, 'cookie', {
      get: function () {
        const allCookies = originalCookieGetter.call(document);
        const cookies = parseCookies(allCookies);

        // Filter to only this app's cookies and remove prefix
        const appCookies = {};
        for (const [name, value] of Object.entries(cookies)) {
          if (isAppCookie(name)) {
            const unprefixedName = unprefixCookieName(name);
            appCookies[unprefixedName] = value;
          }
        }

        return serializeCookies(appCookies);
      },
      set: function (cookieString) {
        const cookie = parseCookieAssignment(cookieString);
        cookie.name = prefixCookieName(cookie.name);
        const prefixedCookieString = serializeCookieAssignment(cookie);
        originalCookieSetter.call(document, prefixedCookieString);
        return true;
      },
      configurable: true,
      enumerable: true,
    });

    window.__APP_MANAGER_COOKIE_OVERRIDDEN = true;
  }
}

