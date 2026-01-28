{# IMPORTANT: Read `instructions/architecture` before making changes. #}
// Override setAttribute for dynamically created elements
// Only override setAttribute ONCE, and always use the TRUE native setAttribute
if (!window.__APP_MANAGER_ORIGINAL_SET_ATTRIBUTE) {
  window.__APP_MANAGER_ORIGINAL_SET_ATTRIBUTE = Element.prototype.setAttribute;
}
if (!window.__APP_MANAGER_REWRITE_SET_ATTRIBUTE) {
  window.__APP_MANAGER_REWRITE_SET_ATTRIBUTE = function (name, value) {
    if ((name === 'src' || name === 'href' || name === 'action') && typeof value === 'string') {
      value = rewriteUrl(value);
      // Keep marker - it will be stripped by proxy when forwarding to localhost
    }
    return window.__APP_MANAGER_ORIGINAL_SET_ATTRIBUTE.call(this, name, value);
  };
}
if (Element.prototype.setAttribute !== window.__APP_MANAGER_REWRITE_SET_ATTRIBUTE) {
  Element.prototype.setAttribute = window.__APP_MANAGER_REWRITE_SET_ATTRIBUTE;
}

