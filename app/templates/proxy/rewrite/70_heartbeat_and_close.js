{# IMPORTANT: Read `instructions/architecture` before making changes. #}
// ============================================================================
// HEARTBEAT: Keep app alive when browser tab is open
// ============================================================================

// Send heartbeat every 30 seconds to keep app alive
let heartbeatInterval = null;

function sendHeartbeat() {
  try {
    fetch(`${APP_SLUG_NORMALIZED}/__heartbeat__`, {
      method: 'GET',
      credentials: 'include',
      cache: 'no-cache',
    }).catch((err) => {
      // Silently fail - heartbeat is best effort
      try {
        console.debug('Heartbeat failed:', err);
      } catch (e) {}
    });
  } catch (e) {
    try {
      console.debug('Heartbeat error:', e);
    } catch (e2) {}
  }
}

// Start heartbeat when page loads
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', function () {
    sendHeartbeat();
    heartbeatInterval = setInterval(sendHeartbeat, 30000);
  });
} else {
  sendHeartbeat();
  heartbeatInterval = setInterval(sendHeartbeat, 30000);
}

// Slow down heartbeat when hidden
document.addEventListener('visibilitychange', function () {
  if (document.hidden) {
    if (heartbeatInterval) {
      clearInterval(heartbeatInterval);
    }
    heartbeatInterval = setInterval(sendHeartbeat, 120000); // 2 minutes
  } else {
    if (heartbeatInterval) {
      clearInterval(heartbeatInterval);
    }
    sendHeartbeat();
    heartbeatInterval = setInterval(sendHeartbeat, 30000);
  }
});

// Clean up on page unload
window.addEventListener('beforeunload', function () {
  if (heartbeatInterval) {
    clearInterval(heartbeatInterval);
  }
});

})(); // end IIFE

