/**
 * Common Utilities for PlantApp Web Interface
 * Shared across all pages to avoid code duplication
 *
 * Usage: <script src="common.js"></script> (after api-adapter.js)
 */

// ============ Admin ============
const ADMIN_EMAILS = ['mrmaximshurigin@gmail.com', 'admin@plantapp.pro'];

function isAdmin() {
  const email = localStorage.getItem('user_email') || '';
  return ADMIN_EMAILS.includes(email.toLowerCase());
}

function showAdminNavLink() {
  if (isAdmin()) {
    const adminLink = document.getElementById('admin-nav-link');
    if (adminLink) adminLink.style.display = '';
  }
}

// ============ Universal Clock ============
/**
 * Start a universal clock that updates header-time element every second.
 * Shows current browser time, NOT device telemetry timestamp.
 * Call this from any page that has <div id="header-time">
 */
function startHeaderClock() {
  const timeEl = document.getElementById('header-time');
  if (!timeEl) return;

  function updateClock() {
    const now = new Date();
    const timeStr = now.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      hour12: false
    });
    timeEl.textContent = timeStr;
    timeEl.className = 'mono';
  }

  updateClock(); // Initial update
  setInterval(updateClock, 1000); // Update every second
}

// Auto-start clock when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', startHeaderClock);
} else {
  startHeaderClock();
}

// ============ State Display ============
/**
 * Map internal controller states to user-friendly display
 * Internal: DISABLED, LAUNCH, ACTIVE, STANDBY, PULSE, SETTLE, CHECK, WATERING, COOLDOWN, EMERGENCY
 * User-friendly: Standby 💤, Watering 💧, Emergency ⚠️
 */
function mapStateToDisplay(state, pumpRunning = false) {
  if (pumpRunning) {
    return { text: 'Watering', emoji: '💧', color: '#1976d2', bg: '#e3f2fd' };
  }

  const s = (state || '').toUpperCase();

  if (s === 'EMERGENCY' || s.includes('ERROR')) {
    return { text: 'Emergency', emoji: '⚠️', color: '#c62828', bg: '#ffebee' };
  }

  if (['WATERING', 'PULSE', 'SETTLE', 'CHECK'].includes(s)) {
    return { text: 'Watering', emoji: '💧', color: '#1976d2', bg: '#e3f2fd' };
  }

  return { text: 'Standby', emoji: '💤', color: '#666', bg: '#f5f5f5' };
}

// ============ Time Formatting ============
/**
 * Format timestamp to relative time (e.g., "5m ago", "2h ago")
 * @param {number} timestamp - Unix timestamp (seconds or milliseconds)
 */
function timeAgo(timestamp) {
  if (!timestamp) return 'never';

  // Convert seconds to milliseconds if needed
  const ms = timestamp < 10000000000 ? timestamp * 1000 : timestamp;
  const seconds = Math.floor((Date.now() - ms) / 1000);

  if (seconds < 0) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;

  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;

  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

/**
 * Format time as HH:MM from Date or timestamp
 */
function formatTime(dateOrTimestamp) {
  const date = typeof dateOrTimestamp === 'number'
    ? new Date(dateOrTimestamp < 10000000000 ? dateOrTimestamp * 1000 : dateOrTimestamp)
    : dateOrTimestamp;
  return date.toTimeString().substring(0, 5);
}

// ============ Battery Display ============
/**
 * Format battery status for display
 * 3 states: 🔋 XX%, 🔋 XX% ⚡, ⚡ AC
 */
function formatBattery(percent, charging) {
  if (percent === null || percent === undefined) {
    return '⚡ AC';
  }
  const pct = Math.round(percent);
  const icon = charging ? ' ⚡' : '';
  return `🔋 ${pct}%${icon}`;
}

// ============ Toast Notifications ============
/**
 * Show toast notification
 * @param {string} message - Message to display
 * @param {string} type - 'success', 'error', 'info', 'warning'
 */
function showToast(message, type = 'info') {
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;

  const colors = {
    success: '#28a745',
    error: '#dc3545',
    warning: '#ffc107',
    info: '#17a2b8'
  };

  Object.assign(toast.style, {
    position: 'fixed',
    top: '20px',
    right: '20px',
    padding: '12px 20px',
    borderRadius: '8px',
    backgroundColor: colors[type] || colors.info,
    color: type === 'warning' ? '#000' : '#fff',
    fontSize: '14px',
    fontWeight: '500',
    boxShadow: '0 4px 12px rgba(0,0,0,0.3)',
    zIndex: '10000',
    opacity: '0',
    transition: 'opacity 0.3s ease',
    maxWidth: '400px'
  });

  document.body.appendChild(toast);

  // Fade in
  setTimeout(() => toast.style.opacity = '1', 10);

  // Remove after 4 seconds
  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// ============ Utilities ============
/**
 * Promise-based sleep
 */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Navigate to page preserving device_id in Cloud mode
 */
function navigateTo(page) {
  if (typeof IS_CLOUD !== 'undefined' && IS_CLOUD && typeof DEVICE_ID !== 'undefined' && DEVICE_ID) {
    if (page.includes('#')) {
      const [path, anchor] = page.split('#');
      location.href = path + '?device=' + DEVICE_ID + '#' + anchor;
    } else {
      location.href = page + '?device=' + DEVICE_ID;
    }
  } else {
    location.href = page;
  }
}

/**
 * Get RSSI display info
 */
function getRssiDisplay(rssi) {
  if (!rssi || rssi === 0) return { icon: '', color: '#999', text: '' };
  if (rssi >= -50) return { icon: '📶', color: '#0a0', text: rssi + ' dBm' };
  if (rssi >= -60) return { icon: '📶', color: '#2e7d32', text: rssi + ' dBm' };
  if (rssi >= -70) return { icon: '📶', color: '#f57c00', text: rssi + ' dBm' };
  return { icon: '📶', color: '#c62828', text: rssi + ' dBm' };
}

// ============ Header Updates ============
/**
 * Update common header elements (time, battery, state, mode, connection)
 * Call this from page-specific updateStatus() functions
 */
function updateHeaderFromStatus(status) {
  // Time
  const timeEl = document.getElementById('header-time');
  if (timeEl && status.timestamp) {
    timeEl.textContent = formatTime(status.timestamp);
    timeEl.className = 'mono';
  }

  // Battery
  const batteryEl = document.getElementById('battery-status');
  if (batteryEl) {
    if (status.battery) {
      batteryEl.textContent = formatBattery(status.battery.percent, status.battery.charging);
    } else {
      batteryEl.textContent = '⚡ AC';
    }
  }

  // State
  const headerStateEl = document.getElementById('header-state');
  if (headerStateEl) {
    const rawState = status.system_state?.state || 'OFF';
    const displayState = mapStateToDisplay(rawState, status.pump_running);
    headerStateEl.textContent = `${displayState.emoji} ${displayState.text}`;
  }

  // Mode
  const modeBadge = document.getElementById('mode-badge');
  if (modeBadge && status.system_state?.mode) {
    const mode = status.system_state.mode;
    modeBadge.textContent = mode.charAt(0).toUpperCase() + mode.slice(1);
    modeBadge.className = 'status-badge status-' + mode;
  }

  // Connection
  const connText = document.getElementById('conn-text');
  if (connText) {
    if (status.wifi_connected) {
      connText.textContent = 'Online';
      connText.style.color = '#fff';
    } else {
      connText.textContent = 'Offline';
      connText.style.color = '#999';
    }
  }

  // Location/Room/CustomName
  if (status.system_state?.location) {
    const el = document.getElementById('location-text');
    if (el) el.textContent = status.system_state.location;
  }
  if (status.system_state?.room) {
    const el = document.getElementById('room-text');
    if (el) el.textContent = status.system_state.room;
  }
  const customNameEl = document.getElementById('custom-name-suffix');
  if (customNameEl) {
    let customName = status.system_state?.device_name || 'Plant';
    // Replace default names with "Plant"
    if (customName === 'Polivalka' || customName.toLowerCase().startsWith('polivalka-')) {
      customName = 'Plant';
    }
    customNameEl.textContent = ' / ' + customName;
  }
}

// ============ WiFi Mode Monitor ============
let _lastWiFiMode = null;
let _lastStaIp = null;

/**
 * Monitor WiFi mode changes and redirect accordingly
 * Only used in local (AP) mode, not Cloud mode
 */
async function monitorWiFiMode() {
  // Skip in Cloud mode
  if (typeof IS_CLOUD !== 'undefined' && IS_CLOUD) return;

  try {
    const response = await fetch('/api/wifi/status', {
      method: 'POST',
      cache: 'no-store'
    });
    const result = await response.json();
    const currentMode = result.mode;
    const currentStaIp = result.sta_ip || null;

    // Initialize
    if (_lastWiFiMode === null) {
      _lastWiFiMode = currentMode;
      _lastStaIp = currentStaIp;
      return;
    }

    // New STA connection - redirect
    if (!_lastStaIp && currentStaIp) {
      console.log('Connected to router, redirecting to ' + currentStaIp);
      window.location.href = 'http://' + currentStaIp + window.location.pathname;
      return;
    }

    // Transition to AP mode - redirect
    if ((_lastWiFiMode === 'sta' || _lastWiFiMode === 'apsta') && currentMode === 'ap') {
      console.log('WiFi disconnected, redirecting to AP mode...');
      window.location.href = 'http://192.168.4.1' + window.location.pathname;
      return;
    }

    _lastWiFiMode = currentMode;
    _lastStaIp = currentStaIp;
  } catch(e) {
    // Try AP fallback
    try {
      await fetch('http://192.168.4.1/api/wifi/status', { method: 'POST', cache: 'no-store' });
      window.location.href = 'http://192.168.4.1' + window.location.pathname;
    } catch(e2) {
      // Will retry on next poll
    }
  }
}

// ============ Device ID Persistence ============
/**
 * Save device_id to localStorage (with user email for security)
 * and update navigation links IMMEDIATELY (not deferred)
 *
 * Security: Device ID stored per-user to prevent cross-user access
 * Performance: Links updated synchronously to prevent race condition
 */
function initDevicePersistence() {
  const params = new URLSearchParams(window.location.search);
  const deviceFromUrl = params.get('device');
  const userEmail = localStorage.getItem('user_email') || 'anonymous';

  // Security: Store device ID per user (prevents BUG #10 - device collision)
  const storageKey = `selected_device_${userEmail}`;

  // Save to localStorage if present in URL
  if (deviceFromUrl) {
    localStorage.setItem(storageKey, deviceFromUrl);
    // Also keep legacy key for backwards compatibility
    localStorage.setItem('selected_device_id', deviceFromUrl);
    console.log('[Common] Saved device to localStorage:', deviceFromUrl, 'for user:', userEmail);
  }

  // Get current device - URL takes priority, then user-specific, then legacy
  const currentDevice = deviceFromUrl ||
                        localStorage.getItem(storageKey) ||
                        localStorage.getItem('selected_device_id');

  // Update navigation links to include device parameter
  if (currentDevice) {
    updateNavLinksWithDevice(currentDevice);
  }
}

/**
 * Update all navigation links with device parameter
 * Called immediately AND on DOMContentLoaded (for dynamic content)
 */
function updateNavLinksWithDevice(deviceId) {
  if (!deviceId) return;

  document.querySelectorAll('.nav a, a[href*=".html"]').forEach(link => {
    const href = link.getAttribute('href');
    if (href && href.endsWith('.html') && !href.includes('fleet.html') && href !== '/') {
      // Don't add device to fleet.html or root (Fleet page shows all devices)
      try {
        const url = new URL(href, window.location.origin);
        url.searchParams.set('device', deviceId);  // Always set (not just if missing)
        link.setAttribute('href', url.pathname + url.search);
      } catch (e) {
        // Invalid URL, skip
      }
    }
  });
  console.log('[Common] Updated nav links with device:', deviceId);
}

// ============ Init ============
// CRITICAL: Initialize device persistence IMMEDIATELY (not deferred!)
// This prevents BUG #1 where user clicks nav before DOMContentLoaded
(function() {
  try {
    initDevicePersistence();
  } catch (e) {
    console.error('[Common] initDevicePersistence failed:', e);
  }
})();

// Also run on DOMContentLoaded for dynamically added links
document.addEventListener('DOMContentLoaded', function() {
  showAdminNavLink();
  initDevicePersistence();  // Re-run for any dynamic content
});

// Set device ID in header for Cloud mode
if (typeof IS_CLOUD !== 'undefined' && IS_CLOUD && typeof DEVICE_ID !== 'undefined' && DEVICE_ID) {
  document.addEventListener('DOMContentLoaded', function() {
    const deviceHeader = document.getElementById('device-id-header');
    if (deviceHeader) {
      deviceHeader.textContent = '🌱 ' + DEVICE_ID;
    }
  });
}

console.log('[Common] Utilities loaded');
