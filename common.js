/**
 * Common Utilities for PlantApp Web Interface
 * Shared across all pages to avoid code duplication
 *
 * Usage: <script src="common.js"></script> (after api-adapter.js)
 */

// ============ Clean URLs ============
// Remove .html from browser address bar (keep file loading via GitHub Pages)
if (window.location.pathname.endsWith('.html') && window.location.pathname !== '/index.html') {
  const clean = window.location.pathname.replace('.html', '') + window.location.search + window.location.hash;
  history.replaceState(null, '', clean);
}

// ============ Admin ============
const ADMIN_EMAILS = ['mrmaximshurigin@gmail.com', 'mahin84@gmail.com'];

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
 * РАЗДЕЛ 3 — ЕДИНОЕ правило отображения заряда (единственное место на этот репо).
 * Заряд показываем в ПРОЦЕНТАХ; порог AC — по SOC%.
 *   percent==null   → onPower ? "⚡ AC" : "🔋 —"
 *   !onPower        → "🔋 XX%"          (на батарее: всегда %)
 *   onPower & <85%  → "🔋 XX% ⚡"        (на питании, ещё заряжается → число + молния)
 *   onPower & ≥85%  → "⚡ AC"           (на питании, заряжен)
 * Порог 85% по SOC, а НЕ по напряжению: под зарядкой напряжение упирается в плато
 * ~4.18В уже к ~78% (логи EBB339), поэтому воль-порог не даёт AC при высоком заряде.
 * 85% выбран по 6-мес логам: "полный на питании" проседает до 88.5% (BC67E9) —
 * 85% даёт запас 3.5%, чтобы полный аккум всегда был AC, без мигания. Унифицирует
 * платы с аккумулятором (≥85%→AC) и без (фантом ~99%→AC).
 * @param {number|null} percent  SOC %
 * @param {number|null} voltage  battery voltage (V) — больше не в решении, оставлен для совместимости
 * @param {boolean} onPower      on external power (N_PG/IO12)
 */
function formatBattery(percent, voltage, onPower) {
  if (percent === null || percent === undefined || percent < 0) {
    return onPower ? '⚡ AC' : '🔋 —';
  }
  const pct = Math.round(percent);
  if (!onPower) return `🔋 ${pct}%`;       // на батарее: всегда %
  if (pct < 85) return `🔋 ${pct}% ⚡`;     // на питании, ещё не заряжен → % + молния
  return '⚡ AC';                           // на питании, заряжен (≥85%) → AC
}
// Helper: extract on_power from a battery object (fallback to charging for old fw).
function batteryOnPower(b) {
  if (!b) return false;
  return (b.on_power !== undefined && b.on_power !== null) ? b.on_power : !!b.charging;
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
 * ===== Timezone helpers (correct per-device local time) =====
 * The device runs on POSIX TZ strings; the browser reports IANA. This maps the
 * browser's IANA zone to the POSIX strings used by the settings.html dropdown, so we
 * can auto-set a device's timezone at claim and prompt the user when it's unset.
 * Without this, every device stays on the firmware default CET/CEST regardless of
 * where it physically is (Timer fires at the wrong hour, pump can run at night).
 */
const IANA_TO_POSIX = {
  'Europe/London':'GMT0BST,M3.5.0,M10.5.0','Europe/Dublin':'GMT0BST,M3.5.0,M10.5.0',
  'Europe/Lisbon':'WET0WEST,M3.5.0,M10.5.0',
  'Europe/Berlin':'CET-1CEST,M3.5.0,M10.5.0/3','Europe/Paris':'CET-1CEST,M3.5.0,M10.5.0/3',
  'Europe/Madrid':'CET-1CEST,M3.5.0,M10.5.0/3','Europe/Rome':'CET-1CEST,M3.5.0,M10.5.0/3',
  'Europe/Amsterdam':'CET-1CEST,M3.5.0,M10.5.0/3','Europe/Brussels':'CET-1CEST,M3.5.0,M10.5.0/3',
  'Europe/Vienna':'CET-1CEST,M3.5.0,M10.5.0/3','Europe/Prague':'CET-1CEST,M3.5.0,M10.5.0/3',
  'Europe/Warsaw':'CET-1CEST,M3.5.0,M10.5.0/3','Europe/Zurich':'CET-1CEST,M3.5.0,M10.5.0/3',
  'Europe/Stockholm':'CET-1CEST,M3.5.0,M10.5.0/3','Europe/Oslo':'CET-1CEST,M3.5.0,M10.5.0/3',
  'Europe/Copenhagen':'CET-1CEST,M3.5.0,M10.5.0/3','Europe/Budapest':'CET-1CEST,M3.5.0,M10.5.0/3',
  'Europe/Kiev':'EET-2EEST,M3.5.0,M10.5.0/3','Europe/Kyiv':'EET-2EEST,M3.5.0,M10.5.0/3',
  'Europe/Athens':'EET-2EEST,M3.5.0,M10.5.0/3','Europe/Bucharest':'EET-2EEST,M3.5.0,M10.5.0/3',
  'Europe/Helsinki':'EET-2EEST,M3.5.0,M10.5.0/3','Europe/Riga':'EET-2EEST,M3.5.0,M10.5.0/3',
  'Europe/Moscow':'MSK-3','Europe/Istanbul':'<TRT>-3',
  'America/Anchorage':'AKST9AKDT,M3.2.0,M11.1.0',
  'America/Los_Angeles':'PST8PDT,M3.2.0,M11.1.0','America/Vancouver':'PST8PDT,M3.2.0,M11.1.0',
  'America/Tijuana':'PST8PDT,M3.2.0,M11.1.0',
  'America/Denver':'MST7MDT,M3.2.0,M11.1.0','America/Edmonton':'MST7MDT,M3.2.0,M11.1.0',
  'America/Phoenix':'MST7',
  'America/Chicago':'CST6CDT,M3.2.0,M11.1.0','America/Mexico_City':'CST6CDT,M3.2.0,M11.1.0',
  'America/Winnipeg':'CST6CDT,M3.2.0,M11.1.0',
  'America/New_York':'EST5EDT,M3.2.0,M11.1.0','America/Toronto':'EST5EDT,M3.2.0,M11.1.0',
  'America/Puerto_Rico':'AST4','America/St_Johns':'NST3:30NDT,M3.2.0,M11.1.0',
  'Pacific/Honolulu':'HST10',
  'America/Sao_Paulo':'<-03>3','America/Argentina/Buenos_Aires':'<-03>3','America/Montevideo':'<-03>3',
  'America/Caracas':'<-04>4','America/Lima':'<-05>5','America/Bogota':'<-05>5',
  'America/Santiago':'<CLT>4<CLST>,M9.1.6/24,M4.1.6/24',
  'Asia/Tokyo':'JST-9','Asia/Seoul':'KST-9',
  'Asia/Shanghai':'CST-8','Asia/Hong_Kong':'CST-8','Asia/Taipei':'CST-8',
  'Asia/Bangkok':'<+07>-7','Asia/Jakarta':'<+07>-7','Asia/Ho_Chi_Minh':'<+07>-7',
  'Asia/Kathmandu':'<+0545>-5:45',
  'Asia/Kolkata':'IST-5:30','Asia/Colombo':'IST-5:30',
  'Asia/Dubai':'<+04>-4','Asia/Riyadh':'<+03>-3','Asia/Kuwait':'<+03>-3','Asia/Qatar':'<+03>-3',
  'Asia/Jerusalem':'IST-2IDT,M3.4.4/26,M10.5.0',
  'Asia/Almaty':'<+06>-6','Asia/Karachi':'<+05>-5','Asia/Kabul':'<+045>-4:30',
  'Africa/Cairo':'EET-2','Africa/Johannesburg':'CAT-2','Africa/Nairobi':'EAT-3','Africa/Lagos':'WAT-1',
  'Australia/Sydney':'AEST-10AEDT,M10.1.0,M4.1.0','Australia/Melbourne':'AEST-10AEDT,M10.1.0,M4.1.0',
  'Australia/Adelaide':'ACST-9:30ACDT,M10.1.0,M4.1.0','Australia/Perth':'AWST-8',
  'Pacific/Auckland':'NZST-12NZDT,M9.5.0,M4.1.0','Pacific/Fiji':'<+11>-11',
  'Pacific/Port_Moresby':'<+10>-10','Pacific/Pago_Pago':'<-11>11'
};

function browserIanaTimezone() {
  try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (e) { return ''; }
}

// Browser's zone as a POSIX TZ string the device understands, or null if the zone
// isn't in our curated map (we intentionally do NOT guess a malformed POSIX string;
// the Settings prompt lets the user pick manually instead).
function browserPosixTimezone() {
  return IANA_TO_POSIX[browserIanaTimezone()] || null;
}

// The cloud returns the IANA default 'Europe/Warsaw' when no timezone was ever stored.
// A real selection is always a POSIX string from the dropdown, never this value — so
// this reliably means "timezone never set on this device".
function isTimezoneUnset(tz) {
  return !tz || tz === 'Europe/Warsaw';
}

// Push the browser's timezone to a specific device. Reuses the existing, tested
// POST /device/{id}/time/timezone (saves to DynamoDB + sends set_timezone MQTT).
// Non-fatal: the claim/whatever succeeds regardless.
async function setDeviceTimezoneFromBrowser(deviceId) {
  const posix = browserPosixTimezone();
  if (!posix || !deviceId) return false;
  try {
    await API.fetchGlobal('/device/' + deviceId + '/time/timezone', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ timezone: posix })
    });
    return true;
  } catch (e) {
    console.warn('[TZ] auto-set failed for', deviceId, e);
    return false;
  }
}

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
      batteryEl.textContent = formatBattery(status.battery.percent, status.battery.voltage, batteryOnPower(status.battery));
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

  document.querySelectorAll('.nav a, a[href]').forEach(link => {
    const href = link.getAttribute('href');
    if (href && !href.startsWith('http') && !href.includes('fleet') && !href.includes('login') && href !== '/') {
      // Don't add device to fleet or root (Fleet page shows all devices)
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

/* ui_guard — one click = one command; messages hide by themselves (item 4, 02.11.2026).
 * Same logic on the board pages (appended to every page by send_html_with_init) and on the
 * site (polivalka-web/common.js). Fable review: documentation/Fable/2026-11-02_item4_double_press_review.md
 * - A clicked button stays busy until 700 ms pass with none of the requests it started in flight
 *   (covers GET -> POST and the cloud's 500 ms device polls). Fuse 20 s. `disabled` is never touched.
 * - Stop controls are never blocked: explicit handler list, not the substring "stop"
 *   (onclick="event.stopPropagation();..." must stay guarded).
 * - alert() becomes a toast that hides by itself and survives a page reload for its time.
 *   confirm() and prompt() are untouched. */
(function () {
  if (window.__uiGuard) return;
  window.__uiGuard = 1;
  var QUIET = 700, FUSE = 20000, KEY = 'uiToast';
  var busy = [];

  function isStop(el) {
    if (el.hasAttribute('data-nobusy')) return true;
    if (/(^|-)stop(-|$)/i.test(el.id || '')) return true;
    return /\b(stopPump|pump2Stop|stopDevice|stopAllDevices)\s*\(/.test(el.getAttribute('onclick') || '');
  }
  function find(el) {
    for (var i = 0; i < busy.length; i++) if (busy[i].el === el) return busy[i];
    return null;
  }
  function release(b) {
    var i = busy.indexOf(b);
    if (i >= 0) busy.splice(i, 1);
    b.el.classList.remove('ui-busy');
    b.el.removeAttribute('aria-busy');
  }
  function check(b) {
    if (busy.indexOf(b) < 0) return;
    var now = Date.now();
    if (now - b.start > FUSE || (b.n <= 0 && now - b.last >= QUIET)) { release(b); return; }
    setTimeout(function () { check(b); }, b.n > 0 ? 200 : Math.max(50, QUIET - (now - b.last)));
  }

  document.addEventListener('click', function (e) {
    var t = e.target;
    if (!t || !t.closest || t.closest('input,select,textarea,label')) return;
    var el = t.closest('button,[onclick]');
    if (!el || el.disabled || isStop(el)) return;
    if (find(el)) { e.preventDefault(); e.stopImmediatePropagation(); return; }
    var now = Date.now();
    var b = { el: el, n: 0, last: now, start: now };
    busy.push(b);
    el.classList.add('ui-busy');
    el.setAttribute('aria-busy', 'true');
    setTimeout(function () { check(b); }, QUIET);
  }, true);

  // Requests started while an element is busy belong to it.
  function own() {
    var owners = busy.slice(), now = Date.now();
    for (var i = 0; i < owners.length; i++) { owners[i].n++; owners[i].last = now; }
    var done = false;
    return function () {
      if (done) return;
      done = true;
      var t = Date.now();
      for (var j = 0; j < owners.length; j++) { owners[j].n--; owners[j].last = t; }
    };
  }
  var origFetch = window.fetch;
  if (origFetch) {
    window.fetch = function () {
      var end = own(), p;
      try { p = origFetch.apply(window, arguments); } catch (x) { end(); throw x; }
      p.then(end, end);
      return p;
    };
  }
  if (window.XMLHttpRequest) {
    var origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function () {
      var end = own();
      this.addEventListener('loadend', end);
      try { return origSend.apply(this, arguments); } catch (x) { end(); throw x; }
    };
  }

  // Toast instead of alert()
  var box = null, timer = null;
  function show(msg, err, ms) {
    if (!document.body) {
      document.addEventListener('DOMContentLoaded', function () { show(msg, err, ms); });
      return;
    }
    if (!box) {
      box = document.createElement('div');
      box.id = 'ui-toast';
      box.setAttribute('role', 'status');
      box.style.cssText = 'position:fixed;top:12px;left:50%;transform:translateX(-50%);max-width:92vw;' +
        'z-index:100000;padding:10px 16px;border-radius:8px;color:#fff;font:14px system-ui,Arial;' +
        'white-space:pre-line;box-shadow:0 4px 12px rgba(0,0,0,.3);cursor:pointer;transition:opacity .3s';
      box.onclick = function () { hide(); };
      document.body.appendChild(box);
    }
    box.textContent = msg;
    box.style.background = err ? '#c62828' : '#2e7d32';
    box.style.opacity = '1';
    box.style.display = 'block';
    clearTimeout(timer);
    timer = setTimeout(hide, ms);
  }
  function hide() {
    clearTimeout(timer);
    try { sessionStorage.removeItem(KEY); } catch (x) {}
    if (!box) return;
    box.style.opacity = '0';
    setTimeout(function () { if (box.style.opacity === '0') box.style.display = 'none'; }, 300);
  }
  window.alert = function (m) {
    var msg = String(m == null ? '' : m);
    var err = /error|fail|invalid|maximum|please|cannot|can't|denied|refused|wrong|❌|⚠/i.test(msg);
    var ms = Math.min(8000, Math.max(3000, msg.length * 60)) + (err ? 2000 : 0);
    try { sessionStorage.setItem(KEY, JSON.stringify({ m: msg, e: err, t: Date.now() + ms })); } catch (x) {}
    show(msg, err, ms);
  };
  try {
    var s = JSON.parse(sessionStorage.getItem(KEY) || 'null');
    if (s && s.t > Date.now()) show(s.m, s.e, Math.max(1500, s.t - Date.now()));
    else sessionStorage.removeItem(KEY);
  } catch (x) {}

  var st = document.createElement('style');
  st.textContent = '.ui-busy{opacity:.6;cursor:progress!important}';
  (document.head || document.documentElement).appendChild(st);
})();
