/**
 * API Adapter - универсальный для Local и Cloud
 *
 * Использование:
 * <script src="api-adapter.js"></script>
 * <script>
 *   // Все API вызовы автоматически роутятся
 *   const data = await fetch(API.getEndpoint('/status')).then(r => r.json());
 * </script>
 */

// Определяем режим работы (Local или Cloud)
// Cloud: GitHub Pages (gt3max.github.io) или localhost (dev)
// Local: 192.168.x.x, polivalka-XX.local, 192.168.4.1
const urlParams = new URLSearchParams(window.location.search);
const DEVICE_ID = urlParams.get('device');
const IS_CLOUD = window.location.hostname === 'gt3max.github.io' ||
                 window.location.hostname === 'localhost';

// Redirect to fleet.html if Cloud mode without device ID (except for fleet.html itself)
const currentPage = window.location.pathname.split('/').pop() || 'index.html';
const deviceRequiredPages = ['home.html', 'sensor.html', 'timer.html', 'settings.html', 'calibration.html', 'update.html', 'trends.html', 'online.html'];
if (IS_CLOUD && !DEVICE_ID && deviceRequiredPages.includes(currentPage)) {
  console.warn('[API Adapter] No device ID in Cloud mode, redirecting to fleet.html');
  window.location.href = 'fleet.html';
}

// API configuration
const API = {
  // Cloud API (AWS Lambda) - EU region (Frankfurt) - HTTP API v2 ($default stage, no /prod)
  cloudBase: 'https://p0833p2v29.execute-api.eu-central-1.amazonaws.com',

  // Local API (ESP32 WebServer)
  localBase: '',

  // Current device ID (для cloud режима)
  deviceId: DEVICE_ID,

  // Get full endpoint URL
  getEndpoint: function(path) {
    if (IS_CLOUD && DEVICE_ID) {
      // Cloud mode: /status → https://api.polivalka.app/device/BB00C1/status
      return `${this.cloudBase}/device/${DEVICE_ID}${path}`;
    } else if (IS_CLOUD && !DEVICE_ID) {
      // Cloud Fleet mode: /devices → https://api.polivalka.app/devices
      return `${this.cloudBase}${path}`;
    } else {
      // Local mode: /status → /api/status
      return `/api${path}`;
    }
  },

  // Wrapper для fetch с автоматическим роутингом
  fetch: async function(path, options = {}) {
    const url = this.getEndpoint(path);
    const response = await fetch(url, {
      ...options,
      cache: 'no-store'
    });

    if (!response.ok) {
      throw new Error(`API error: ${response.status} ${response.statusText}`);
    }

    return response;
  },

  // Convenience methods
  get: async function(path) {
    return this.fetch(path).then(r => r.json());
  },

  post: async function(path, data) {
    return this.fetch(path, {
      method: 'POST',
      headers: data ? {'Content-Type': 'application/json'} : {},
      body: data ? JSON.stringify(data) : undefined
    }).then(r => r.json());
  }
};

// Добавить кнопку "Back to Fleet" если в cloud mode
if (IS_CLOUD && DEVICE_ID) {
  document.addEventListener('DOMContentLoaded', function() {
    // Найти header
    const header = document.querySelector('.header');
    if (header) {
      // Добавить кнопку "Back to Fleet" в начало
      const backButton = document.createElement('div');
      backButton.innerHTML = '<a href="fleet.html" style="color:#fff;text-decoration:none;font-size:14px">← Fleet</a>';
      backButton.style.marginRight = '12px';
      header.insertBefore(backButton, header.firstChild);
    }

    // Обновить navigation links (добавить ?device=XX)
    document.querySelectorAll('.nav a').forEach(link => {
      const href = link.getAttribute('href');
      if (href && !href.includes('?') && !href.includes('fleet.html')) {
        link.setAttribute('href', `${href.split('?')[0]}?device=${DEVICE_ID}`);
      }
    });
  });
}

console.log('[API Adapter] Mode:', IS_CLOUD ? 'Cloud' : 'Local', '| Device ID:', DEVICE_ID || 'N/A');
