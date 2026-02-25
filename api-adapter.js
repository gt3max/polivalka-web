/**
 * API Adapter - универсальный для Local и Cloud
 * С поддержкой JWT авторизации для Cloud mode
 *
 * Использование:
 * <script src="api-adapter.js"></script>
 * <script>
 *   // Все API вызовы автоматически роутятся
 *   const data = await API.get('/status');
 * </script>
 */

// Определяем режим работы (Local или Cloud)
const urlParams = new URLSearchParams(window.location.search);
const DEVICE_ID = urlParams.get('device');
const IS_CLOUD = window.location.hostname === 'gt3max.github.io' ||
                 window.location.hostname === 'plantapp.pro' ||
                 window.location.hostname === 'www.plantapp.pro' ||
                 window.location.hostname === 'localhost';

// Pages that don't require authentication
const publicPages = ['login.html', 'index.html', 'fleet.html'];
// Pages that require device ID
const deviceRequiredPages = ['home.html', 'sensor.html', 'timer.html', 'settings.html', 'calibration.html', 'update.html', 'trends.html', 'online.html', 'ota.html', 'identify.html'];

const currentPage = window.location.pathname.split('/').pop() || 'index.html';

// ============ Auth Functions ============

const Auth = {
  // Get stored access token
  getToken: function() {
    return localStorage.getItem('access_token');
  },

  // Get refresh token
  getRefreshToken: function() {
    return localStorage.getItem('refresh_token');
  },

  // Check if token is expired (with 5 min buffer)
  isTokenExpired: function() {
    const expires = parseInt(localStorage.getItem('token_expires') || '0');
    return Date.now() > (expires - 300000); // 5 min buffer
  },

  // Check if user is logged in
  isLoggedIn: function() {
    return this.getToken() && !this.isTokenExpired();
  },

  // Get user email
  getUserEmail: function() {
    return localStorage.getItem('user_email');
  },

  // Clear all auth data (logout)
  clear: function() {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('user_email');
    localStorage.removeItem('token_expires');
  },

  // Redirect to login page
  redirectToLogin: function() {
    const returnUrl = window.location.href;
    window.location.href = `login.html?return=${encodeURIComponent(returnUrl)}`;
  },

  // Refresh access token using refresh token
  refresh: async function() {
    const refreshToken = this.getRefreshToken();
    if (!refreshToken) {
      return false;
    }

    try {
      const res = await fetch(`${API.cloudBase}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refreshToken })
      });

      if (!res.ok) {
        this.clear();
        return false;
      }

      const data = await res.json();
      localStorage.setItem('access_token', data.access_token);
      localStorage.setItem('token_expires', Date.now() + (data.expires_in * 1000));
      return true;

    } catch (err) {
      console.error('[Auth] Refresh failed:', err);
      return false;
    }
  },

  // Logout (call API and clear local)
  logout: async function() {
    const token = this.getToken();
    if (token) {
      try {
        await fetch(`${API.cloudBase}/auth/logout`, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${token}` }
        });
      } catch (err) {
        // Ignore logout errors
      }
    }
    this.clear();
    window.location.href = 'login.html';
  }
};

// ============ API Adapter ============

const API = {
  // Cloud API (AWS Lambda) - EU region (Frankfurt)
  cloudBase: 'https://p0833p2v29.execute-api.eu-central-1.amazonaws.com',

  // Local API (ESP32 WebServer)
  localBase: '',

  // Current device ID
  deviceId: DEVICE_ID,

  // Get full endpoint URL
  getEndpoint: function(path) {
    if (IS_CLOUD && DEVICE_ID) {
      return `${this.cloudBase}/device/${DEVICE_ID}${path}`;
    } else if (IS_CLOUD && !DEVICE_ID) {
      return `${this.cloudBase}${path}`;
    } else {
      return `/api${path}`;
    }
  },

  // Get auth headers for Cloud mode
  getAuthHeaders: function() {
    if (!IS_CLOUD) return {};

    const token = Auth.getToken();
    if (token) {
      return { 'Authorization': `Bearer ${token}` };
    }
    return {};
  },

  // Wrapper для fetch с автоматическим роутингом и авторизацией
  fetch: async function(path, options = {}) {
    // In Cloud mode, ensure we're logged in (except for auth endpoints)
    if (IS_CLOUD && !path.startsWith('/auth') && Auth.isTokenExpired()) {
      // Try to refresh token
      const refreshed = await Auth.refresh();
      if (!refreshed) {
        Auth.redirectToLogin();
        throw new Error('Session expired. Please login again.');
      }
    }

    const url = this.getEndpoint(path);
    const headers = {
      ...this.getAuthHeaders(),
      ...(options.headers || {})
    };

    const response = await fetch(url, {
      ...options,
      headers,
      cache: 'no-store'
    });

    // Handle 401 Unauthorized
    if (response.status === 401 && IS_CLOUD) {
      Auth.clear();
      Auth.redirectToLogin();
      throw new Error('Unauthorized. Please login again.');
    }

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.error || `API error: ${response.status}`);
    }

    return response;
  },

  // Fetch global endpoint (no /device/{id} prefix, e.g. /plants/*)
  fetchGlobal: async function(path, options = {}) {
    if (IS_CLOUD && !path.startsWith('/auth') && Auth.isTokenExpired()) {
      const refreshed = await Auth.refresh();
      if (!refreshed) {
        Auth.redirectToLogin();
        throw new Error('Session expired. Please login again.');
      }
    }
    const url = IS_CLOUD ? `${this.cloudBase}${path}` : `/api${path}`;
    const headers = {
      ...this.getAuthHeaders(),
      ...(options.headers || {})
    };
    const response = await fetch(url, { ...options, headers, cache: 'no-store' });
    if (response.status === 401 && IS_CLOUD) {
      Auth.clear();
      Auth.redirectToLogin();
      throw new Error('Unauthorized. Please login again.');
    }
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.error || `API error: ${response.status}`);
    }
    return response;
  },

  // GET request with response normalization
  get: async function(path) {
    const data = await this.fetch(path).then(r => r.json());
    return this.normalize(data, path);
  },

  // Normalize Cloud response to match Local API format for consistency
  normalize: function(data, path) {
    if (!IS_CLOUD || !data) return data;

    // /status endpoint normalization
    if (path === '/status') {
      // Cloud uses 'online', Local uses 'wifi_connected' - provide both
      if (data.online !== undefined && data.wifi_connected === undefined) {
        data.wifi_connected = data.online;
      }
    }

    return data;
  },

  // POST request
  post: async function(path, data) {
    return this.fetch(path, {
      method: 'POST',
      headers: data ? {'Content-Type': 'application/json'} : {},
      body: data ? JSON.stringify(data) : undefined
    }).then(r => r.json());
  }
};

// ============ Initialization ============

// Cloud mode auth check
if (IS_CLOUD && !publicPages.includes(currentPage)) {
  // Check if logged in
  if (!Auth.getToken()) {
    console.warn('[API Adapter] Not logged in, redirecting to login');
    Auth.redirectToLogin();
  } else if (Auth.isTokenExpired()) {
    // Try to refresh token
    Auth.refresh().then(success => {
      if (!success) {
        console.warn('[API Adapter] Token expired and refresh failed');
        Auth.redirectToLogin();
      }
    });
  }
}

// Redirect to home if Cloud mode without device ID (on device pages)
if (IS_CLOUD && !DEVICE_ID && deviceRequiredPages.includes(currentPage)) {
  console.warn('[API Adapter] No device ID in Cloud mode, redirecting to home');
  window.location.href = 'fleet.html';
}

// В Cloud mode: добавить ?device=XX ко всем внутренним ссылкам (кроме fleet, login)
if (IS_CLOUD && DEVICE_ID) {
  document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('a[href]').forEach(link => {
      const href = link.getAttribute('href');
      // Только локальные ссылки на .html страницы (не fleet, login, внешние)
      if (href && href.endsWith('.html') && !href.includes('?') &&
          !href.includes('fleet.html') && !href.includes('login.html') &&
          !href.startsWith('http')) {
        link.setAttribute('href', `${href.split('?')[0]}?device=${DEVICE_ID}`);
      }
      // Ссылки с якорем (calibration.html#pump)
      if (href && href.includes('.html#') && !href.includes('?') && !href.startsWith('http')) {
        const [page, anchor] = href.split('#');
        link.setAttribute('href', `${page}?device=${DEVICE_ID}#${anchor}`);
      }
    });
  });
}

console.log('[API Adapter] Mode:', IS_CLOUD ? 'Cloud' : 'Local',
            '| Device:', DEVICE_ID || 'N/A',
            '| Auth:', IS_CLOUD ? (Auth.isLoggedIn() ? 'OK' : 'Required') : 'N/A');
