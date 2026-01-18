/**
 * Device Controller - защитный слой между UI и API
 * Централизованное управление состоянием устройств
 * Защита от race conditions, null values, повторных вызовов
 */

class DeviceController {
  constructor() {
    this.devices = new Map();
    this.pendingRequests = new Map();
    this.callbacks = new Map();
    this.errorLog = [];
  }

  /**
   * Безопасное получение устройства
   */
  getDevice(deviceId) {
    if (!deviceId || typeof deviceId !== 'string') {
      console.error('Invalid deviceId:', deviceId);
      return null;
    }
    return this.devices.get(deviceId) || null;
  }

  /**
   * Обновление данных устройства (с проверками)
   */
  updateDevice(deviceId, data) {
    if (!deviceId || !data) return false;

    const device = this.devices.get(deviceId) || {};

    // Безопасное слияние данных
    const updated = {
      ...device,
      ...data,
      // Защита критичных полей
      device_id: deviceId,
      battery_pct: data.battery_pct !== undefined ? data.battery_pct : device.battery_pct,
      moisture_pct: data.moisture_pct ?? device.moisture_pct ?? 0,
      last_update: Date.now()
    };

    this.devices.set(deviceId, updated);
    this.notifyListeners(deviceId, 'update', updated);
    return true;
  }

  /**
   * Защищённый API вызов (предотвращает дубли)
   */
  async safeApiCall(key, apiFunction, options = {}) {
    // Проверка на повторный вызов
    if (this.pendingRequests.has(key)) {
      return this.pendingRequests.get(key);
    }

    const {
      timeout = 10000,
      retries = 1,
      onError = null
    } = options;

    // Создаём промис с таймаутом
    const timeoutPromise = new Promise((_, reject) =>
      setTimeout(() => reject(new Error('Request timeout')), timeout)
    );

    const apiPromise = apiFunction()
      .catch(async (error) => {
        // Retry логика
        if (retries > 0) {
          await new Promise(r => setTimeout(r, 1000));
          return this.safeApiCall(key + '_retry', apiFunction, { ...options, retries: retries - 1 });
        }
        throw error;
      })
      .finally(() => {
        this.pendingRequests.delete(key);
      });

    // Сохраняем промис чтобы предотвратить дубли
    const racePromise = Promise.race([apiPromise, timeoutPromise]);
    this.pendingRequests.set(key, racePromise);

    try {
      const result = await racePromise;
      return result;
    } catch (error) {
      this.logError(key, error);
      if (onError) onError(error);
      throw error;
    }
  }

  /**
   * Запуск насоса с полной защитой
   */
  async startPump(deviceId, duration = 60) {
    if (!deviceId) throw new Error('Device ID required');

    const device = this.getDevice(deviceId);

    // Проверка состояния
    if (device?.pump_running) {
      return { status: 'already_running' };
    }

    // Обновляем UI оптимистично
    this.updateDevice(deviceId, {
      pump_running: true,
      pump_start_time: Date.now()
    });

    try {
      // Защищённый вызов API
      const result = await this.safeApiCall(
        `pump_start_${deviceId}`,
        () => API.post(`/device/${deviceId}/pump?sec=${duration}`),
        {
          timeout: 5000,
          retries: 1,
          onError: () => {
            // Откат UI при ошибке
            this.updateDevice(deviceId, {
              pump_running: false,
              pump_start_time: null
            });
          }
        }
      );

      return result;
    } catch (error) {
      // UI уже откачен в onError
      throw error;
    }
  }

  /**
   * Остановка насоса
   */
  async stopPump(deviceId) {
    if (!deviceId) throw new Error('Device ID required');

    const device = this.getDevice(deviceId);

    if (!device?.pump_running) {
      return { status: 'not_running' };
    }

    // Оптимистичное обновление
    this.updateDevice(deviceId, {
      pump_running: false,
      pump_start_time: null
    });

    try {
      const result = await this.safeApiCall(
        `pump_stop_${deviceId}`,
        () => API.post(`/device/${deviceId}/pump/stop`),
        {
          timeout: 5000,
          onError: () => {
            // Откат при ошибке
            this.updateDevice(deviceId, {
              pump_running: true
            });
          }
        }
      );

      return result;
    } catch (error) {
      throw error;
    }
  }

  /**
   * Обновление сенсора
   */
  async refreshSensor(deviceId) {
    if (!deviceId) throw new Error('Device ID required');

    try {
      const result = await this.safeApiCall(
        `sensor_${deviceId}`,
        () => API.get(`/device/${deviceId}/sensor`),
        {
          timeout: 8000,
          retries: 2
        }
      );

      // Обновляем данные
      this.updateDevice(deviceId, {
        moisture_pct: result.moisture_pct,
        adc_raw: result.adc_raw,
        last_sensor_update: result.timestamp
      });

      return result;
    } catch (error) {
      // Не обновляем данные при ошибке
      throw error;
    }
  }

  /**
   * Загрузка всех устройств
   */
  async loadDevices() {
    try {
      const devices = await this.safeApiCall(
        'load_devices',
        () => API.get('/devices'),
        {
          timeout: 10000,
          retries: 2
        }
      );

      // Сохраняем в Map
      devices.forEach(device => {
        this.updateDevice(device.device_id, device);
      });

      return Array.from(this.devices.values());
    } catch (error) {
      // Возвращаем кешированные данные при ошибке
      console.error('Failed to load devices, using cache');
      return Array.from(this.devices.values());
    }
  }

  /**
   * Подписка на изменения
   */
  subscribe(deviceId, callback) {
    if (!this.callbacks.has(deviceId)) {
      this.callbacks.set(deviceId, new Set());
    }
    this.callbacks.get(deviceId).add(callback);

    // Возврат функции отписки
    return () => {
      const callbacks = this.callbacks.get(deviceId);
      if (callbacks) {
        callbacks.delete(callback);
      }
    };
  }

  /**
   * Уведомление слушателей
   */
  notifyListeners(deviceId, event, data) {
    const callbacks = this.callbacks.get(deviceId);
    if (callbacks) {
      callbacks.forEach(cb => {
        try {
          cb(event, data);
        } catch (error) {
          console.error('Callback error:', error);
        }
      });
    }
  }

  /**
   * Логирование ошибок
   */
  logError(context, error) {
    const errorEntry = {
      timestamp: Date.now(),
      context,
      message: error.message,
      stack: error.stack
    };

    this.errorLog.push(errorEntry);

    // Ограничиваем размер лога
    if (this.errorLog.length > 100) {
      this.errorLog.shift();
    }

    console.error(`[${context}]`, error);
  }

  /**
   * Получение статистики
   */
  getStats() {
    const devices = Array.from(this.devices.values());
    return {
      total: devices.length,
      online: devices.filter(d => Date.now() - d.last_update < 7200000).length,
      warnings: devices.filter(d =>
        (d.battery_pct !== null && d.battery_pct < 10) ||
        d.moisture_pct < 15
      ).length,
      watering: devices.filter(d => d.pump_running).length,
      errors: this.errorLog.length
    };
  }
}

// Глобальный экземпляр
window.deviceController = new DeviceController();