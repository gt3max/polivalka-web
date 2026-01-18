# Sensor Mode - Full System Audit

**Date:** 2026-01-18
**Auditor:** Claude Opus 4.5
**Status:** VERIFIED - All connections traced

---

## 1. HARDWARE LAYER

### 1.1 Sensors

| Sensor | GPIO | ADC Channel | Type | Detection Thresholds |
|--------|------|-------------|------|---------------------|
| J5/J6 (Capacitive) | 35 | ADC1_CH7 | Capacitive | ADC < 100 OR > 4000 = DISCONNECTED |
| J7 (Resistive) | 34 | ADC1_CH6 | Resistive (DFRobot SEN0114) | ADC > 3900 = SHORTED (no low detect) |
| Power | 5 | GPIO | Common power for both | On during reads only |

### 1.2 Calibration Values

**Capacitive (J5/J6):** 3-point calibration
- `adc_air` (reference) - Default: 2800
- `adc_water` (100%) - Default: 1200
- `adc_dry_soil` (0%) - Default: 2400

**Resistive (J7):** 2-point calibration
- `adc2_dry` (0%) - Default: 100
- `adc2_wet` (100%) - Default: 3000

### 1.3 Files
- `sensor.c:40-82` - GPIO, ADC, thresholds
- `sensor.h` - Public API (212 lines)

---

## 2. CONNECTION DETECTION & BLOCKING

### 2.1 Detection Logic

**Capacitive (J5/J6):**
```c
// sensor.c:464-488
bool connected = (adc_reading >= 100 && adc_reading <= 4000);
```

**Resistive (J7):**
```c
// sensor.c:836-862
// NOTE: ADC=0 is VALID for dry resistive sensor!
bool connected = (adc_reading <= 3900);
```

### 2.2 Preflight Check (LAUNCH state)

**File:** `sensor_controller.c:770-892`

| Check | Threshold | Action |
|-------|-----------|--------|
| Readings collected | 30 minimum | Continue/Fail |
| Mean ADC | 500-3500 | Warning if out of range |
| Span | >= 50 | Warning if too low (dead sensor) |
| StdDev | < 50% of span | Warning if noisy |
| **J6 DISCONNECT** | mean < 100 AND span < 30 | **BLOCK - Return to DISABLED** |

### 2.3 Runtime Detection (STANDBY/CHECK)

```c
// sensor_controller.c:1037-1043 (STANDBY)
if (!sensor_is_connected()) {
    warning_active = true;
    snprintf(warning_message, "Sensor disconnected! Check J6 connector.");
    return;  // Skip this check, retry next interval
}

// sensor_controller.c:1335-1344 (CHECK)
if (!sensor_is_connected()) {
    warning_message = "Sensor disconnected during watering!";
    state_transition(SENSOR_STATE_COOLDOWN);  // Safety stop
    return;
}
```

### 2.4 Cloud Notification on Block

```c
// sensor_controller.c:870-878
if (sensor_disconnected) {
    save_enabled_state(false);  // Don't restore on reboot
    if (aws_iot_is_connected()) {
        aws_iot_publish_system(mode_str, "DISABLED", ...);
    }
}
```

---

## 3. STATE MACHINE

### 3.1 States

| State | Duration | Purpose | File Location |
|-------|----------|---------|---------------|
| DISABLED | - | Controller off | `sensor_controller.c:96` |
| LAUNCH | 60s | Preflight checks, arm | `sensor_controller.c:740-912` |
| STANDBY | Variable (adaptive) | Monitor moisture | `sensor_controller.c:937-1180` |
| PULSE | pulse_sec | Deliver water | `sensor_controller.c:1186-1240` |
| SETTLE | wait_sec | Let water absorb | `sensor_controller.c:1245-1314` |
| CHECK | Instant | Measure moisture | `sensor_controller.c:1320-1498` |
| COOLDOWN | cooldown_min | Rest period | `sensor_controller.c:1505-1550` |

### 3.2 State Flow

```
User Enable → LAUNCH (60s countdown + preflight)
                ↓
        [Sensor OK?] → No → DISABLED (blocked)
                ↓ Yes
            STANDBY (check moisture every adaptive_interval)
                ↓
        [moisture < start_pct?] → No → continue STANDBY
                ↓ Yes
              PULSE (pump runs pulse_sec)
                ↓
             SETTLE (wait wait_sec for absorption)
                ↓
              CHECK (measure moisture)
                ↓
        [moisture >= stop_pct?] → No → back to PULSE
                ↓ Yes
            COOLDOWN (rest cooldown_min)
                ↓
            STANDBY (repeat cycle)
```

### 3.3 NVS Persistence

| Key | Purpose | File |
|-----|---------|------|
| `enabled` | Restore after reboot | `sensor_controller.c:108-148` |
| `last_mp_ts` | Microprime timestamp | `sensor_controller.c:153-196` |
| `deep_cycles` | Cycles since deep watering | `sensor_controller.c:201-255` |
| `last_deep_ts` | Last deep watering time | `sensor_controller.c:201-255` |

---

## 4. PRESETS SYSTEM

### 4.1 Available Presets

| ID | Name | start% | stop% | pulse_sec | cooldown_min |
|----|------|--------|-------|-----------|--------------|
| 0 | Succulents/Cacti | 15 | 35 | 3 | 1440 (24h) |
| 1 | Standard | 35 | 55 | 5 | 120 (2h) |
| 2 | Tropical | 45 | 70 | 8 | 60 (1h) |
| 3 | Herbs/Seedlings | 30 | 50 | 4 | 90 (1.5h) |
| 4 | Custom | User-defined | - | - | - |

### 4.2 Safety Limits

| Limit | Value | Purpose |
|-------|-------|---------|
| Soft limit | max_water_day_ml | Warning, continues |
| Hard limit | soft × multiplier | Blocks watering |
| Global cap | 2000 ml/day | Flood protection |

### 4.3 Files
- `sensor_presets.h:17-70` - Definitions
- `sensor_presets.c` - Implementation

---

## 5. PUMP INTEGRATION

### 5.1 Pump Control

```c
// sensor_controller.c:1196 (PULSE start)
pump_start(duration_ms);

// sensor_controller.c:1219 (PULSE end)
pump_stop();

// sensor_controller.c:489 (disable)
pump_stop();  // Safety stop on disable
```

### 5.2 Volume Tracking

```c
// sensor_controller.c:1222-1226 (PULSE end)
uint32_t water_ml = pump_get_last_volume_ml();
water_ml_in_cycle += water_ml;
no_rise_water_delivered += water_ml;
daily_water_ml += water_ml;
```

---

## 6. ESP32 WEB API (AP Mode)

### 6.1 Sensor Endpoints

| Endpoint | Method | Purpose | File |
|----------|--------|---------|------|
| `/api/moisture` | GET | Read ADC + percent | `web_server.c:1364-1397` |
| `/api/calibrate?type=X` | GET | Calibrate (air/water/dry_soil) | `web_server.c:1761-1826` |
| `/api/reset` | GET | Reset calibration | `web_server.c:1830-1847` |
| `/api/sensor/set_adc` | GET | Admin preset | `web_server.c:1849-1902` |
| `/api/sensor/settings` | GET | Get/Set config | `web_server.c:2198-2327` |
| `/api/sensor2/status` | GET | J7 ADC + percent | `web_server.c:1904-1930` |
| `/api/sensor2/calibrate` | GET | J7 calibrate | `web_server.c:1932-1982` |
| `/api/sensor2/settings` | GET | J7 calibration values | `web_server.c:2056-2087` |

### 6.2 Controller Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/sensor/controller/enable` | POST | Start LAUNCH |
| `/api/sensor/controller/disable` | POST | Stop controller |
| `/api/sensor/controller/status` | GET | Get state + warning |

---

## 7. AWS IoT TELEMETRY

### 7.1 Sensor Topic

**Topic:** `Polivalka/{device_id}/sensor`

**Payload:**
```json
{
  "device_id": "Polivalka-BB00C1",
  "timestamp": 1737226800,
  "sensor": {
    "moisture_percent": 45.5,
    "adc_raw": 2340,
    "sensor2_adc": 1500,
    "sensor2_percent": 55.0
  }
}
```

**File:** `aws_iot.c:1699-1760`

### 7.2 System Topic (includes warning)

**Topic:** `Polivalka/{device_id}/system`

**Includes:**
```json
{
  "system": {
    "mode": "sensor",
    "state": "STANDBY",
    "warning_active": true,
    "warning_msg": "Sensor disconnected!",
    ...
  }
}
```

**File:** `aws_iot.c:1966-2044`

---

## 8. LAMBDA PROCESSING

### 8.1 iot_rule_telemetry.py

**Sensor handling:**
```python
# Line 80-82
if 'sensor' in event:
    data_type = 'sensor'
    data = event['sensor']
```

**Saves to:**
- Time-series record (real timestamp)
- Latest record (timestamp=0) - **NOW INCLUDES sensor, battery, system**

### 8.2 Files
- `iot_rule_telemetry.py:80-135`

---

## 9. CLOUD API (api_handler.py)

### 9.1 Sensor Controller Endpoints

| Endpoint | Handler | Purpose |
|----------|---------|---------|
| `POST /device/{id}/sensor/controller/enable` | `send_controller_command()` | Enable sensor mode |
| `POST /device/{id}/sensor/controller/disable` | `send_controller_command()` | Disable sensor mode |
| `POST /device/{id}/sensor/controller/cancel` | `send_controller_command()` | Cancel LAUNCH |
| `GET /device/{id}/sensor/controller/status` | Direct from telemetry | Get state + warning |

### 9.2 Status Endpoint Response

```python
# api_handler.py:1381-1422
return {
    'state': state,
    'arming_countdown': 60 if state == 'LAUNCH' else 0,
    'moisture_pct': moisture_pct,
    'warning_active': warning_active,
    'warning_msg': warning_msg,
    'watering': state in ['PULSE', 'SETTLE', 'CHECK'],
    ...
}
```

---

## 10. CLOUD UI

### 10.1 home.html Sensor Display

```javascript
// Line 230-237 - J5/J6 display
sensor1Disconnected = (s.adc !== null && s.adc < 100);
document.getElementById('sensor1-vals').innerHTML =
    `ADC: ${s.adc}<br>Moisture: ${moisturePct} %${sensor1Warning}`;

// Line 245-253 - J7 display
sensor2Disconnected = (s.sensor2_adc > 3900);
document.getElementById('sensor2-vals').innerHTML =
    `ADC: ${s.sensor2_adc}<br>Moisture: ${pct2} %${sensor2Warning}`;
```

### 10.2 sensor.html Controller UI

- State display (DISABLED/LAUNCH/STANDBY/etc)
- Warning message display
- Enable/Disable/Cancel buttons
- Preset selector
- Parameter configuration

---

## 11. IDENTIFIED ISSUES

### 11.1 FIXED in this session

| Issue | Fix | File |
|-------|-----|------|
| J7 detection showing "disconnected" at ADC=0 | Changed threshold logic | `sensor.c:80-81` |
| Cloud J7 detection hardcoded wrong | Fixed JavaScript | `home.html:251` |
| System telemetry not in latest record | Added 'system' to Lambda | `iot_rule_telemetry.py:122` |
| API not reading system from latest | Added loop for all types | `api_handler.py:2717-2719` |

### 11.2 Potential Issues Found

| Issue | Location | Severity | Notes |
|-------|----------|----------|-------|
| Cloud status shows hardcoded values | `api_handler.py:1414-1417` | LOW | start/stop thresholds, pulse duration are hardcoded |
| Arming countdown local only | `api_handler.py:1397` | LOW | Frontend counts down locally, not synced |

### 11.3 Verified Working

- Preflight blocking when J6 disconnected
- Runtime warning when sensor disconnects during STANDBY
- Safety stop when sensor disconnects during CHECK
- NVS persistence of enabled state
- Warning publishing to Cloud via system telemetry
- Deep watering cycle tracking
- Daily limits enforcement

---

## 12. CONNECTION MAP

```
┌────────────────────────────────────────────────────────────────┐
│                         ESP32 FIRMWARE                         │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────┐     ┌──────────────────┐     ┌─────────────────┐ │
│   │ sensor.c│────▶│ sensor_controller│────▶│    pump.c       │ │
│   │ J5/J6   │     │      .c          │     │                 │ │
│   │ J7      │     │ States, Presets  │     │ Start/Stop      │ │
│   └─────────┘     └──────────────────┘     └─────────────────┘ │
│        │                   │                        │           │
│        │                   │                        │           │
│        ▼                   ▼                        ▼           │
│   ┌─────────────────────────────────────────────────────────┐  │
│   │                    aws_iot.c                             │  │
│   │  publish_sensor() | publish_system() | publish_pump()    │  │
│   └─────────────────────────────────────────────────────────┘  │
│        │                   │                        │           │
│        │                   │                        │           │
│   ┌─────────────────────────────────────────────────────────┐  │
│   │                   web_server.c                           │  │
│   │  /api/moisture | /api/sensor/controller/* | /api/status  │  │
│   └─────────────────────────────────────────────────────────┘  │
│                                                                 │
└────────────────────────────────────────────────────────────────┘
                              │
                              │ MQTT
                              ▼
┌────────────────────────────────────────────────────────────────┐
│                         AWS IoT CORE                           │
│  Topics: Polivalka/+/sensor | Polivalka/+/system | .../pump    │
└────────────────────────────────────────────────────────────────┘
                              │
                              │ IoT Rules
                              ▼
┌────────────────────────────────────────────────────────────────┐
│                     iot_rule_telemetry.py                      │
│  - Detect data_type (sensor/battery/system/pump)               │
│  - Save to time-series (real timestamp)                        │
│  - Save to "latest" record (timestamp=0)                       │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│                      DynamoDB Tables                           │
│  polivalka_telemetry: PK=device_id, SK=timestamp               │
│  polivalka_devices: PK=user_id, SK=device_id                   │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│                      api_handler.py                            │
│  GET /device/{id}/sensor/controller/status                     │
│  POST /device/{id}/sensor/controller/enable                    │
│  get_latest_telemetry() → reads timestamp=0 record             │
└────────────────────────────────────────────────────────────────┘
                              │
                              │ API Gateway
                              ▼
┌────────────────────────────────────────────────────────────────┐
│                      Cloud Website                             │
│  home.html: Sensor display, state, warnings                    │
│  sensor.html: Controller UI, presets, configuration            │
└────────────────────────────────────────────────────────────────┘
```

---

## 13. VERIFICATION CHECKLIST

- [x] Sensor reads correct ADC values
- [x] Calibration persisted in NVS
- [x] Preflight blocks when J6 disconnected (mean<100, span<30)
- [x] Runtime warning on disconnect
- [x] Safety stop in CHECK state on disconnect
- [x] State machine transitions correct
- [x] Pump starts/stops correctly
- [x] Volume tracking accurate
- [x] Daily limits enforced
- [x] Deep watering cycles tracked
- [x] System telemetry includes warning_active/warning_msg
- [x] Lambda saves to latest record
- [x] API reads from latest record
- [x] Cloud UI displays warnings
- [x] J7 detection correct (ADC=0 is valid)

---

## 14. CONCLUSION

**Sensor Mode is fully connected end-to-end.**

All data flows verified:
1. Hardware → sensor.c → sensor_controller.c
2. sensor_controller.c → aws_iot.c → MQTT
3. MQTT → IoT Rule → Lambda → DynamoDB
4. DynamoDB → api_handler.py → Cloud UI

**Critical safety features verified:**
- Preflight blocking prevents operation without sensor
- Runtime detection warns and stops watering if sensor fails
- Daily limits prevent overwatering
- Deep watering cycle tracking works

**Issues fixed during audit:**
- J7 detection thresholds
- System telemetry in latest record
- API reading all data types from latest
