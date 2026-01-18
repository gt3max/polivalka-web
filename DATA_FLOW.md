# Polivalka Data Flow Documentation

## Overview

This document describes the complete data flow from ESP32 device to Cloud UI.
**Always consult this document when debugging telemetry/display issues.**

```
ESP32 → MQTT → IoT Rule → Lambda → DynamoDB → API Lambda → Web UI
```

---

## 1. Telemetry Types

| Type     | Topic                    | Interval      | Contains                                    |
|----------|--------------------------|---------------|---------------------------------------------|
| sensor   | Polivalka/{id}/sensor    | 60 min        | moisture_percent, adc_raw, sensor2_*        |
| battery  | Polivalka/{id}/battery   | 60 min        | voltage, percent, charging                  |
| system   | Polivalka/{id}/system    | 30 min        | firmware_version, reboot_count, state, etc  |
| pump     | Polivalka/{id}/pump      | on event      | action, volume_ml, duration_sec             |

---

## 2. MQTT Message Format

All telemetry uses **nested structure**:

```json
{
  "device_id": "Polivalka-BB00C1",
  "timestamp": 1737226800,
  "<type>": {
    // type-specific data
  }
}
```

### Example: System Telemetry
```json
{
  "device_id": "Polivalka-BB00C1",
  "timestamp": 1737226800,
  "system": {
    "mode": "sensor",
    "state": "STAND-BY",
    "firmware_version": "v1.0.48",
    "reboot_count": 5,
    "clean_restarts": 3,
    "unexpected_restarts": 2,
    "uptime_ms": 3600000,
    ...
  }
}
```

---

## 3. Lambda Processing (iot_rule_telemetry.py)

### 3.1 Telemetry Detection
```python
if 'sensor' in event:
    data_type = 'sensor'
    data = event['sensor']
elif 'battery' in event:
    data_type = 'battery'
    data = event['battery']
elif 'system' in event:
    data_type = 'system'
    data = event['system']
elif 'pump' in event:
    data_type = 'pump'
    data = event['pump']
```

### 3.2 DynamoDB Storage

**Two records per telemetry message:**

1. **Time-series record** (for history/trends):
   ```
   PK: device_id = "Polivalka-BB00C1"
   SK: timestamp = 1737226800
   {type}: {...data...}
   ttl: timestamp + 7 days
   ```

2. **Latest record** (for quick access):
   ```
   PK: device_id = "Polivalka-BB00C1"
   SK: timestamp = 0
   {type}: {...data...}
   last_update: 1737226800
   ```

**CRITICAL:** sensor, battery, AND system all save to latest record!

---

## 4. API Reading (api_handler.py)

### 4.1 get_latest_telemetry()

Reads data in two steps:

1. **Latest record (timestamp=0)** - fast, always current
2. **Query last 24h** - backup, finds all types

```python
# Step 1: Read latest record
latest_record = telemetry_table.get_item(
    Key={'device_id': device_id, 'timestamp': 0}
)
# Extract ALL types (sensor, battery, system)
for data_type in ['sensor', 'battery', 'system']:
    if data_type in item:
        latest[data_type] = dict(item[data_type])

# Step 2: Query recent records (backup)
response = telemetry_table.query(...)
```

### 4.2 Response Format

```python
device_data = {
    'device_id': device_id,
    'firmware_version': latest.get('system', {}).get('firmware_version'),
    'reboot_count': latest.get('system', {}).get('reboot_count'),
    'battery_pct': latest.get('battery', {}).get('percent'),
    ...
}
```

---

## 5. Web UI Display

### 5.1 Admin Panel (admin.html)

```javascript
// Reads from /devices endpoint
document.getElementById('stat-firmware').textContent = device.firmware_version;
document.getElementById('stat-reboot-count').textContent = device.reboot_count;
```

### 5.2 Home Page (home.html)

```javascript
// Reads from /status endpoint
const batteryStatus = document.getElementById('battery-status');
if (s.battery && s.battery.percent >= 0) {
    batteryStatus.textContent = `🔋 ${percent}%`;
}
```

---

## 6. Common Failure Points

### 6.1 Lambda not saving to latest record
**Symptom:** Old data shown, new telemetry ignored
**Check:** iot_rule_telemetry.py line 122: includes 'sensor', 'battery', 'system'

### 6.2 API not reading from latest record
**Symptom:** Fallback to defaults (v1.0.0, null, etc)
**Check:** api_handler.py get_latest_telemetry() reads all types

### 6.3 Timestamp issues
**Symptom:** Data saved with wrong timestamp
**Check:** Timestamp sanitization (< 1000000000 → use server time)

### 6.4 Nested structure mismatch
**Symptom:** "Unknown message type"
**Check:** ESP32 sends `{"system": {...}}`, Lambda expects `'system' in event`

---

## 7. Debugging Checklist

When telemetry doesn't display correctly:

1. **ESP32 Log:** Confirm publish succeeded (`Publishing to Polivalka/.../system`)
2. **CloudWatch Lambda Log:** Check iot_rule_telemetry for errors
3. **DynamoDB:** Query timestamp=0 record, verify data exists
4. **API CloudWatch:** Check api_handler for get_latest_telemetry output
5. **Browser Console:** Check API response contains expected fields

---

## 8. Files Reference

| Layer      | File                              | Purpose                           |
|------------|-----------------------------------|-----------------------------------|
| ESP32      | aws_iot.c:1699-2044              | MQTT publish functions            |
| IoT Rule   | (AWS Console)                     | Routes topics to Lambda           |
| Lambda     | iot_rule_telemetry.py            | Saves to DynamoDB                 |
| DynamoDB   | polivalka_telemetry              | Stores telemetry data             |
| API        | api_handler.py:2699-2756         | get_latest_telemetry()            |
| Web        | admin.html, home.html, fleet.html| Display                           |

---

## 9. Modification Checklist

When adding new telemetry field:

- [ ] Add to ESP32 publish function (aws_iot.c)
- [ ] Add to Lambda processing if new type (iot_rule_telemetry.py)
- [ ] Add to API response (api_handler.py)
- [ ] Add to Web display (*.html)
- [ ] Update this documentation

When changing telemetry structure:

- [ ] Update BOTH ESP32 AND Lambda (must match)
- [ ] Update API extraction logic
- [ ] Update Web JS parsing
- [ ] Test end-to-end before deploy
