"""
IoT Rule Handler - Save MQTT telemetry to DynamoDB

Triggered by IoT Rules:
  - Polivalka/+/sensor  → save sensor data
  - Polivalka/+/battery → save battery data
  - Polivalka/+/pump    → save pump events
  - Polivalka/+/system  → save system state
  - Polivalka/+/config  → save config to devices table

Input (from MQTT):
  {
    "device_id": "Polivalka-BB00C1",
    "timestamp": 1731586800,
    "sensor": {
      "moisture_percent": 45,
      "adc_raw": 2340
    }
  }

Output (to DynamoDB polivalka_telemetry):
  PK: device_id = "Polivalka-BB00C1"
  SK: timestamp = 1731586800 (numeric)
  sensor: {moisture_percent: 45, adc_raw: 2340}  (data in ROOT, not nested)
  ttl: timestamp + 7 days
"""

import json
import boto3
import os
from decimal import Decimal

dynamodb = boto3.resource('dynamodb', region_name='eu-central-1')


def convert_floats_to_decimal(obj):
    """Recursively convert floats to Decimals for DynamoDB compatibility"""
    if isinstance(obj, float):
        return Decimal(str(obj))
    elif isinstance(obj, dict):
        return {k: convert_floats_to_decimal(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_floats_to_decimal(item) for item in obj]
    return obj


TELEMETRY_TABLE = os.environ.get('TELEMETRY_TABLE', 'polivalka_telemetry')
DEVICES_TABLE = os.environ.get('DEVICES_TABLE', 'polivalka_devices')
telemetry_table = dynamodb.Table(TELEMETRY_TABLE)
devices_table = dynamodb.Table(DEVICES_TABLE)

# TTL = 7 days (604800 seconds)
TTL_SECONDS = 7 * 24 * 3600


def lambda_handler(event, context):
    """Save MQTT telemetry to DynamoDB"""

    # Extract device_id from MQTT message
    # СТАНДАРТ: device_id ВСЕГДА в формате "Polivalka-BC67E9" (с префиксом!)
    device_id = event.get('device_id', '')  # "Polivalka-BB00C1"
    timestamp = event.get('timestamp', 0)

    # Determine data type (sensor, battery, pump, system)
    data_type = None
    data = None

    # Handle config messages differently - save to devices table, not telemetry
    if 'config_type' in event:
        return handle_config(event, device_id, timestamp)

    if 'sensor' in event:
        data_type = 'sensor'
        data = event['sensor']
    elif 'battery' in event:
        data_type = 'battery'
        data = event['battery']
    elif 'pump' in event:
        data_type = 'pump'
        data = event['pump']
    elif 'system' in event:
        data_type = 'system'
        data = event['system']
    else:
        print(f"Unknown message type: {event}")
        return {'statusCode': 400, 'body': 'Unknown message type'}

    # Create DynamoDB item
    # ВАЖНО: Данные хранятся в КОРНЕ (sensor, battery, pump, system как top-level keys)
    # НЕ вложены в 'data' Map - для простоты query и совместимости
    item = {
        'device_id': device_id,
        'timestamp': timestamp,
        data_type: data,  # e.g., 'sensor': {...}, 'battery': {...}
        'ttl': timestamp + TTL_SECONDS
    }

    # Save to DynamoDB telemetry table
    # Convert floats to Decimal (DynamoDB doesn't support Python floats)
    try:
        item_converted = convert_floats_to_decimal(item)
        telemetry_table.put_item(Item=item_converted)
        print(f"Saved {data_type} data for {device_id} at {timestamp}")
    except Exception as e:
        print(f"Error saving telemetry: {e}")
        return {'statusCode': 500, 'body': str(e)}

    # If system telemetry, update Devices table with all device stats
    if data_type == 'system':
        # Extract all fields we want to persist to devices table
        device_name = data.get('device_name')
        location = data.get('location')
        room = data.get('room')
        wifi_scan_interval = data.get('wifi_scan_interval_hours')
        firmware_version = data.get('firmware_version')
        reboot_count = data.get('reboot_count')
        clean_restarts = data.get('clean_restarts')
        unexpected_restarts = data.get('unexpected_restarts')
        ota_count = data.get('ota_count')
        ota_last_timestamp = data.get('ota_last_timestamp')
        # Boot info - important for debugging battery/crash issues
        boot_type = data.get('boot_type')
        reset_reason = data.get('reset_reason')

        # Find user_id for this device (scan the table)
        try:
            scan_response = devices_table.scan(
                FilterExpression='device_id = :device',
                ExpressionAttributeValues={':device': device_id}
            )

            if scan_response['Items'] and len(scan_response['Items']) > 0:
                user_id = scan_response['Items'][0]['user_id']

                update_expr_parts = ['last_update = :ts']  # Always update last_update
                expr_attr_values = {':ts': timestamp}
                expr_attr_names = {}  # For reserved words

                # Device info (location is reserved word in DynamoDB!)
                if device_name:
                    update_expr_parts.append('device_name = :name')
                    expr_attr_values[':name'] = device_name
                if location:
                    update_expr_parts.append('#loc = :loc')
                    expr_attr_names['#loc'] = 'location'
                    expr_attr_values[':loc'] = location
                if room:
                    update_expr_parts.append('room = :room')
                    expr_attr_values[':room'] = room
                if wifi_scan_interval is not None:
                    update_expr_parts.append('wifi_scan_interval_hours = :wifi_scan')
                    expr_attr_values[':wifi_scan'] = wifi_scan_interval

                # Get current item for comparison
                current_item = scan_response['Items'][0]
                current_firmware = current_item.get('firmware_version', '')
                firmware_changed = firmware_version and firmware_version != current_firmware

                # Firmware version (always update)
                if firmware_version:
                    update_expr_parts.append('firmware_version = :fw')
                    expr_attr_values[':fw'] = firmware_version
                    if firmware_changed:
                        print(f"Firmware version changed: {current_firmware} -> {firmware_version} for {device_id}")

                # COUNTERS: Only update if new value >= old value (prevent data loss)
                # NO automatic reset on firmware change - counters are reset manually by admin only
                # reboot_count - total reboots (always update from ESP32 - source of truth)
                if reboot_count is not None:
                    update_expr_parts.append('reboot_count = :reboot')
                    expr_attr_values[':reboot'] = reboot_count

                # clean_restarts and unexpected_restarts - PROTECTED counters
                # Allow update if:
                # 1. Value increased (normal operation)
                # 2. Admin manual reset (new value < 20 and is a decrease)
                if clean_restarts is not None:
                    current_clean = current_item.get('clean_restarts', 0)
                    is_admin_reset = clean_restarts < 20 and current_clean > clean_restarts
                    if clean_restarts >= current_clean or is_admin_reset:
                        update_expr_parts.append('clean_restarts = :clean')
                        expr_attr_values[':clean'] = clean_restarts
                        if clean_restarts < current_clean:
                            print(f"Admin counter reset - clean_restarts: {current_clean} -> {clean_restarts} for {device_id}")
                    else:
                        print(f"WARN: Ignoring clean_restarts decrease {current_clean} -> {clean_restarts} for {device_id}")

                if unexpected_restarts is not None:
                    current_unexpected = current_item.get('unexpected_restarts', 0)
                    is_admin_reset = unexpected_restarts < 20 and current_unexpected > unexpected_restarts
                    if unexpected_restarts >= current_unexpected or is_admin_reset:
                        update_expr_parts.append('unexpected_restarts = :unexpected')
                        expr_attr_values[':unexpected'] = unexpected_restarts
                        if unexpected_restarts < current_unexpected:
                            print(f"Admin counter reset - unexpected_restarts: {current_unexpected} -> {unexpected_restarts} for {device_id}")
                    else:
                        print(f"WARN: Ignoring unexpected_restarts decrease {current_unexpected} -> {unexpected_restarts} for {device_id}")

                # OTA stats - also protected (only increase)
                if ota_count is not None:
                    current_item = scan_response['Items'][0]
                    current_ota = current_item.get('ota_count', 0)
                    if ota_count >= current_ota:
                        update_expr_parts.append('ota_count = :ota_count')
                        expr_attr_values[':ota_count'] = ota_count
                    else:
                        print(f"WARN: Ignoring ota_count decrease {current_ota} -> {ota_count} for {device_id}")
                if ota_last_timestamp is not None:
                    update_expr_parts.append('ota_last_timestamp = :ota_ts')
                    expr_attr_values[':ota_ts'] = ota_last_timestamp

                # Boot info - always update (useful for debugging battery/crash issues)
                if boot_type:
                    update_expr_parts.append('boot_type = :boot_type')
                    expr_attr_values[':boot_type'] = boot_type
                if reset_reason:
                    update_expr_parts.append('reset_reason = :reset_reason')
                    expr_attr_values[':reset_reason'] = reset_reason

                update_kwargs = {
                    'Key': {'user_id': user_id, 'device_id': device_id},
                    'UpdateExpression': 'SET ' + ', '.join(update_expr_parts),
                    'ExpressionAttributeValues': expr_attr_values
                }
                if expr_attr_names:
                    update_kwargs['ExpressionAttributeNames'] = expr_attr_names

                devices_table.update_item(**update_kwargs)
                print(f"Updated device stats for {device_id}: fw={firmware_version}, clean={clean_restarts}, unexpected={unexpected_restarts}, ota={ota_count}, boot={boot_type}")
            else:
                print(f"Device {device_id} not found in devices table")
        except Exception as e:
            print(f"Error updating device info: {e}")
            # Don't fail the whole Lambda - telemetry is already saved

    # If pump event, update devices table (last_watering, speed, calibration)
    if data_type == 'pump':
        action = data.get('action')
        pump_speed = data.get('speed')
        pump_calibration = data.get('calibration')

        # Find user_id for this device (scan the table)
        try:
            scan_response = devices_table.scan(
                FilterExpression='device_id = :device',
                ExpressionAttributeValues={':device': device_id}
            )

            if scan_response['Items'] and len(scan_response['Items']) > 0:
                user_id = scan_response['Items'][0]['user_id']

                update_expr_parts = []
                expr_values = {}

                # Update last_watering_timestamp and aggregate stats on pump stop
                if action == 'stop':
                    update_expr_parts.append('last_watering_timestamp = :ts')
                    expr_values[':ts'] = timestamp

                    # Aggregate total_water_ml
                    volume_ml = data.get('volume_ml', 0)
                    if volume_ml and volume_ml > 0:
                        update_expr_parts.append('total_water_ml = if_not_exists(total_water_ml, :zero) + :vol')
                        expr_values[':vol'] = int(volume_ml)
                        expr_values[':zero'] = 0

                    # Aggregate pump_runtime_sec
                    duration_sec = data.get('duration_sec', 0)
                    if duration_sec and duration_sec > 0:
                        update_expr_parts.append('pump_runtime_sec = if_not_exists(pump_runtime_sec, :zero2) + :dur')
                        expr_values[':dur'] = int(duration_sec)
                        expr_values[':zero2'] = 0

                # Admin reset: reset all pump stats and restart counters to 0
                elif action == 'admin_reset':
                    update_expr_parts = [
                        'total_water_ml = :zero',
                        'pump_runtime_sec = :zero',
                        'reboot_count = :zero',
                        'clean_restarts = :zero',
                        'unexpected_restarts = :zero'
                    ]
                    expr_values = {':zero': 0}
                    print(f"ADMIN RESET for {device_id}: resetting pump stats and restart counters")

                # Update pump_speed if present
                if pump_speed is not None:
                    update_expr_parts.append('pump_speed = :speed')
                    expr_values[':speed'] = int(pump_speed)

                # Update pump_calibration if present
                if pump_calibration is not None:
                    update_expr_parts.append('pump_calibration = :calib')
                    expr_values[':calib'] = Decimal(str(pump_calibration))

                if update_expr_parts:
                    devices_table.update_item(
                        Key={'user_id': user_id, 'device_id': device_id},
                        UpdateExpression='SET ' + ', '.join(update_expr_parts),
                        ExpressionAttributeValues=expr_values
                    )
                    print(f"Updated pump data for {device_id}: action={action}, volume_ml={data.get('volume_ml')}, duration_sec={data.get('duration_sec')}, speed={pump_speed}")
            else:
                print(f"Device {device_id} not found in devices table for pump update")
        except Exception as e:
            print(f"Error updating pump data: {e}")
            # Don't fail the whole Lambda - telemetry is already saved

    return {'statusCode': 200, 'body': 'Saved'}


def handle_config(event, device_id, timestamp):
    """
    Handle config messages - save to devices table (not telemetry)
    Config is stored per-device, not as time-series data

    Expected format:
    {
        "device_id": "Polivalka-BB00C1",
        "timestamp": 1731586800,
        "config_type": "timer",
        "schedules": [...]
    }
    """
    config_type = event.get('config_type')  # "timer", "sensor", etc.

    # Find user_id for this device (scan the table)
    try:
        scan_response = devices_table.scan(
            FilterExpression='device_id = :device',
            ExpressionAttributeValues={':device': device_id}
        )

        if not scan_response['Items'] or len(scan_response['Items']) == 0:
            print(f"Device {device_id} not found in devices table for config save")
            return {'statusCode': 404, 'body': 'Device not found'}

        user_id = scan_response['Items'][0]['user_id']

        # Build update expression based on config_type
        if config_type == 'timer':
            schedules = event.get('schedules', [])
            devices_table.update_item(
                Key={'user_id': user_id, 'device_id': device_id},
                UpdateExpression='SET config_timer = :cfg, config_timer_updated = :ts',
                ExpressionAttributeValues={
                    ':cfg': schedules,
                    ':ts': timestamp
                }
            )
            print(f"Saved timer config for {device_id}: {len(schedules)} schedules")

        elif config_type == 'sensor':
            # ESP32 sends all sensor fields in root, build config object
            sensor_config = {
                'preset': event.get('preset', 'Custom'),
                'start_pct': event.get('start_pct', 35),
                'stop_pct': event.get('stop_pct', 55),
                'pulse_sec': event.get('pulse_sec', 5),
                'wait_sec': event.get('wait_sec', 120),
                'max_water_cycle_ml': event.get('max_water_cycle_ml', 300),
                'cooldown_min': event.get('cooldown_min', 120),
                'max_water_day_ml': event.get('max_water_day_ml', 400),
                'no_rise_check_ml': event.get('no_rise_check_ml', 60),
                'idle_check_interval_min': event.get('idle_check_interval_min', 60),
                'microprime_interval_hours': event.get('microprime_interval_hours', 48),
                'microprime_pulse_sec': event.get('microprime_pulse_sec', 4),
                'microprime_settle_sec': event.get('microprime_settle_sec', 90),
                'baseline_delta_pct_per_ml': event.get('baseline_delta_pct_per_ml', 0.0)
            }
            sensor_config = convert_floats_to_decimal(sensor_config)
            devices_table.update_item(
                Key={'user_id': user_id, 'device_id': device_id},
                UpdateExpression='SET config_sensor = :cfg, config_sensor_updated = :ts',
                ExpressionAttributeValues={
                    ':cfg': sensor_config,
                    ':ts': timestamp
                }
            )
            print(f"Saved sensor config for {device_id}: preset={sensor_config['preset']}")

        else:
            print(f"Unknown config_type: {config_type}")
            return {'statusCode': 400, 'body': f'Unknown config_type: {config_type}'}

        return {'statusCode': 200, 'body': f'Config {config_type} saved'}

    except Exception as e:
        print(f"Error saving config: {e}")
        return {'statusCode': 500, 'body': str(e)}
