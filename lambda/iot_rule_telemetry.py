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

    # Save to DynamoDB telemetry table using UpdateItem
    # ВАЖНО: Используем UpdateItem вместо PutItem чтобы НЕ перезаписывать другие типы данных!
    # Если pump и sensor приходят с одинаковым timestamp (в пределах секунды),
    # PutItem перезаписывал первую запись. UpdateItem добавляет поля к существующей записи.
    try:
        data_converted = convert_floats_to_decimal(data)
        telemetry_table.update_item(
            Key={'device_id': device_id, 'timestamp': timestamp},
            UpdateExpression='SET #dt = :data, #ttl = :ttl',
            ExpressionAttributeNames={
                '#dt': data_type,
                '#ttl': 'ttl'
            },
            ExpressionAttributeValues={
                ':data': data_converted,
                ':ttl': timestamp + TTL_SECONDS
            }
        )
        print(f"Saved {data_type} data for {device_id} at {timestamp}")
    except Exception as e:
        print(f"Error saving telemetry: {e}")
        return {'statusCode': 500, 'body': str(e)}

    # Also update "latest" record (timestamp=0) for quick access from home.html
    # This ensures fresh data is available without sending get_status command
    if data_type in ['sensor', 'battery']:
        try:
            telemetry_table.update_item(
                Key={'device_id': device_id, 'timestamp': 0},
                UpdateExpression='SET #dt = :data, last_update = :ts',
                ExpressionAttributeNames={'#dt': data_type},
                ExpressionAttributeValues={
                    ':data': convert_floats_to_decimal(data),
                    ':ts': timestamp
                }
            )
            print(f"Updated latest record for {device_id}: {data_type}")
        except Exception as e:
            print(f"Failed to update latest record: {e}")  # Non-fatal

    # If system telemetry with device info, update Devices table
    if data_type == 'system':
        device_name = data.get('device_name')
        location = data.get('location')
        room = data.get('room')
        wifi_scan_interval = data.get('wifi_scan_interval_hours')

        # Only update if at least one field is present and non-empty
        if device_name or location or room or wifi_scan_interval:
            # Find user_id for this device (scan the table)
            try:
                scan_response = devices_table.scan(
                    FilterExpression='device_id = :device',
                    ExpressionAttributeValues={':device': device_id}
                )

                if scan_response['Items'] and len(scan_response['Items']) > 0:
                    user_id = scan_response['Items'][0]['user_id']

                    update_expr_parts = []
                    expr_attr_values = {}

                    if device_name:
                        update_expr_parts.append('device_name = :name')
                        expr_attr_values[':name'] = device_name
                    if location:
                        update_expr_parts.append('location = :loc')
                        expr_attr_values[':loc'] = location
                    if room:
                        update_expr_parts.append('room = :room')
                        expr_attr_values[':room'] = room
                    if wifi_scan_interval:
                        update_expr_parts.append('wifi_scan_interval_hours = :wifi_scan')
                        expr_attr_values[':wifi_scan'] = wifi_scan_interval

                    devices_table.update_item(
                        Key={'user_id': user_id, 'device_id': device_id},
                        UpdateExpression='SET ' + ', '.join(update_expr_parts),
                        ExpressionAttributeValues=expr_attr_values
                    )
                    print(f"Updated device info for {device_id}: name={device_name}, location={location}, room={room}, wifi_scan={wifi_scan_interval}")
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

                # Update last_watering_timestamp on pump stop
                if action == 'stop':
                    update_expr_parts.append('last_watering_timestamp = :ts')
                    expr_values[':ts'] = timestamp

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
                    print(f"Updated pump data for {device_id}: action={action}, speed={pump_speed}, calibration={pump_calibration}")
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
