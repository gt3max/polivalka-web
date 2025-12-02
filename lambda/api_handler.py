"""
Polivalka Cloud API - Lambda Handler
Handles all API Gateway requests for Cloud Dashboard

API Endpoints:
  GET  /devices                    - List user's devices
  GET  /device/{id}/status         - Get device status
  POST /device/{id}/command        - Send MQTT command
  GET  /device/{id}/sensor/history - Sensor data history (7 days)
  GET  /device/{id}/battery/history- Battery data history (7 days)

DynamoDB Tables:
  - polivalka_devices    (PK: user_id, SK: device_id)
  - polivalka_telemetry  (PK: device_id, SK: timestamp) - data stored in ROOT (sensor, battery, system, pump)
  - polivalka_commands   (PK: device_id, SK: command_id)

Environment Variables:
  - DEVICES_TABLE=polivalka_devices
  - TELEMETRY_TABLE=polivalka_telemetry
  - COMMANDS_TABLE=polivalka_commands
  - IOT_ENDPOINT=xxx.iot.eu-central-1.amazonaws.com
"""

import json
import boto3
import time
import uuid
import hashlib
import hmac
import base64
import os
from decimal import Decimal
from boto3.dynamodb.conditions import Key

# ============ JWT Verification ============

# JWT secret (same as auth_handler.py)
JWT_SECRET = os.environ.get('JWT_SECRET', 'polivalka-jwt-secret-v1-change-later')


def base64url_decode(data):
    """URL-safe base64 decoding with padding restoration"""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def verify_jwt(token):
    """Verify JWT token and return payload or None"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None

        header_b64, payload_b64, signature_b64 = parts

        # Verify signature
        message = f"{header_b64}.{payload_b64}"
        expected_sig = hmac.new(
            JWT_SECRET.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).digest()
        actual_sig = base64url_decode(signature_b64)

        if not hmac.compare_digest(expected_sig, actual_sig):
            return None

        # Decode payload
        payload = json.loads(base64url_decode(payload_b64))

        # Check expiration
        if payload.get('exp', 0) < time.time():
            return None

        return payload
    except Exception:
        return None


def get_user_from_event(event):
    """Extract and verify user from JWT token in Authorization header"""
    headers = event.get('headers', {})
    # HTTP API v2 uses lowercase headers
    auth_header = headers.get('Authorization') or headers.get('authorization', '')

    if not auth_header.startswith('Bearer '):
        return None

    token = auth_header[7:]
    payload = verify_jwt(token)

    if not payload or payload.get('type') != 'access':
        return None

    return payload.get('email')


# ============ End JWT ============

# ALL resources in eu-central-1 (Frankfurt)
dynamodb = boto3.resource('dynamodb', region_name='eu-central-1')
# IoT Data client requires explicit endpoint
iot_client = boto3.client('iot-data',
                         region_name='eu-central-1',
                         endpoint_url='https://a3vtuj03g69hnf-ats.iot.eu-central-1.amazonaws.com')
s3_client = boto3.client('s3',
                        region_name='eu-central-1',
                        config=boto3.session.Config(signature_version='s3v4'))

# Table names (from environment)
import os
DEVICES_TABLE = os.environ.get('DEVICES_TABLE', 'polivalka_devices')
TELEMETRY_TABLE = os.environ.get('TELEMETRY_TABLE', 'polivalka_telemetry')
COMMANDS_TABLE = os.environ.get('COMMANDS_TABLE', 'polivalka_commands')
FIRMWARE_BUCKET = os.environ.get('FIRMWARE_BUCKET', 'polivalka-firmware')

# All tables in eu-central-1
devices_table = dynamodb.Table(DEVICES_TABLE)
telemetry_table = dynamodb.Table(TELEMETRY_TABLE)
commands_table = dynamodb.Table(COMMANDS_TABLE)


def lambda_handler(event, context):
    """Main handler for API Gateway proxy integration"""

    # Support both API Gateway v1 (REST API) and v2 (HTTP API) formats
    if 'httpMethod' in event:
        # REST API v1 format
        http_method = event['httpMethod']
        path = event['path']
    elif 'requestContext' in event and 'http' in event['requestContext']:
        # HTTP API v2 format
        http_method = event['requestContext']['http']['method']
        path = event['requestContext']['http']['path']

        # Note: HTTP API v2 with $default stage does NOT include stage in path
        # Path will be directly /device/... not /prod/device/...
    else:
        # Unknown format - log and return error
        print(f"[ERROR] Unknown event format: {event}")
        return {
            'statusCode': 400,
            'headers': cors_headers(),
            'body': json.dumps({'error': 'Unknown API Gateway format'})
        }

    # Handle CORS preflight
    if http_method == 'OPTIONS':
        return {
            'statusCode': 200,
            'headers': cors_headers(),
            'body': ''
        }

    # Extract user_id from JWT token
    user_id = get_user_from_event(event)

    # For MVP: allow unauthenticated access with fallback to 'admin'
    # TODO: Remove this fallback when auth is fully deployed
    if not user_id:
        # Check if Authorization header is present but invalid
        headers = event.get('headers', {})
        auth_header = headers.get('Authorization') or headers.get('authorization', '')
        if auth_header:
            # Token was provided but invalid/expired
            return {
                'statusCode': 401,
                'headers': cors_headers(),
                'body': json.dumps({'error': 'Invalid or expired token'})
            }
        # No token provided - allow access for backward compatibility (MVP)
        # This will be removed once all clients are updated
        user_id = 'admin'
        print(f"[WARN] No auth token - using fallback user_id='admin'")

    # Route to appropriate handler
    print(f"[DEBUG] path={path}, user_id={user_id}")
    if path == '/devices' and http_method == 'GET':
        return get_devices(user_id)

    # Parse device_id from path /device/{id}/*
    if path.startswith('/device/'):
        parts = path.split('/')
        if len(parts) >= 3:
            device_id = parts[2]

            if len(parts) == 4 and parts[3] == 'status' and http_method == 'GET':
                return get_device_status(device_id, user_id)

            if len(parts) == 4 and parts[3] == 'command' and http_method == 'POST':
                body = json.loads(event.get('body', '{}'))
                return send_device_command(device_id, user_id, body)

            if len(parts) == 5 and parts[3] == 'command' and http_method == 'GET':
                command_id = parts[4]
                return get_command_result(device_id, user_id, command_id)

            if len(parts) == 4 and parts[3] == 'sensor' and http_method == 'GET':
                return get_sensor_realtime(device_id, user_id)

            if len(parts) == 5 and parts[3] == 'sensor' and parts[4] == 'history':
                return get_sensor_history(device_id, user_id)

            # Sensor presets endpoint - GET returns config from devices_table
            if len(parts) == 5 and parts[3] == 'sensor' and parts[4] == 'preset' and http_method == 'GET':
                # Get sensor config from devices_table (synced from ESP32)
                device_info = get_device_info(device_id, user_id)
                sensor_config = device_info.get('config_sensor', {})

                # Return config matching ESP32 /api/sensor/preset format
                return {
                    'statusCode': 200,
                    'headers': cors_headers(),
                    'body': json.dumps({
                        'preset': sensor_config.get('preset', 'Standard'),
                        'start_pct': sensor_config.get('start_pct', 35),
                        'stop_pct': sensor_config.get('stop_pct', 55),
                        'pulse_sec': sensor_config.get('pulse_sec', 5),
                        'wait_sec': sensor_config.get('wait_sec', 120),
                        'max_pulses': sensor_config.get('max_pulses', 5),
                        'cooldown_min': sensor_config.get('cooldown_min', 120),
                        'max_water_day_ml': sensor_config.get('max_water_day_ml', 400),
                        'no_rise_check_ml': sensor_config.get('no_rise_check_ml', 60),
                        'idle_check_interval_min': sensor_config.get('idle_check_interval_min', 60),
                        'microprime_interval_hours': sensor_config.get('microprime_interval_hours', 48),
                        'microprime_pulse_sec': sensor_config.get('microprime_pulse_sec', 4),
                        'microprime_settle_sec': sensor_config.get('microprime_settle_sec', 90),
                        'baseline_delta_pct_per_ml': sensor_config.get('baseline_delta_pct_per_ml', 0.0)
                    }, cls=DecimalEncoder)
                }

            # POST /device/{id}/sensor/preset/set - set preset by name (sends MQTT to ESP32)
            if len(parts) == 6 and parts[3] == 'sensor' and parts[4] == 'preset' and parts[5] == 'set' and http_method == 'POST':
                body = json.loads(event.get('body', '{}'))
                preset_name = body.get('preset')
                if not preset_name:
                    # Try query string
                    query_params = event.get('queryStringParameters', {}) or {}
                    preset_name = query_params.get('preset')
                if not preset_name:
                    return {'statusCode': 400, 'headers': cors_headers(), 'body': json.dumps({'error': 'Missing preset name'})}
                return send_command_with_params(device_id, user_id, 'sensor_preset_set', {'preset': preset_name}, f'Preset {preset_name} applied')

            # POST /device/{id}/sensor/preset/custom - set custom sensor parameters (sends MQTT to ESP32)
            if len(parts) == 6 and parts[3] == 'sensor' and parts[4] == 'preset' and parts[5] == 'custom' and http_method == 'POST':
                # Parse parameters from query string (matching ESP32 API format)
                query_params = event.get('queryStringParameters', {}) or {}
                params = {}

                # Parse all sensor parameters
                param_names = [
                    'start_moisture_pct', 'stop_moisture_pct', 'pulse_sec', 'wait_sec',
                    'max_pulses', 'cooldown_min', 'max_water_day_ml', 'no_rise_check_ml',
                    'idle_check_interval_min', 'microprime_interval_hours',
                    'microprime_pulse_sec', 'microprime_settle_sec'
                ]
                for param in param_names:
                    if param in query_params:
                        try:
                            params[param] = int(query_params[param])
                        except ValueError:
                            pass

                if not params:
                    return {'statusCode': 400, 'headers': cors_headers(), 'body': json.dumps({'error': 'No valid parameters'})}

                return send_command_with_params(device_id, user_id, 'sensor_set', params, 'Sensor settings saved')

            # Enable/disable sensor controller - send MQTT command to ESP32
            # Uses send_controller_command() which returns {success: true} (AP-compatible format)
            if len(parts) == 6 and parts[3] == 'sensor' and parts[4] == 'controller' and parts[5] == 'enable' and http_method == 'POST':
                return send_controller_command(device_id, user_id, 'sensor_controller_enable', 'Sensor controller enabled')

            if len(parts) == 6 and parts[3] == 'sensor' and parts[4] == 'controller' and parts[5] == 'disable' and http_method == 'POST':
                return send_controller_command(device_id, user_id, 'sensor_controller_disable', 'Sensor controller disabled')

            if len(parts) == 6 and parts[3] == 'sensor' and parts[4] == 'controller' and parts[5] == 'cancel' and http_method == 'POST':
                return send_controller_command(device_id, user_id, 'sensor_controller_cancel', 'Sensor watering cancelled')

            # Sensor controller status endpoint - returns data from telemetry
            if len(parts) == 6 and parts[3] == 'sensor' and parts[4] == 'controller' and parts[5] == 'status':
                # Get latest telemetry to determine controller state
                latest = get_latest_telemetry(device_id)
                mode = latest.get('system', {}).get('mode', 'manual')
                # Get state from system telemetry (ESP32 now sends it)
                state = latest.get('system', {}).get('state', 'DISABLED')
                # Get sensor data for moisture display
                sensor_data = latest.get('sensor', {})
                moisture_pct = sensor_data.get('percent', 0) or 0

                # arming_countdown: 60 when LAUNCH, 0 otherwise
                # Frontend will show countdown locally
                arming_countdown = 60 if state == 'LAUNCH' else 0

                return {
                    'statusCode': 200,
                    'headers': cors_headers(),
                    'body': json.dumps({
                        'state': state,
                        'arming_countdown': arming_countdown,
                        'moisture_pct': moisture_pct,
                        'daily_water_ml': 0,
                        'daily_hard_limit_reached': False,
                        'pulses_delivered': 0,
                        'total_water_ml': 0,
                        'cooldown_remaining': 0,
                        'warning_active': False,
                        'warning_msg': '',
                        'watering': state in ['PULSE', 'SETTLE', 'CHECK'],
                        'start_threshold': 35,
                        'stop_threshold': 55,
                        'pulse_duration': 32,
                        'retry_interval': 600,
                        'last_check': None,
                        'last_watering': None,
                        'timestamp': int(time.time())
                    })
                }

            # Timer controller endpoints - send MQTT command to ESP32
            # Uses send_controller_command() which returns {success: true} (AP-compatible format)
            if len(parts) == 6 and parts[3] == 'timer' and parts[4] == 'controller' and parts[5] == 'enable' and http_method == 'POST':
                return send_controller_command(device_id, user_id, 'timer_controller_enable', 'Timer controller enabled')

            if len(parts) == 6 and parts[3] == 'timer' and parts[4] == 'controller' and parts[5] == 'disable' and http_method == 'POST':
                return send_controller_command(device_id, user_id, 'timer_controller_disable', 'Timer controller disabled')

            if len(parts) == 6 and parts[3] == 'timer' and parts[4] == 'controller' and parts[5] == 'cancel' and http_method == 'POST':
                return send_controller_command(device_id, user_id, 'timer_controller_cancel', 'Timer watering cancelled')

            # Schedule management endpoints - send MQTT command to ESP32
            # POST /device/{id}/schedule/set - create/update schedule
            if len(parts) == 5 and parts[3] == 'schedule' and parts[4] == 'set' and http_method == 'POST':
                body = json.loads(event.get('body', '{}'))
                # Convert time "HH:MM" to hour/minute if needed
                if 'time' in body and ':' in str(body.get('time', '')):
                    time_parts = body['time'].split(':')
                    body['hour'] = int(time_parts[0])
                    body['minute'] = int(time_parts[1])
                # Convert days array to days_mask if needed
                if 'days' in body and isinstance(body['days'], list):
                    mask = 0
                    for d in body['days']:
                        mask |= (1 << (d - 1))  # day 1=Mon -> bit 0
                    body['days_mask'] = mask
                # Convert unit string to number if needed
                if 'unit' in body and isinstance(body['unit'], str):
                    unit_map = {'sec': 0, 'min': 1, 'hr': 2}
                    body['unit'] = unit_map.get(body['unit'], 0)
                return send_command_with_params(device_id, user_id, 'schedule_set', body, 'Schedule saved')

            # POST /device/{id}/schedule/delete - delete schedule
            if len(parts) == 5 and parts[3] == 'schedule' and parts[4] == 'delete' and http_method == 'POST':
                body = json.loads(event.get('body', '{}'))
                schedule_id = body.get('id')
                if schedule_id is None:
                    return {'statusCode': 400, 'headers': cors_headers(), 'body': json.dumps({'error': 'Missing schedule id'})}
                return send_command_with_params(device_id, user_id, 'schedule_delete', {'id': schedule_id}, 'Schedule deleted')

            if len(parts) == 6 and parts[3] == 'timer' and parts[4] == 'controller' and parts[5] == 'status' and http_method == 'GET':
                # Get latest telemetry to determine controller state
                latest = get_latest_telemetry(device_id)
                mode = latest.get('system', {}).get('mode', 'manual')
                # Get state from system telemetry (ESP32 now sends it)
                state = latest.get('system', {}).get('state', 'DISABLED')

                # arming_countdown_sec: 15 when LAUNCH, 0 otherwise (timer uses 15 sec)
                arming_countdown_sec = 15 if state == 'LAUNCH' else 0

                return {
                    'statusCode': 200,
                    'headers': cors_headers(),
                    'body': json.dumps({
                        'state': state,
                        'arming_countdown_sec': arming_countdown_sec,
                        'schedule_exists': True,
                        'next_watering_str': 'Not scheduled',
                        'current_duration_sec': 0,
                        'daily_water_ml': 0,
                        'warning_active': False,
                        'warning_msg': '',
                        'morning_enabled': True,
                        'morning_time': '06:00',
                        'evening_enabled': False,
                        'evening_time': '20:00',
                        'duration': 30,
                        'timestamp': int(time.time())
                    })
                }

            # Time status endpoint - for timer.html and settings.html
            if len(parts) == 5 and parts[3] == 'time' and parts[4] == 'status' and http_method == 'GET':
                latest = get_latest_telemetry(device_id)
                time_set = latest.get('system', {}).get('time_set', False)
                # Get device's timestamp from system telemetry
                device_ts = latest.get('system', {}).get('timestamp') or latest.get('timestamp')

                # Get timezone from devices_table (default: CET = UTC+1)
                device_info = get_device_info(device_id, user_id)
                tz_string = device_info.get('timezone', 'CET-1CEST,M3.5.0,M10.5.0/3')
                tz_offset_minutes = parse_timezone_offset(tz_string)

                current_time = None
                if device_ts:
                    from datetime import datetime, timezone as dt_timezone, timedelta
                    # Convert to local time using offset
                    utc_dt = datetime.fromtimestamp(int(device_ts), tz=dt_timezone.utc)
                    local_dt = utc_dt + timedelta(minutes=tz_offset_minutes)
                    current_time = local_dt.strftime('%Y-%m-%dT%H:%M:%S')

                return {
                    'statusCode': 200,
                    'headers': cors_headers(),
                    'body': json.dumps({
                        'time_set': time_set,
                        'source': 'ntp' if time_set else 'none',
                        'timestamp': int(time.time()),
                        'current_time': current_time,
                        'timezone': tz_string
                    })
                }

            # Timezone GET endpoint - for settings.html
            if len(parts) == 5 and parts[3] == 'time' and parts[4] == 'timezone' and http_method == 'GET':
                device_info = get_device_info(device_id, user_id)
                tz_string = device_info.get('timezone', 'CET-1CEST,M3.5.0,M10.5.0/3')
                return {
                    'statusCode': 200,
                    'headers': cors_headers(),
                    'body': json.dumps({
                        'success': True,
                        'timezone': tz_string
                    })
                }

            # Timezone POST endpoint - save to DynamoDB + send MQTT to ESP32
            if len(parts) == 5 and parts[3] == 'time' and parts[4] == 'timezone' and http_method == 'POST':
                body = json.loads(event.get('body', '{}'))
                new_tz = body.get('timezone', '')
                if not new_tz:
                    return {'statusCode': 400, 'headers': cors_headers(), 'body': json.dumps({'success': False, 'error': 'Missing timezone'})}

                # Save to devices_table (admin-aware: find actual user_id from device record)
                device_info = get_device_info(device_id, user_id)
                if not device_info:
                    return {'statusCode': 404, 'headers': cors_headers(), 'body': json.dumps({'error': 'Device not found'})}

                # Use the actual user_id from DynamoDB (may differ from JWT user_id for admin)
                actual_user_id = device_info.get('user_id', user_id)
                devices_table.update_item(
                    Key={'user_id': actual_user_id, 'device_id': device_id},
                    UpdateExpression='SET #tz = :tz',
                    ExpressionAttributeNames={'#tz': 'timezone'},
                    ExpressionAttributeValues={':tz': new_tz}
                )

                # Send MQTT command to ESP32 to update timezone
                return send_command_with_params(device_id, user_id, 'set_timezone', {'timezone': new_tz}, 'Timezone saved')

            # NOTE: Removed duplicate /schedules endpoint - schedules are returned later in code
            # Schedules are stored on ESP32, not in DynamoDB

            if len(parts) == 5 and parts[3] == 'battery' and parts[4] == 'history':
                return get_battery_history(device_id, user_id)

            # Battery status (for home.html Cloud mode)
            if len(parts) == 5 and parts[3] == 'battery' and parts[4] == 'status' and http_method == 'GET':
                return get_battery_status(device_id, user_id)

            # Pump status (for calibration.html)
            if len(parts) == 5 and parts[3] == 'pump' and parts[4] == 'status' and http_method == 'GET':
                # Get pump calibration from device info
                device_info = get_device_info(device_id, user_id)
                pump_calib = device_info.get('pump_calibration', {})
                ml_per_sec = float(pump_calib.get('ml_per_sec', 2.5)) if pump_calib else 2.5
                calibrated = pump_calib.get('calibrated', False) if pump_calib else False

                return {
                    'statusCode': 200,
                    'headers': cors_headers(),
                    'body': json.dumps({
                        'running': False,  # Can't know real-time pump state
                        'remaining_sec': 0,
                        'ml_per_sec': ml_per_sec,
                        'calibrated': calibrated
                    })
                }

            # Pump control shortcuts
            if len(parts) == 4 and parts[3] == 'pump' and http_method == 'POST':
                # Parse query string for duration: ?sec=5
                query_params = event.get('queryStringParameters', {}) or {}
                duration = int(query_params.get('sec', 5))
                body = {'command': 'start_pump', 'params': {'duration': duration}}
                return send_device_command(device_id, user_id, body)

            if len(parts) == 5 and parts[3] == 'pump' and parts[4] == 'stop' and http_method == 'POST':
                body = {'command': 'stop_pump', 'params': {}}
                return send_device_command(device_id, user_id, body)

            # OTA Update - get presigned upload URL
            if len(parts) == 5 and parts[3] == 'ota' and parts[4] == 'upload-url' and http_method == 'GET':
                return get_ota_upload_url(device_id, user_id)

            # OTA Update trigger
            if len(parts) == 4 and parts[3] == 'ota' and http_method == 'POST':
                body_data = json.loads(event.get('body', '{}'))
                return trigger_ota_update(device_id, user_id, body_data)

            # Schedules endpoint for timer controller
            # Config is synced from ESP32 to DynamoDB via MQTT
            if len(parts) == 4 and parts[3] == 'schedules' and http_method == 'GET':
                # Read config_timer from devices table
                try:
                    scan_response = devices_table.scan(
                        FilterExpression='device_id = :device',
                        ExpressionAttributeValues={':device': device_id}
                    )
                    if scan_response['Items'] and len(scan_response['Items']) > 0:
                        device = scan_response['Items'][0]
                        schedules = device.get('config_timer', [])
                        updated = device.get('config_timer_updated', 0)
                        return {
                            'statusCode': 200,
                            'headers': cors_headers(),
                            'body': json.dumps({
                                'schedules': schedules,
                                'config_updated': updated,
                                'source': 'cloud_sync'
                            }, cls=DecimalEncoder)
                        }
                    else:
                        return {
                            'statusCode': 200,
                            'headers': cors_headers(),
                            'body': json.dumps({
                                'schedules': [],
                                'message': 'Device not found or no config synced yet'
                            })
                        }
                except Exception as e:
                    print(f"Error reading config_timer: {e}")
                    return {
                        'statusCode': 500,
                        'headers': cors_headers(),
                        'body': json.dumps({'error': str(e)})
                    }

            # Set operating mode (manual, timer, sensor)
            if len(parts) == 4 and parts[3] == 'mode' and http_method == 'POST':
                body_data = json.loads(event.get('body', '{}'))
                return set_device_mode(device_id, user_id, body_data)

            # Update device info (name, location, room) - sends MQTT command to ESP32
            if len(parts) == 4 and parts[3] == 'info' and http_method == 'POST':
                body_data = json.loads(event.get('body', '{}'))
                return update_device_info_mqtt(device_id, user_id, body_data)

            # Activity log (commands + telemetry combined)
            if len(parts) == 4 and parts[3] == 'activity' and http_method == 'GET':
                return get_device_activity(device_id, user_id)

            # ESP32 real-time logs from RAM buffer
            if len(parts) == 4 and parts[3] == 'logs' and http_method == 'GET':
                return get_device_logs(device_id, user_id)

            # Update device info (name, location, room) - from Settings page
            if len(parts) == 4 and parts[3] == 'info' and http_method == 'POST':
                body_data = json.loads(event.get('body', '{}'))
                return update_device_info(device_id, user_id, body_data)

            # GET /device/{id}/telemetry/config - Get telemetry config (admin only)
            if len(parts) == 5 and parts[3] == 'telemetry' and parts[4] == 'config' and http_method == 'GET':
                return get_telemetry_config(device_id, user_id)

    return {
        'statusCode': 404,
        'headers': cors_headers(),
        'body': json.dumps({'error': 'Not found'})
    }


def get_devices(user_id):
    """GET /devices - List all user's devices with latest telemetry"""

    # Admin users see ALL devices (for fleet management)
    ADMIN_EMAILS = ['mrmaximshurigin@gmail.com', 'admin']

    if user_id in ADMIN_EMAILS:
        # Admin: scan ALL devices
        response = devices_table.scan()
    else:
        # Regular user: only their devices
        response = devices_table.query(
            KeyConditionExpression=Key('user_id').eq(user_id)
        )

    devices = []
    for item in response.get('Items', []):
        device_id = item['device_id']

        # Get latest telemetry (sensor, battery, system)
        latest = get_latest_telemetry(device_id)

        # Merge device metadata + telemetry
        # Migration: "off" → "manual" (backward compatibility with old firmware)
        mode = latest.get('system', {}).get('mode', 'manual')
        if mode == 'off':
            mode = 'manual'

        # Controller is enabled based on state from device telemetry
        # state = DISABLED means controller is OFF
        # state = LAUNCH/STANDBY/ACTIVE/etc means controller is ON
        device_state = latest.get('system', {}).get('state', 'DISABLED')
        controller_enabled = device_state != 'DISABLED'

        # Device info: prefer telemetry (ESP32 source of truth), fallback to DynamoDB
        system_data = latest.get('system', {})
        device_name = system_data.get('device_name') or item.get('device_name') or device_id
        device_location = system_data.get('location') or item.get('location') or '—'
        device_room = system_data.get('room') or item.get('room') or '—'

        # Battery: distinguish "no data" from "AC power (percent=null)"
        battery_data = latest.get('battery')
        battery_pct = battery_data.get('percent') if battery_data else None
        battery_charging = battery_data.get('charging', False) if battery_data else False
        battery_no_data = battery_data is None

        device_data = {
            'device_id': device_id,
            'name': device_name,
            'location': device_location,
            'room': device_room,
            'moisture_pct': latest.get('sensor', {}).get('moisture_percent'),
            'adc_raw': latest.get('sensor', {}).get('adc_raw'),
            'battery_pct': battery_pct,
            'battery_charging': battery_charging,
            'battery_no_data': battery_no_data,  # True = no telemetry yet
            'mode': mode,
            'controller_enabled': controller_enabled,  # True if state != DISABLED (from telemetry)
            'state': latest.get('system', {}).get('state', 'UNKNOWN'),
            'firmware_version': latest.get('system', {}).get('firmware_version', 'v1.0.0'),
            'reboot_count': latest.get('system', {}).get('reboot_count'),
            'uptime': format_uptime(latest.get('system', {}).get('uptime_ms')),
            'last_watering': item.get('last_watering_timestamp'),
            'last_update': latest.get('last_update'),
            'online': is_device_online(latest.get('last_update')),
            'warnings': generate_warnings(latest)
        }

        devices.append(device_data)

    return {
        'statusCode': 200,
        'headers': cors_headers(),
        'body': json.dumps(devices, cls=DecimalEncoder)
    }


def get_device_status(device_id, user_id):
    """GET /device/{id}/status - Get full device status"""

    # Verify user owns this device
    if not verify_device_access(device_id, user_id):
        return {'statusCode': 403, 'headers': cors_headers(),
                'body': json.dumps({'error': 'Access denied'})}

    # Get device metadata (uses admin-aware get_device_info)
    device_meta = get_device_info(device_id, user_id)

    # Get latest telemetry
    latest = get_latest_telemetry(device_id)

    # Migration: "off" → "manual" (backward compatibility)
    mode = latest.get('system', {}).get('mode', 'manual')
    if mode == 'off':
        mode = 'manual'

    # Determine pump_running from latest pump telemetry
    # ESP32 publishes pump telemetry with action:"start" when pump starts
    # and action:"stop" when pump stops. Check if last action was "start"
    # and if it's recent enough (within expected duration)
    pump_data = latest.get('pump', {})
    pump_running = False
    pump_elapsed_ms = 0
    pump_remaining_ms = 0

    if pump_data.get('action') == 'start':
        # Check if pump start was recent (within reasonable time)
        pump_timestamp = pump_data.get('timestamp', 0)
        duration_sec = pump_data.get('duration_sec', 0)
        elapsed_sec = int(time.time()) - pump_timestamp if pump_timestamp else 0

        if elapsed_sec < duration_sec + 5:  # Add 5 sec buffer for timing
            pump_running = True
            pump_elapsed_ms = elapsed_sec * 1000
            pump_remaining_ms = max(0, (duration_sec - elapsed_sec) * 1000)

    # Device info: prefer telemetry (ESP32 source of truth), fallback to DynamoDB
    system_data = latest.get('system', {})
    device_name = system_data.get('device_name') or device_meta.get('device_name') or device_id
    device_location = system_data.get('location') or device_meta.get('location') or '—'
    device_room = system_data.get('room') or device_meta.get('room') or '—'

    # Format response matching ESP32 /api/status structure
    status = {
        'adc': latest.get('sensor', {}).get('adc_raw'),
        'percent': latest.get('sensor', {}).get('moisture_percent'),
        'system_state': {
            'device_name': device_name,
            'location': device_location,
            'room': device_room,
            'mode': mode,
            'state': latest.get('system', {}).get('state', 'STANDBY')
        },
        'battery': latest.get('battery', {}),
        'last_watering': latest.get('last_watering'),
        'pump_running': pump_running,
        'pump_elapsed_ms': pump_elapsed_ms,
        'pump_remaining_ms': pump_remaining_ms,
        'timestamp': latest.get('last_update'),
        'online': is_device_online(latest.get('last_update'))  # Add online status
    }

    return {
        'statusCode': 200,
        'headers': cors_headers(),
        'body': json.dumps(status, cls=DecimalEncoder)
    }


def send_device_command(device_id, user_id, body):
    """POST /device/{id}/command - Send MQTT command to device"""

    # Verify access
    if not verify_device_access(device_id, user_id):
        return {'statusCode': 403, 'headers': cors_headers(),
                'body': json.dumps({'error': 'Access denied'})}

    # Extract command
    command = body.get('command')
    params = body.get('params', {})

    if not command:
        return {'statusCode': 400, 'headers': cors_headers(),
                'body': json.dumps({'error': 'Missing command'})}

    # Generate command ID
    command_id = str(uuid.uuid4())

    # Sanitize params for DynamoDB (convert floats to Decimal)
    def sanitize_for_dynamodb(obj):
        if isinstance(obj, float):
            return Decimal(str(obj))
        elif isinstance(obj, dict):
            return {k: sanitize_for_dynamodb(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [sanitize_for_dynamodb(v) for v in obj]
        return obj

    safe_params = sanitize_for_dynamodb(params)

    # Store command in DynamoDB
    try:
        commands_table.put_item(
            Item={
                'device_id': device_id,
                'command_id': command_id,
                'command': command,
                'params': safe_params,
                'status': 'pending',
                'created_at': int(time.time()),
                'ttl': int(time.time()) + 604800  # 7 days TTL
            }
        )
    except Exception as e:
        print(f"[ERROR] DynamoDB put_item failed: {e}")
        return {'statusCode': 500, 'headers': cors_headers(),
                'body': json.dumps({'error': f'Database error: {str(e)}'})}


    # Publish MQTT command
    mqtt_payload = {
        'command_id': command_id,
        'command': command,
        'params': params
    }

    # Topic format: {device_id}/command (device_id already contains "Polivalka-" prefix)
    # ESP32 subscribes to: Polivalka/BB00C1/command
    # So we need to extract MAC address from device_id and use it
    # device_id format: "Polivalka-BB00C1" → use "Polivalka/BB00C1/command"
    mac_address = device_id.replace('Polivalka-', '')
    topic = f'Polivalka/{mac_address}/command'

    try:
        iot_client.publish(
            topic=topic,
            qos=1,
            payload=json.dumps(mqtt_payload)
        )

        return {
            'statusCode': 200,
            'headers': cors_headers(),
            'body': json.dumps({
                'command_id': command_id,
                'status': 'sent',
                'message': f'Command sent to device {device_id}'
            })
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': cors_headers(),
            'body': json.dumps({'error': str(e)})
        }


def send_controller_command(device_id, user_id, command, success_message):
    """Send controller enable/disable/cancel command via MQTT and return AP-compatible response.

    Unlike send_device_command(), this returns {success: true} immediately,
    matching the response format that AP (ESP32 HTTP API) returns.
    The ESP32 will process the command and update telemetry.
    """

    # Verify access
    if not verify_device_access(device_id, user_id):
        return {'statusCode': 403, 'headers': cors_headers(),
                'body': json.dumps({'error': 'Access denied'})}

    # Generate command ID
    command_id = str(uuid.uuid4())

    # Store command in DynamoDB
    commands_table.put_item(
        Item={
            'device_id': device_id,
            'command_id': command_id,
            'command': command,
            'params': {},
            'status': 'pending',
            'created_at': int(time.time()),
            'ttl': int(time.time()) + 604800  # 7 days TTL
        }
    )

    # Publish MQTT command
    mqtt_payload = {
        'command_id': command_id,
        'command': command,
        'params': {}
    }

    # Extract MAC address from device_id
    mac_address = device_id.replace('Polivalka-', '')
    topic = f'Polivalka/{mac_address}/command'

    try:
        iot_client.publish(
            topic=topic,
            qos=1,
            payload=json.dumps(mqtt_payload)
        )

        # Return AP-compatible format: {success: true, message: "..."}
        return {
            'statusCode': 200,
            'headers': cors_headers(),
            'body': json.dumps({
                'success': True,
                'message': success_message
            })
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': cors_headers(),
            'body': json.dumps({'success': False, 'error': str(e)})
        }


def send_command_with_params(device_id, user_id, command, params, success_message):
    """Send command with parameters via MQTT and return AP-compatible response.

    Similar to send_controller_command() but accepts params dict.
    Used for schedule_set, schedule_delete, etc.
    """

    # Verify access
    if not verify_device_access(device_id, user_id):
        return {'statusCode': 403, 'headers': cors_headers(),
                'body': json.dumps({'error': 'Access denied'})}

    # Generate command ID
    command_id = str(uuid.uuid4())

    # Store command in DynamoDB
    commands_table.put_item(
        Item={
            'device_id': device_id,
            'command_id': command_id,
            'command': command,
            'params': params,
            'status': 'pending',
            'created_at': int(time.time()),
            'ttl': int(time.time()) + 604800  # 7 days TTL
        }
    )

    # Publish MQTT command
    mqtt_payload = {
        'command_id': command_id,
        'command': command,
        'params': params
    }

    # Extract MAC address from device_id
    mac_address = device_id.replace('Polivalka-', '')
    topic = f'Polivalka/{mac_address}/command'

    try:
        iot_client.publish(
            topic=topic,
            qos=1,
            payload=json.dumps(mqtt_payload)
        )

        # Return AP-compatible format: {success: true, message: "..."}
        return {
            'statusCode': 200,
            'headers': cors_headers(),
            'body': json.dumps({
                'success': True,
                'message': success_message
            })
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': cors_headers(),
            'body': json.dumps({'success': False, 'error': str(e)})
        }


def update_device_info_mqtt(device_id, user_id, body):
    """POST /device/{id}/info - Update device info (name, location, room) via MQTT command.

    Sends MQTT command to ESP32 which saves to NVS and publishes updated system telemetry.
    ESP32 is the source of truth - this ensures Cloud and Local settings are synced.
    """

    # Verify access
    if not verify_device_access(device_id, user_id):
        return {'statusCode': 403, 'headers': cors_headers(),
                'body': json.dumps({'error': 'Access denied'})}

    # Extract device info from body
    device_name = body.get('name', '').strip()
    location = body.get('location', '').strip()
    room = body.get('room', '').strip()

    # Validate - at least one field must be provided
    if not device_name and not location and not room:
        return {'statusCode': 400, 'headers': cors_headers(),
                'body': json.dumps({'error': 'No fields to update'})}

    # Generate command ID
    command_id = str(uuid.uuid4())

    # Build params - only include non-empty fields
    params = {}
    if device_name:
        params['name'] = device_name
    if location:
        params['location'] = location
    if room:
        params['room'] = room

    # MQTT command payload
    mqtt_payload = {
        'command_id': command_id,
        'command': 'update_device_info',
        'params': params
    }

    # Extract MAC address from device_id
    mac_address = device_id.replace('Polivalka-', '')
    topic = f'Polivalka/{mac_address}/command'

    try:
        iot_client.publish(
            topic=topic,
            qos=1,
            payload=json.dumps(mqtt_payload)
        )

        # Return AP-compatible format
        return {
            'statusCode': 200,
            'headers': cors_headers(),
            'body': json.dumps({
                'success': True,
                'message': 'Device info update sent',
                'updated': params
            })
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': cors_headers(),
            'body': json.dumps({'success': False, 'error': str(e)})
        }


def set_device_mode(device_id, user_id, body):
    """POST /device/{id}/mode - Set operating mode (manual, timer, sensor)"""

    # Verify access
    if not verify_device_access(device_id, user_id):
        return {'statusCode': 403, 'headers': cors_headers(),
                'body': json.dumps({'error': 'Access denied'})}

    # Extract mode
    mode = body.get('mode')

    # Validate mode
    valid_modes = ['manual', 'timer', 'sensor']
    if not mode:
        return {'statusCode': 400, 'headers': cors_headers(),
                'body': json.dumps({'error': 'Missing mode parameter'})}

    if mode not in valid_modes:
        return {'statusCode': 400, 'headers': cors_headers(),
                'body': json.dumps({'error': f'Invalid mode: {mode} (expected: manual, timer, sensor)'})}

    # Generate command ID
    command_id = str(uuid.uuid4())

    # Store command in DynamoDB
    commands_table.put_item(
        Item={
            'device_id': device_id,
            'command_id': command_id,
            'command': 'set_mode',
            'params': {'mode': mode},
            'status': 'pending',
            'created_at': int(time.time()),
            'ttl': int(time.time()) + 604800  # 7 days TTL
        }
    )

    # Publish MQTT command
    mqtt_payload = {
        'command_id': command_id,
        'command': 'set_mode',
        'params': {'mode': mode}
    }

    # Extract MAC address from device_id
    mac_address = device_id.replace('Polivalka-', '')
    topic = f'Polivalka/{mac_address}/command'

    try:
        iot_client.publish(
            topic=topic,
            qos=1,
            payload=json.dumps(mqtt_payload)
        )

        return {
            'statusCode': 200,
            'headers': cors_headers(),
            'body': json.dumps({
                'command_id': command_id,
                'status': 'sent',
                'mode': mode,
                'message': f'Mode changed to {mode}'
            })
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': cors_headers(),
            'body': json.dumps({'error': str(e)})
        }


def get_sensor_history(device_id, user_id, days=7):
    """GET /device/{id}/sensor/history - Get sensor data history"""

    if not verify_device_access(device_id, user_id):
        return {'statusCode': 403, 'headers': cors_headers(),
                'body': json.dumps({'error': 'Access denied'})}

    # Query telemetry table for sensor data (last 7 days)
    cutoff = int(time.time()) - (days * 86400)

    response = telemetry_table.query(
        KeyConditionExpression=Key('device_id').eq(device_id) &
                               Key('timestamp').gt(cutoff),
        ScanIndexForward=False,  # Descending (newest first)
        Limit=1000  # Max 1000 points
    )

    # Extract sensor data points
    history = []
    for item in response.get('Items', []):
        if 'sensor' in item:
            timestamp = int(item.get('timestamp', 0))
            sensor_data = item['sensor']
            history.append({
                'timestamp': timestamp,
                'moisture_percent': sensor_data.get('moisture_percent'),
                'adc_raw': sensor_data.get('adc_raw')
            })

    return {
        'statusCode': 200,
        'headers': cors_headers(),
        'body': json.dumps(history, cls=DecimalEncoder)
    }


def get_battery_status(device_id, user_id):
    """GET /device/{id}/battery/status - Get latest battery data

    Returns same format as ESP32 /api/battery/status:
    - available: true/false (whether battery data exists)
    - voltage, percent, charging (actual values)

    When no battery telemetry exists, returns available:false
    to distinguish from "AC power" (which has percent:null)
    """

    if not verify_device_access(device_id, user_id):
        return {'statusCode': 403, 'headers': cors_headers(),
                'body': json.dumps({'error': 'Access denied'})}

    latest = get_latest_telemetry(device_id)
    battery = latest.get('battery')

    # No battery telemetry at all - return available:false
    if battery is None:
        return {
            'statusCode': 200,
            'headers': cors_headers(),
            'body': json.dumps({
                'available': False,
                'voltage': None,
                'percent': None,
                'charging': False,
                'no_data': True  # Flag to distinguish from AC power
            })
        }

    # Battery telemetry exists - return actual data
    return {
        'statusCode': 200,
        'headers': cors_headers(),
        'body': json.dumps({
            'available': battery.get('percent') is not None,
            'voltage': battery.get('voltage'),
            'percent': battery.get('percent'),
            'charging': battery.get('charging', False)
        }, cls=DecimalEncoder)
    }


def get_battery_history(device_id, user_id, days=7):
    """GET /device/{id}/battery/history - Get battery data history"""

    if not verify_device_access(device_id, user_id):
        return {'statusCode': 403, 'headers': cors_headers(),
                'body': json.dumps({'error': 'Access denied'})}

    cutoff = int(time.time()) - (days * 86400)

    response = telemetry_table.query(
        KeyConditionExpression=Key('device_id').eq(device_id) &
                               Key('timestamp').gt(cutoff),
        ScanIndexForward=False,
        Limit=1000
    )

    history = []
    for item in response.get('Items', []):
        if 'battery' in item:
            timestamp = int(item.get('timestamp', 0))
            battery_data = item['battery']
            history.append({
                'timestamp': timestamp,
                'voltage': battery_data.get('voltage'),
                'percent': battery_data.get('percent'),
                'charging': battery_data.get('charging')
            })

    return {
        'statusCode': 200,
        'headers': cors_headers(),
        'body': json.dumps(history, cls=DecimalEncoder)
    }


# === Helper Functions ===

def get_latest_telemetry(device_id):
    """Get latest sensor, battery, system data for device"""

    latest = {}

    # Query recent records (schema: device_id + timestamp)
    # Data types stored as top-level Maps: system, pump, sensor, battery
    cutoff = int(time.time()) - 86400  # Last 24 hours

    response = telemetry_table.query(
        KeyConditionExpression=Key('device_id').eq(device_id) &
                               Key('timestamp').gt(cutoff),
        ScanIndexForward=False,  # Newest first
        Limit=100  # Get recent records to find latest of each type
    )

    # Extract latest of each data type
    for item in response.get('Items', []):
        timestamp = int(item.get('timestamp', 0))

        # Check each data type and keep the latest
        for data_type in ['sensor', 'battery', 'system', 'pump']:
            if data_type in item and data_type not in latest:
                data = dict(item[data_type])  # Copy to avoid mutation
                data['timestamp'] = timestamp  # Add record timestamp to data
                latest[data_type] = data
                if 'last_update' not in latest or timestamp > latest['last_update']:
                    latest['last_update'] = timestamp

    return latest


def verify_device_access(device_id, user_id):
    """Check if user owns this device (admins have access to all devices)"""

    # Admin has access to ALL devices
    ADMIN_EMAILS = ['mrmaximshurigin@gmail.com', 'admin']
    if user_id in ADMIN_EMAILS:
        return True

    # Regular user: check ownership
    response = devices_table.get_item(
        Key={'user_id': user_id, 'device_id': device_id}
    )

    return 'Item' in response


def get_device_info(device_id, user_id):
    """Get device info from devices_table.

    For admin users: scans by device_id only (admin sees all devices)
    For regular users: queries by user_id + device_id (only own devices)
    """
    ADMIN_EMAILS = ['mrmaximshurigin@gmail.com', 'admin']

    if user_id in ADMIN_EMAILS:
        # Admin: scan by device_id only (device may have any user_id in DB)
        response = devices_table.scan(
            FilterExpression='device_id = :device',
            ExpressionAttributeValues={':device': device_id}
        )
        items = response.get('Items', [])
        return items[0] if items else {}
    else:
        # Regular user: query by user_id + device_id
        response = devices_table.get_item(
            Key={'user_id': user_id, 'device_id': device_id}
        )
        return response.get('Item', {})


def parse_timezone_offset(tz_string):
    """Parse POSIX timezone string and return offset in minutes from UTC.

    Examples:
    - CET-1CEST,M3.5.0,M10.5.0/3 → 60 (CET = UTC+1)
    - MSK-3 → 180 (Moscow = UTC+3)
    - EST5EDT → -300 (Eastern US = UTC-5)

    Note: This is simplified - doesn't handle DST transitions.
    For full accuracy, would need to check current date against DST rules.
    """
    import re

    if not tz_string:
        return 0

    # Extract first timezone offset: NAME[-+]OFFSET or NAME[+-]OFFSET
    # POSIX format: CET-1 means CET is UTC+1 (sign is inverted!)
    match = re.match(r'^[A-Z]+([+-]?\d+)', tz_string)
    if match:
        # POSIX inverts the sign: CET-1 means UTC+1
        offset_hours = -int(match.group(1))
        return offset_hours * 60

    return 0  # Default to UTC


def format_uptime(uptime_ms):
    """Convert uptime_ms to human-readable format"""
    if not uptime_ms or uptime_ms < 0:
        return 'N/A'

    seconds = uptime_ms / 1000

    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    elif seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.1f}h"
    else:
        days = int(seconds / 86400)
        hours = int((seconds % 86400) / 3600)
        if hours > 0:
            return f"{days}d {hours}h"
        return f"{days}d"


def is_device_online(last_update_timestamp):
    """Check if device is online (updated within last 45 minutes)

    PRODUCTION telemetry intervals (app_main.c):
    - Sensor: 60 min (3600000ms)
    - Battery: 60 min (3600000ms)
    - System: 30 min (1800000ms) - heartbeat

    Online threshold = 45 min (1.5x system heartbeat) to account for delays
    """

    if not last_update_timestamp:
        return False

    return (int(time.time()) - last_update_timestamp) < 2700  # 45 min (1.5x 30 min heartbeat)


def generate_warnings(telemetry):
    """Generate warning messages based on telemetry"""

    warnings = []

    battery = telemetry.get('battery', {})
    sensor = telemetry.get('sensor', {})

    # Battery warnings
    battery_pct = battery.get('percent')
    if battery_pct is not None and battery_pct <= 10:
        warnings.append('Low battery (10%)')

    # Moisture warnings
    moisture = sensor.get('moisture_percent')
    if moisture is not None and moisture < 20:
        warnings.append(f'Moisture too low ({moisture}%)')

    return warnings


def cors_headers():
    """CORS headers for API Gateway"""
    return {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type,Authorization',
        'Access-Control-Allow-Methods': 'GET,POST,OPTIONS'
    }


def get_command_result(device_id, user_id, command_id):
    """GET /device/{id}/command/{command_id} - Get command result"""

    if not verify_device_access(device_id, user_id):
        return {'statusCode': 403, 'headers': cors_headers(),
                'body': json.dumps({'error': 'Access denied'})}

    # Query command from DynamoDB
    response = commands_table.get_item(
        Key={'device_id': device_id, 'command_id': command_id}
    )

    if 'Item' not in response:
        return {'statusCode': 404, 'headers': cors_headers(),
                'body': json.dumps({'error': 'Command not found'})}

    item = response['Item']

    return {
        'statusCode': 200,
        'headers': cors_headers(),
        'body': json.dumps({
            'command_id': command_id,
            'command': item.get('command'),
            'status': item.get('status', 'pending'),
            'result': item.get('result'),
            'created_at': item.get('created_at'),
            'completed_at': item.get('completed_at')
        }, cls=DecimalEncoder)
    }


def get_sensor_realtime(device_id, user_id):
    """GET /device/{id}/sensor - Get real-time device status (sensor, mode, battery, pump)"""

    if not verify_device_access(device_id, user_id):
        return {'statusCode': 403, 'headers': cors_headers(),
                'body': json.dumps({'error': 'Access denied'})}

    # Send get_status command (returns sensor + mode + battery + pump)
    command_id = str(uuid.uuid4())
    commands_table.put_item(
        Item={
            'device_id': device_id,
            'command_id': command_id,
            'command': 'get_status',
            'params': {},
            'status': 'pending',
            'created_at': int(time.time()),
            'ttl': int(time.time()) + 604800  # 7 days TTL
        }
    )

    # Publish MQTT command
    mqtt_payload = {
        'command_id': command_id,
        'command': 'get_status',
        'params': {}
    }

    mac_address = device_id.replace('Polivalka-', '')
    topic = f'Polivalka/{mac_address}/command'

    try:
        iot_client.publish(
            topic=topic,
            qos=1,
            payload=json.dumps(mqtt_payload)
        )
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': cors_headers(),
            'body': json.dumps({'error': f'MQTT publish failed: {str(e)}'})
        }

    # Wait for response (polling for up to 10 seconds)
    max_attempts = 20  # 20 * 500ms = 10 seconds
    for attempt in range(max_attempts):
        time.sleep(0.5)

        response = commands_table.get_item(
            Key={'device_id': device_id, 'command_id': command_id}
        )

        if 'Item' in response:
            item = response['Item']
            status = item.get('status')

            # Check if command completed (success or error)
            if status in ['success', 'error', 'completed']:
                # Parse result data (get_status returns: sensor, battery, pump, system)
                result = item.get('result', {})
                if isinstance(result, str):
                    try:
                        result = json.loads(result)
                    except:
                        pass

                # Extract nested data structures
                sensor = result.get('sensor', {})
                battery = result.get('battery', {})
                pump = result.get('pump', {})
                system = result.get('system', {})

                return {
                    'statusCode': 200,
                    'headers': cors_headers(),
                    'body': json.dumps({
                        'moisture_pct': sensor.get('moisture'),
                        'adc_raw': sensor.get('adc'),
                        'battery': battery,
                        'pump_running': pump.get('running', False),
                        'mode': system.get('mode', 'manual'),
                        'timestamp': item.get('completed_at', int(time.time()))
                    }, cls=DecimalEncoder)
                }

    # Timeout - device didn't respond
    return {
        'statusCode': 408,
        'headers': cors_headers(),
        'body': json.dumps({
            'error': 'Device did not respond',
            'command_id': command_id,
            'hint': 'Device may be offline or sleeping'
        })
    }


def get_ota_upload_url(device_id, user_id):
    """GET /device/{id}/ota/upload-url - Get presigned URL for firmware upload"""

    if not verify_device_access(device_id, user_id):
        return {'statusCode': 403, 'headers': cors_headers(),
                'body': json.dumps({'error': 'Access denied'})}

    # Generate unique firmware filename
    timestamp = int(time.time())
    filename = f"firmware/devices/{device_id}/{timestamp}.bin"

    try:
        # Generate presigned URL (valid for 10 minutes)
        presigned_url = s3_client.generate_presigned_url(
            'put_object',
            Params={
                'Bucket': FIRMWARE_BUCKET,
                'Key': filename,
                'ContentType': 'application/octet-stream'
            },
            ExpiresIn=600  # 10 minutes
        )

        # Public download URL for the firmware (after upload)
        download_url = f"https://{FIRMWARE_BUCKET}.s3.eu-central-1.amazonaws.com/{filename}"

        return {
            'statusCode': 200,
            'headers': cors_headers(),
            'body': json.dumps({
                'upload_url': presigned_url,
                'download_url': download_url,
                'filename': filename,
                'expires_in': 600
            })
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': cors_headers(),
            'body': json.dumps({'error': f'Failed to generate upload URL: {str(e)}'})
        }


def trigger_ota_update(device_id, user_id, body):
    """POST /device/{id}/ota - Trigger OTA update"""

    if not verify_device_access(device_id, user_id):
        return {'statusCode': 403, 'headers': cors_headers(),
                'body': json.dumps({'error': 'Access denied'})}

    # Extract firmware URL and version
    firmware_url = body.get('url')
    version = body.get('version', 'unknown')

    if not firmware_url:
        return {'statusCode': 400, 'headers': cors_headers(),
                'body': json.dumps({'error': 'Missing firmware URL'})}

    # Send OTA command via MQTT
    command_id = str(uuid.uuid4())
    mqtt_payload = {
        'command_id': command_id,
        'command': 'ota_update',
        'url': firmware_url,
        'version': version
    }

    # Store command in DynamoDB
    commands_table.put_item(
        Item={
            'device_id': device_id,
            'command_id': command_id,
            'command': 'ota_update',
            'params': {'url': firmware_url, 'version': version},
            'status': 'pending',
            'created_at': int(time.time()),
            'ttl': int(time.time()) + 604800  # 7 days TTL
        }
    )

    # Publish MQTT command
    mac_address = device_id.replace('Polivalka-', '')
    topic = f'Polivalka/{mac_address}/command'

    try:
        iot_client.publish(
            topic=topic,
            qos=1,
            payload=json.dumps(mqtt_payload)
        )

        return {
            'statusCode': 200,
            'headers': cors_headers(),
            'body': json.dumps({
                'command_id': command_id,
                'status': 'sent',
                'message': f'OTA update triggered for {device_id}',
                'version': version
            })
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': cors_headers(),
            'body': json.dumps({'error': f'Failed to trigger OTA: {str(e)}'})
        }


def get_device_activity(device_id, user_id):
    """GET /device/{id}/activity - Get command history + telemetry for activity log"""

    # Verify access
    if not verify_device_access(device_id, user_id):
        return {
            'statusCode': 403,
            'headers': cors_headers(),
            'body': json.dumps({'error': 'Access denied'})
        }

    try:
        activity_items = []

        # 1. Get commands (last 50)
        cmd_response = commands_table.query(
            KeyConditionExpression=Key('device_id').eq(device_id),
            Limit=50,
            ScanIndexForward=False  # Sort DESC by command_id (timestamp-based)
        )

        for cmd in cmd_response.get('Items', []):
            activity_items.append({
                'timestamp': cmd.get('created_at', 0),
                'type': 'COMMAND',
                'level': 'ERROR' if cmd.get('status') == 'error' else 'INFO',
                'component': 'AWS_IOT',
                'command': cmd.get('command'),
                'status': cmd.get('status', 'pending'),
                'message': cmd.get('message', ''),
                'params': cmd.get('params', {}),
                'result': cmd.get('result', {})
            })

        # 2. Get telemetry (last 50 system events)
        # Query recent telemetry and filter for system events
        cutoff = int(time.time()) - 86400  # Last 24 hours
        telem_response = telemetry_table.query(
            KeyConditionExpression=Key('device_id').eq(device_id) & Key('timestamp').gt(cutoff),
            Limit=100,  # Get more to filter for system events
            ScanIndexForward=False  # Sort DESC
        )

        # Process all telemetry events (system, pump, sensor, battery)
        event_count = 0
        prev_firmware_version = None

        for telem in telem_response.get('Items', []):
            event_count += 1
            if event_count > 100:  # Limit to 100 events total
                break

            ts = int(telem.get('timestamp', 0))
            system_data = telem.get('system', {})

            # Detect OTA update (firmware version change)
            # Note: Iterating DESC (newest first), so prev = newer, curr = older
            curr_firmware_version = system_data.get('firmware_version')
            if prev_firmware_version and curr_firmware_version:
                if curr_firmware_version != prev_firmware_version:
                    # Firmware version changed - OTA update occurred
                    # Upgrade: curr (old) → prev (new)
                    activity_items.append({
                        'timestamp': ts,
                        'type': 'OTA',
                        'level': 'INFO',
                        'component': 'OTA_UPDATE',
                        'message': f"🔄 OTA Update completed: {curr_firmware_version} → {prev_firmware_version}",
                        'old_version': curr_firmware_version,
                        'new_version': prev_firmware_version
                    })

            prev_firmware_version = curr_firmware_version

            # Parse system events
            if 'system' in telem:
                system_data = telem.get('system', {})
                # Migration: "off" → "manual" (backward compatibility)
                mode = system_data.get('mode', 'manual')
                if mode == 'off':
                    mode = 'manual'
                boot_type = system_data.get('boot_type')
                reset_reason = system_data.get('reset_reason')
                reboot_count = system_data.get('reboot_count')

                # Check for reboot events (only on FIRST system heartbeat after reboot)
                if boot_type == 'OTA_BOOT':
                    # OTA Update reboot
                    activity_items.append({
                        'timestamp': ts,
                        'type': 'OTA',
                        'level': 'INFO',
                        'component': 'OTA_UPDATE',
                        'message': f"🔄 OTA Update completed (reboot #{reboot_count})",
                        'reset_reason': reset_reason
                    })
                    # Don't show normal heartbeat for boot events
                    continue

                elif boot_type == 'CRASH_BOOT':
                    # Watchdog/panic crash reboot
                    activity_items.append({
                        'timestamp': ts,
                        'type': 'REBOOT',
                        'level': 'WARNING',
                        'component': 'SYSTEM',
                        'message': f"⚠️ Device crashed: {reset_reason} reset (reboot #{reboot_count})",
                        'reset_reason': reset_reason
                    })
                    # Don't show normal heartbeat for boot events
                    continue

                elif boot_type == 'SYSTEM_BOOT' and reset_reason:
                    # Normal reboot (power loss, manual restart, etc)
                    if reset_reason == 'POWERON':
                        msg = f"⚡ Power restored (reboot #{reboot_count})"
                    elif reset_reason == 'SW_RESTART':
                        msg = f"🔄 Manual restart (reboot #{reboot_count})"
                    elif reset_reason == 'BROWNOUT':
                        msg = f"⚠️ Low voltage restart (reboot #{reboot_count})"
                    else:
                        msg = f"🔄 Device rebooted: {reset_reason} (reboot #{reboot_count})"

                    activity_items.append({
                        'timestamp': ts,
                        'type': 'REBOOT',
                        'level': 'INFO',
                        'component': 'SYSTEM',
                        'message': msg,
                        'reset_reason': reset_reason
                    })
                    # Don't show normal heartbeat for boot events
                    continue

                # Normal system heartbeat (mode change, etc) - SKIP if boot event was shown
                activity_items.append({
                    'timestamp': ts,
                    'type': 'SYSTEM',
                    'level': 'INFO',
                    'component': 'SYSTEM',
                    'mode': mode,
                    'message': f"Mode: {mode}"
                })

            # Parse pump events
            if 'pump' in telem:
                pump_data = telem.get('pump', {})
                action = pump_data.get('action')
                duration = pump_data.get('duration_sec')
                volume = pump_data.get('volume_ml')

                if action == 'start':
                    activity_items.append({
                        'timestamp': ts,
                        'type': 'PUMP',
                        'level': 'INFO',
                        'component': 'PUMP',
                        'message': f"💧 Pump started ({duration}s, {volume}ml)"
                    })
                elif action == 'stop':
                    activity_items.append({
                        'timestamp': ts,
                        'type': 'PUMP',
                        'level': 'INFO',
                        'component': 'PUMP',
                        'message': f"🛑 Pump stopped ({duration}s, {volume}ml)"
                    })

            # Parse sensor events
            if 'sensor' in telem:
                sensor_data = telem.get('sensor', {})
                moisture = sensor_data.get('moisture_percent', 0)
                adc = sensor_data.get('adc_raw', 0)
                activity_items.append({
                    'timestamp': ts,
                    'type': 'SENSOR',
                    'level': 'INFO',
                    'component': 'SENSOR',
                    'message': f"💧 Moisture: {moisture}% (ADC: {adc})"
                })

            # Parse battery events
            if 'battery' in telem:
                battery_data = telem.get('battery', {})
                voltage = battery_data.get('voltage', 0)
                percent = battery_data.get('percent')
                charging = battery_data.get('charging', False)

                if percent is not None:
                    charge_icon = '⚡' if charging else ''
                    activity_items.append({
                        'timestamp': ts,
                        'type': 'BATTERY',
                        'level': 'INFO',
                        'component': 'BATTERY',
                        'message': f"🔋 Battery: {percent}% ({voltage}V) {charge_icon}"
                    })
                else:
                    activity_items.append({
                        'timestamp': ts,
                        'type': 'BATTERY',
                        'level': 'INFO',
                        'component': 'BATTERY',
                        'message': f"⚡ AC Power ({voltage}V)"
                    })

        # 3. Sort all by timestamp DESC
        activity_items.sort(key=lambda x: x['timestamp'], reverse=True)

        # 4. Limit to 100 most recent
        activity_items = activity_items[:100]

        return {
            'statusCode': 200,
            'headers': cors_headers(),
            'body': json.dumps({
                'device_id': device_id,
                'activity': activity_items
            }, cls=DecimalEncoder)
        }

    except Exception as e:
        print(f"Error getting activity: {str(e)}")
        return {
            'statusCode': 500,
            'headers': cors_headers(),
            'body': json.dumps({'error': f'Failed to get activity: {str(e)}'})
        }


def get_device_logs(device_id, user_id):
    """GET /device/{id}/logs - Get real-time ESP32 logs from RAM buffer"""

    if not verify_device_access(device_id, user_id):
        return {'statusCode': 403, 'headers': cors_headers(),
                'body': json.dumps({'error': 'Access denied'})}

    # Send get_logs command
    command_id = str(uuid.uuid4())

    # Store command in DynamoDB
    commands_table.put_item(
        Item={
            'device_id': device_id,
            'command_id': command_id,
            'command': 'get_logs',
            'params': {'limit': 50},  # Request last 50 logs
            'status': 'pending',
            'created_at': int(time.time()),
            'ttl': int(time.time()) + 604800  # 7 days TTL
        }
    )

    # Publish MQTT command
    mqtt_payload = {
        'command_id': command_id,
        'command': 'get_logs',
        'params': {'limit': 50}
    }

    mac_address = device_id.replace('Polivalka-', '')
    topic = f'Polivalka/{mac_address}/command'

    try:
        iot_client.publish(
            topic=topic,
            qos=1,
            payload=json.dumps(mqtt_payload)
        )
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': cors_headers(),
            'body': json.dumps({'error': f'MQTT publish failed: {str(e)}'})
        }

    # Wait for response (polling for up to 10 seconds)
    max_attempts = 20  # 20 * 500ms = 10 seconds
    for attempt in range(max_attempts):
        time.sleep(0.5)

        response = commands_table.get_item(
            Key={'device_id': device_id, 'command_id': command_id}
        )

        if 'Item' in response:
            item = response['Item']
            status = item.get('status')

            # Check if command completed
            if status in ['success', 'error', 'completed']:
                # Parse result data
                result = item.get('result', {})
                if isinstance(result, str):
                    try:
                        result = json.loads(result)
                    except:
                        pass

                # Extract logs array
                logs = result.get('logs', [])
                count = result.get('count', 0)
                uptime_ms = result.get('uptime_ms', 0)

                # Format logs for display
                formatted_logs = []
                for log in logs:
                    timestamp_ms = log.get('timestamp_ms', 0)
                    event = log.get('event', '')

                    # Format as ESP32 monitor style
                    # Convert ms to seconds for display
                    seconds = timestamp_ms / 1000
                    formatted_logs.append({
                        'timestamp_ms': timestamp_ms,
                        'timestamp_sec': seconds,
                        'event': event,
                        'formatted': f"[{seconds:8.3f}] {event}"
                    })

                return {
                    'statusCode': 200,
                    'headers': cors_headers(),
                    'body': json.dumps({
                        'device_id': device_id,
                        'count': count,
                        'uptime_ms': uptime_ms,
                        'logs': formatted_logs
                    }, cls=DecimalEncoder)
                }

    # Timeout - device didn't respond
    return {
        'statusCode': 408,
        'headers': cors_headers(),
        'body': json.dumps({
            'error': 'Device did not respond',
            'command_id': command_id,
            'hint': 'Device may be offline or sleeping'
        })
    }


def update_device_info(device_id, user_id, body):
    """Update device info (name, location, room) in DynamoDB"""

    # Verify user owns this device
    if not verify_device_access(device_id, user_id):
        return {
            'statusCode': 403,
            'headers': cors_headers(),
            'body': json.dumps({'error': 'Access denied'})
        }

    # Get device info (admin-aware: finds device regardless of stored user_id)
    device_info = get_device_info(device_id, user_id)
    if not device_info:
        return {
            'statusCode': 404,
            'headers': cors_headers(),
            'body': json.dumps({'error': 'Device not found'})
        }

    # Use the actual user_id from DynamoDB (may differ from JWT user_id for admin)
    actual_user_id = device_info.get('user_id', user_id)

    # Extract fields from body
    device_name = body.get('name', '').strip()
    location = body.get('location', '').strip()
    room = body.get('room', '').strip()

    # Validate at least device name is provided
    if not device_name:
        return {
            'statusCode': 400,
            'headers': cors_headers(),
            'body': json.dumps({'error': 'Device name is required'})
        }

    # Default values if empty
    if not location:
        location = '—'
    if not room:
        room = '—'

    try:
        # Update device info in DynamoDB (use actual_user_id from DB)
        devices_table.update_item(
            Key={
                'user_id': actual_user_id,
                'device_id': device_id
            },
            UpdateExpression='SET device_name = :name, #loc = :location, room = :room',
            ExpressionAttributeNames={
                '#loc': 'location'  # location is a reserved word
            },
            ExpressionAttributeValues={
                ':name': device_name,
                ':location': location,
                ':room': room
            }
        )

        print(f"[INFO] Updated device info for {device_id}: name={device_name}, location={location}, room={room}")

        return {
            'statusCode': 200,
            'headers': cors_headers(),
            'body': json.dumps({
                'success': True,
                'message': 'Device info updated',
                'device_name': device_name,
                'location': location,
                'room': room
            })
        }

    except Exception as e:
        print(f"[ERROR] Failed to update device info: {e}")
        return {
            'statusCode': 500,
            'headers': cors_headers(),
            'body': json.dumps({'error': str(e)})
        }


class DecimalEncoder(json.JSONEncoder):
    """JSON encoder for DynamoDB Decimal types"""
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super(DecimalEncoder, self).default(obj)


# ============ Admin Functions ============

def is_user_admin(user_id):
    """Check if user has admin privileges"""
    ADMIN_EMAILS = ['mrmaximshurigin@gmail.com', 'admin']
    return user_id in ADMIN_EMAILS


def find_device_by_id(device_id):
    """Find device in any user's collection (scan - OK for small tables)"""
    try:
        response = devices_table.scan(
            FilterExpression='device_id = :did',
            ExpressionAttributeValues={':did': device_id}
        )
        items = response.get('Items', [])
        return items[0] if items else None
    except Exception as e:
        print(f"[ERROR] find_device_by_id: {e}")
        return None


def get_telemetry_config(device_id, user_id):
    """GET /device/{id}/telemetry/config - Get telemetry config (admin only)

    Returns flat structure expected by admin.html:
    - sensor_interval_min, battery_interval_min, system_interval_min
    - pump_events, config_events, response_events
    - last_updated (timestamp when config was saved)
    """

    # Admin only
    if not is_user_admin(user_id):
        return {'statusCode': 403, 'headers': cors_headers(),
                'body': json.dumps({'error': 'Admin privileges required'})}

    # Find device to get config
    device_record = find_device_by_id(device_id)
    if not device_record:
        return {'statusCode': 404, 'headers': cors_headers(),
                'body': json.dumps({'error': 'Device not found'})}

    # Get stored config or empty dict
    stored = device_record.get('telemetry_config', {})

    # Return flat structure with defaults for missing values
    return {
        'statusCode': 200,
        'headers': cors_headers(),
        'body': json.dumps({
            'device_id': device_id,
            'sensor_interval_min': stored.get('sensor_interval_min', 60),
            'battery_interval_min': stored.get('battery_interval_min', 60),
            'system_interval_min': stored.get('system_interval_min', 30),
            'pump_events': stored.get('pump_events', True),
            'config_events': stored.get('config_events', True),
            'response_events': stored.get('response_events', True),
            'last_updated': stored.get('last_updated')
        }, cls=DecimalEncoder)
    }
