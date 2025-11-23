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
from decimal import Decimal
from boto3.dynamodb.conditions import Key

# ALL resources in eu-central-1 (Frankfurt)
dynamodb = boto3.resource('dynamodb', region_name='eu-central-1')
iot_client = boto3.client('iot-data', region_name='eu-central-1')
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

    # Extract user_id from Cognito authorizer (or API key for now)
    user_id = event.get('requestContext', {}).get('authorizer', {}).get('claims', {}).get('sub', 'admin')

    # Route to appropriate handler
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

            if len(parts) == 5 and parts[3] == 'battery' and parts[4] == 'history':
                return get_battery_history(device_id, user_id)

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

            # Activity log (commands + telemetry combined)
            if len(parts) == 4 and parts[3] == 'activity' and http_method == 'GET':
                return get_device_activity(device_id, user_id)

            # ESP32 real-time logs from RAM buffer
            if len(parts) == 4 and parts[3] == 'logs' and http_method == 'GET':
                return get_device_logs(device_id, user_id)

    return {
        'statusCode': 404,
        'headers': cors_headers(),
        'body': json.dumps({'error': 'Not found'})
    }


def get_devices(user_id):
    """GET /devices - List all user's devices with latest telemetry"""

    # Query devices for this user
    response = devices_table.query(
        KeyConditionExpression=Key('user_id').eq(user_id)
    )

    devices = []
    for item in response.get('Items', []):
        device_id = item['device_id']

        # Get latest telemetry (sensor, battery, system)
        latest = get_latest_telemetry(device_id)

        # Merge device metadata + telemetry
        device_data = {
            'device_id': device_id,
            'name': item.get('device_name', device_id),  # device_id already contains "Polivalka-"
            'location': item.get('location', '—'),
            'room': item.get('room', '—'),
            'moisture_pct': latest.get('sensor', {}).get('moisture_percent'),
            'adc_raw': latest.get('sensor', {}).get('adc_raw'),
            'battery_pct': latest.get('battery', {}).get('percent'),
            'battery_charging': latest.get('battery', {}).get('charging', False),
            'mode': latest.get('system', {}).get('mode', 'off'),
            'state': latest.get('system', {}).get('state', 'UNKNOWN'),
            'firmware_version': latest.get('system', {}).get('firmware_version', 'v1.0.0'),
            'reboot_count': latest.get('system', {}).get('reboot_count'),
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

    # Get device metadata
    device_response = devices_table.get_item(
        Key={'user_id': user_id, 'device_id': device_id}
    )
    device_meta = device_response.get('Item', {})

    # Get latest telemetry
    latest = get_latest_telemetry(device_id)

    # Format response matching ESP32 /api/status structure
    status = {
        'adc': latest.get('sensor', {}).get('adc_raw'),
        'percent': latest.get('sensor', {}).get('moisture_percent'),
        'system_state': {
            'device_name': device_meta.get('device_name', device_id),
            'location': device_meta.get('location', '—'),
            'room': device_meta.get('room', '—'),
            'mode': latest.get('system', {}).get('mode', 'off'),
            'state': latest.get('system', {}).get('state', 'STANDBY')
        },
        'battery': latest.get('battery', {}),
        'last_watering': latest.get('last_watering'),
        'pump_running': False,  # TODO: get from telemetry
        'timestamp': latest.get('last_update')
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
                latest[data_type] = item[data_type]
                if 'last_update' not in latest or timestamp > latest['last_update']:
                    latest['last_update'] = timestamp

    return latest


def verify_device_access(device_id, user_id):
    """Check if user owns this device"""

    response = devices_table.get_item(
        Key={'user_id': user_id, 'device_id': device_id}
    )

    return 'Item' in response


def is_device_online(last_update_timestamp):
    """Check if device is online (updated within last 5 minutes)"""

    if not last_update_timestamp:
        return False

    return (int(time.time()) - last_update_timestamp) < 300  # 5 min


def generate_warnings(telemetry):
    """Generate warning messages based on telemetry"""

    warnings = []

    battery = telemetry.get('battery', {})
    sensor = telemetry.get('sensor', {})

    # Battery warnings
    if battery.get('percent', 100) <= 10:
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
    """GET /device/{id}/sensor - Get real-time sensor reading"""

    if not verify_device_access(device_id, user_id):
        return {'statusCode': 403, 'headers': cors_headers(),
                'body': json.dumps({'error': 'Access denied'})}

    # Send get_sensor command
    command_id = str(uuid.uuid4())
    commands_table.put_item(
        Item={
            'device_id': device_id,
            'command_id': command_id,
            'command': 'get_sensor',
            'params': {},
            'status': 'pending',
            'created_at': int(time.time()),
            'ttl': int(time.time()) + 604800  # 7 days TTL
        }
    )

    # Publish MQTT command
    mqtt_payload = {
        'command_id': command_id,
        'command': 'get_sensor',
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
                # Parse result data
                result = item.get('result', {})
                if isinstance(result, str):
                    try:
                        result = json.loads(result)
                    except:
                        pass

                return {
                    'statusCode': 200,
                    'headers': cors_headers(),
                    'body': json.dumps({
                        'moisture_pct': result.get('moisture'),
                        'adc_raw': result.get('adc'),
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
                mode = system_data.get('mode', 'off')
                # Note: ESP32 doesn't publish 'state' in system telemetry, only 'mode'
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


class DecimalEncoder(json.JSONEncoder):
    """JSON encoder for DynamoDB Decimal types"""
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super(DecimalEncoder, self).default(obj)
