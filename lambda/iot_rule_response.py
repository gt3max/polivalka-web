"""
IoT Rule Handler - Process command responses from devices

Triggered by IoT Rule:
  - Polivalka/+/response → update command status in DynamoDB

Input (from MQTT Polivalka/{device_id}/response):
  {
    "command_id": "abc-123",
    "status": "success",
    "message": "Pump started",
    "data": {...}
  }

Output: Update polivalka_commands table
  - Set status = success/error
  - Add response data
  - Add completed_at timestamp
"""

import json
import boto3
import os
import time
from decimal import Decimal
from boto3.dynamodb.conditions import Key

dynamodb = boto3.resource('dynamodb', region_name='eu-central-1')
COMMANDS_TABLE = os.environ.get('COMMANDS_TABLE', 'polivalka_commands')
TELEMETRY_TABLE = os.environ.get('TELEMETRY_TABLE', 'polivalka_telemetry')
DEVICES_TABLE = os.environ.get('DEVICES_TABLE', 'polivalka_devices')
commands_table = dynamodb.Table(COMMANDS_TABLE)
telemetry_table = dynamodb.Table(TELEMETRY_TABLE)
devices_table = dynamodb.Table(DEVICES_TABLE)

def convert_floats(obj):
    """Convert all float values to Decimal recursively"""
    if isinstance(obj, float):
        return Decimal(str(obj))
    elif isinstance(obj, dict):
        return {k: convert_floats(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_floats(item) for item in obj]
    return obj


def normalize_flat_response(flat):
    """Convert flat ESP32 get_status response to nested format expected by Lambda/API.

    ESP32 sends flat: {moisture: 99, adc: 1213, voltage: 4.18, percent: 81, mode: "sensor", ...}
    Lambda expects nested: {sensor: {moisture, adc}, battery: {percent, voltage}, system: {mode, state}, pump: {running}}
    """
    # Only normalize if response is flat (no 'sensor'/'battery'/'system' keys)
    if 'sensor' in flat or 'battery' in flat or 'system' in flat:
        return flat  # Already nested format

    result = {}

    # Sensor data
    if 'moisture' in flat or 'adc' in flat:
        result['sensor'] = {
            'moisture': flat.get('moisture'),
            'adc': flat.get('adc'),
            'percent_float': flat.get('percent_float'),
            'calibration': {
                'water': flat.get('water'),
                'dry_soil': flat.get('dry_soil'),
                'air': flat.get('air')
            }
        }

    # Sensor2 (J7 resistive) if present
    if 'sensor2_adc' in flat or 'sensor2_percent' in flat:
        result['sensor2'] = {
            'adc': flat.get('sensor2_adc'),
            'percent': flat.get('sensor2_percent')
        }

    # Battery data
    # Note: 'percent' in flat response is battery percent (moisture is in 'moisture' field)
    # Sanity check: skip if percent=0 but voltage > 3.5V (old firmware bug, e.g. v1.0.33)
    battery_pct = flat.get('percent')
    battery_voltage = flat.get('voltage')
    if 'voltage' in flat or 'charging' in flat:
        if battery_pct is not None and battery_pct > 0:
            result['battery'] = {
                'percent': battery_pct,
                'voltage': battery_voltage,
                'charging': flat.get('charging', False)
            }
        elif battery_pct == 0 and battery_voltage and battery_voltage > 3.5:
            # Firmware bug: percent=0 with high voltage — skip to preserve periodic telemetry
            print(f"Skipping invalid battery: percent=0, voltage={battery_voltage} (firmware bug)")
        else:
            result['battery'] = {
                'percent': battery_pct,
                'voltage': battery_voltage,
                'charging': flat.get('charging', False)
            }

    # System data
    if 'mode' in flat or 'state' in flat:
        result['system'] = {
            'mode': flat.get('mode'),
            'state': flat.get('state'),
            'firmware': flat.get('firmware'),
            'firmware_version': flat.get('firmware'),
            'reboot_count': flat.get('reboot_count'),
            'clean_restarts': flat.get('clean_restarts'),
            'unexpected_restarts': flat.get('unexpected_restarts'),
            'scan_interval_hours': flat.get('scan_interval_hours')
        }

    # Pump data
    if 'running' in flat:
        result['pump'] = {
            'running': flat.get('running', False),
            'calibration': flat.get('calibration'),
            'speed': flat.get('speed')
        }

    return result


def lambda_handler(event, context):
    """Update command status based on device response"""

    print(f"Received event: {json.dumps(event)}")

    # ESP32 sends: {"device_id": "BB00C1", "response": {"command_id": ..., "status": ..., "moisture": 67, ...}, "timestamp": ...}
    # Handle both nested (SELECT *) and flat (IoT Rule extracts fields) formats
    if 'response' in event and isinstance(event['response'], dict):
        # Nested format: IoT Rule passes raw MQTT message
        response_data = event['response']
        device_id = event.get('device_id', '')
        command_id = response_data.get('command_id')
        status = response_data.get('status', 'unknown')
        message = response_data.get('message', '')
        # Extract data payload - ESP32 sends data directly in response (not nested in 'data')
        # Copy response and remove metadata fields to get just the data
        result = {k: v for k, v in response_data.items()
                  if k not in ['command_id', 'status', 'message']}
    else:
        # Flat format: IoT Rule already extracted fields
        device_id = event.get('device_id', '')
        command_id = event.get('command_id')
        status = event.get('status', 'unknown')
        message = event.get('message', '')
        result = event.get('result', {})

    # Normalize device_id to always include Polivalka- prefix
    if device_id and not device_id.startswith('Polivalka-'):
        device_id = f'Polivalka-{device_id}'

    # Normalize flat ESP32 response to nested format (sensor/battery/system/pump)
    if isinstance(result, dict):
        result = normalize_flat_response(result)

    if not command_id:
        print(f"No command_id in response (device_id={device_id})")
        return {'statusCode': 400, 'body': 'Missing command_id'}

    # Update command in DynamoDB
    try:
        update_values = {
            ':status': status,
            ':completed_at': int(time.time()),
            ':ttl': int(time.time()) + 86400
        }

        # Add result and message if present
        if result:
            # Convert any float values to Decimal for DynamoDB
            update_values[':result'] = convert_floats(result)
        if message:
            update_values[':message'] = message

        # Build update expression dynamically
        update_expr_parts = ['#status = :status', 'completed_at = :completed_at', '#ttl = :ttl']
        if result:
            update_expr_parts.append('#result = :result')
        if message:
            update_expr_parts.append('message = :message')

        attr_names = {
            '#status': 'status',
            '#ttl': 'ttl'  # ttl is a reserved keyword
        }
        if result:
            attr_names['#result'] = 'result'

        commands_table.update_item(
            Key={
                'device_id': device_id,
                'command_id': command_id
            },
            UpdateExpression='SET ' + ', '.join(update_expr_parts),
            ExpressionAttributeNames=attr_names,
            ExpressionAttributeValues=update_values
        )

        print(f"Updated command {command_id} for device {device_id}: {status}")

        # Update telemetry table (proves device is online + fresh sensor data)
        try:
            current_time = int(time.time())
            update_expr = 'SET last_update = :ts'
            expr_values = {':ts': current_time}

            # If result has data from get_status, update telemetry (timestamp=0 record)
            # IMPORTANT: Each data type gets its own 'updated_at' timestamp
            # so stale data doesn't appear "fresh" when last_update is bumped
            # by unrelated command responses (e.g. stop_pump bumps last_update
            # but doesn't update sensor data → old sensor data looked "newer"
            # than real telemetry, causing 0% moisture bug)
            if isinstance(result, dict):
                # Sensor: DO NOT save from command responses to ts=0 record.
                # IoT Rule flatten loses sensor2 nested data (resistive J7),
                # so ts=0 sensor record overwrites periodic telemetry (which has sensor2)
                # in get_latest_telemetry() — causing "Sensor not connected" for sensor2.
                # Periodic sensor telemetry is source of truth.

                # Battery: DO NOT save from command responses to ts=0 record.
                # get_status battery percent is unreliable (v1.0.33: 0% at 4.16V,
                # v1.0.104: 81% at 4.18V). Periodic battery telemetry is source of truth.
                # Saving here would override correct periodic data in get_latest_telemetry().

                # System data (mode, state, firmware)
                # Note: command response has 'firmware', periodic telemetry has 'firmware_version'
                # We normalize to 'firmware_version' for consistency with get_latest_telemetry()
                if 'system' in result:
                    system = result.get('system', {})
                    system_save = {
                        'mode': system.get('mode'),
                        'state': system.get('state'),
                        'updated_at': current_time
                    }
                    # Normalize firmware field name
                    fw = system.get('firmware') or system.get('firmware_version')
                    if fw:
                        system_save['firmware_version'] = fw
                    update_expr += ', system_data = :system'
                    expr_values[':system'] = convert_floats(system_save)
                    print(f"Updating system telemetry: mode={system.get('mode')}, state={system.get('state')}")

            telemetry_table.update_item(
                Key={'device_id': device_id, 'timestamp': 0},  # timestamp=0 is "latest" record
                UpdateExpression=update_expr,
                ExpressionAttributeValues=expr_values
            )
            print(f"Updated telemetry for {device_id}: last_update={current_time}")
        except Exception as e:
            print(f"Failed to update telemetry: {e}")  # Non-fatal, continue

        # ============ FLEET ARCHITECTURE: Update devices.latest ============
        # This provides single source of truth for Fleet display
        if isinstance(result, dict) and result:
            try:
                # Find ALL device records (may have multiple owners)
                query_response = devices_table.query(
                    IndexName='device_id-index',
                    KeyConditionExpression=Key('device_id').eq(device_id)
                )

                if query_response.get('Items'):
                    current_time = int(time.time())

                    for item in query_response['Items']:
                        owner_id = item['user_id']
                        update_parts = []
                        expr_names = {}
                        expr_values = {}

                        # Update each data type with its own updated_at
                        for dtype in ['sensor', 'battery', 'system', 'pump']:
                            if dtype in result and result[dtype]:
                                data_copy = convert_floats(result[dtype].copy())
                                data_copy['updated_at'] = current_time
                                update_parts.append(f'latest.#{dtype} = :{dtype}')
                                expr_names[f'#{dtype}'] = dtype
                                expr_values[f':{dtype}'] = data_copy

                        if update_parts:
                            try:
                                # Create empty 'latest' Map if not exists, then set nested fields
                                expr_values[':empty'] = {}
                                devices_table.update_item(
                                    Key={'user_id': owner_id, 'device_id': device_id},
                                    UpdateExpression='SET latest = if_not_exists(latest, :empty), ' + ', '.join(update_parts),
                                    ExpressionAttributeNames=expr_names,
                                    ExpressionAttributeValues=expr_values
                                )
                            except Exception as e:
                                print(f"Error updating latest for {owner_id}/{device_id}: {e}")

                    print(f"Updated devices.latest for {len(query_response['Items'])} owner(s)")
            except Exception as e:
                print(f"Failed to update devices.latest: {e}")  # Non-fatal
        # ============ END FLEET ARCHITECTURE ============

        # Extract calibration data from get_status response and update devices table
        if isinstance(result, dict):
            try:
                # Find user_id for this device (query by GSI)
                query_response = devices_table.query(
                    IndexName='device_id-index',
                    KeyConditionExpression=Key('device_id').eq(device_id)
                )
                if query_response.get('Items'):
                    user_id = query_response['Items'][0]['user_id']

                    # Pump calibration and speed
                    pump_data = result.get('pump', {})
                    pump_calibration = pump_data.get('calibration')
                    pump_speed = pump_data.get('speed')

                    if pump_calibration is not None or pump_speed is not None:
                        update_expr_parts = []
                        expr_values = {}

                        if pump_calibration is not None:
                            update_expr_parts.append('pump_calibration = :calib')
                            expr_values[':calib'] = Decimal(str(pump_calibration))

                        if pump_speed is not None:
                            update_expr_parts.append('pump_speed = :speed')
                            expr_values[':speed'] = int(pump_speed)

                        if update_expr_parts:
                            devices_table.update_item(
                                Key={'user_id': user_id, 'device_id': device_id},
                                UpdateExpression='SET ' + ', '.join(update_expr_parts),
                                ExpressionAttributeValues=expr_values
                            )
                            print(f"Updated pump for {device_id}: calibration={pump_calibration}, speed={pump_speed}")

                    # Sensor calibration (water, dry_soil, air)
                    # Format 1: from get_status - nested sensor.calibration
                    sensor_data = result.get('sensor', {})
                    sensor_calib = sensor_data.get('calibration', {})
                    if sensor_calib:
                        sensor_calib_decimal = {
                            'water': int(sensor_calib.get('water', 1200)),
                            'dry_soil': int(sensor_calib.get('dry_soil', 2400)),
                            'air': int(sensor_calib.get('air', 2800))
                        }
                        devices_table.update_item(
                            Key={'user_id': user_id, 'device_id': device_id},
                            UpdateExpression='SET sensor_calibration = :calib',
                            ExpressionAttributeValues={':calib': sensor_calib_decimal}
                        )
                        print(f"Updated sensor_calibration for {device_id}: {sensor_calib_decimal}")

                    # Format 2: from set_sensor_calibration - flat adc_water, adc_dry_soil, adc_air
                    if 'adc_water' in result or 'adc_dry_soil' in result or 'adc_air' in result:
                        sensor_calib_decimal = {
                            'water': int(result.get('adc_water', 1200)),
                            'dry_soil': int(result.get('adc_dry_soil', 2400)),
                            'air': int(result.get('adc_air', 2800))
                        }
                        devices_table.update_item(
                            Key={'user_id': user_id, 'device_id': device_id},
                            UpdateExpression='SET sensor_calibration = :calib',
                            ExpressionAttributeValues={':calib': sensor_calib_decimal}
                        )
                        print(f"Updated sensor_calibration (flat format) for {device_id}: {sensor_calib_decimal}")

                    # Sensor 2 (Resistive) calibration - adc_dry, adc_wet
                    # From sensor2_calibrate_dry, sensor2_calibrate_wet, set_sensor2_preset commands
                    if 'adc_dry' in result or 'adc_wet' in result:
                        # Only update fields that were provided
                        update_parts = []
                        expr_values = {}
                        if 'adc_dry' in result:
                            update_parts.append('sensor2_calibration.dry = :dry')
                            expr_values[':dry'] = int(result['adc_dry'])
                        if 'adc_wet' in result:
                            update_parts.append('sensor2_calibration.wet = :wet')
                            expr_values[':wet'] = int(result['adc_wet'])

                        if update_parts:
                            devices_table.update_item(
                                Key={'user_id': user_id, 'device_id': device_id},
                                UpdateExpression='SET ' + ', '.join(update_parts),
                                ExpressionAttributeValues=expr_values
                            )
                            print(f"Updated sensor2_calibration for {device_id}: {expr_values}")

            except Exception as e:
                print(f"Failed to update calibration: {e}")  # Non-fatal

        return {'statusCode': 200, 'body': 'Updated'}

    except Exception as e:
        print(f"Error updating command: {e}")
        return {'statusCode': 500, 'body': str(e)}
