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


def lambda_handler(event, context):
    """Update command status based on device response"""

    print(f"Received event: {json.dumps(event)}")

    # ESP32 sends: {"device_id": "Polivalka-BB00C1", "response": {...}}
    # IoT Rule SQL extracts fields from nested response object
    device_id = event.get('device_id')  # Already has "Polivalka-" prefix
    command_id = event.get('command_id')
    status = event.get('status', 'unknown')
    message = event.get('message', '')
    result = event.get('result', {})  # IoT Rule extracts response.data as "result"

    if not command_id:
        print("No command_id in response")
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

            # If result has sensor data (from get_status), update telemetry
            # IMPORTANT: Each data type gets its own 'updated_at' timestamp
            # so stale data doesn't appear "fresh" when last_update is bumped
            # by unrelated command responses (e.g. stop_pump bumps last_update
            # but doesn't update sensor data → old sensor data looked "newer"
            # than real telemetry, causing 0% moisture bug)
            if isinstance(result, dict) and 'sensor' in result:
                sensor = result.get('sensor', {})
                update_expr += ', sensor = :sensor'
                sensor_data = {
                    'adc_raw': sensor.get('adc'),
                    'moisture_percent': sensor.get('moisture'),
                    'updated_at': current_time  # Per-type timestamp
                }
                # Include sensor2 (resistive J7) if present
                if 'sensor2' in result:
                    sensor2 = result.get('sensor2', {})
                    sensor_data['sensor2_adc'] = sensor2.get('adc')
                    sensor_data['sensor2_percent'] = sensor2.get('percent')
                expr_values[':sensor'] = sensor_data
                print(f"Updating sensor telemetry: adc={sensor.get('adc')}, moisture={sensor.get('moisture')}, sensor2={result.get('sensor2')}")

            telemetry_table.update_item(
                Key={'device_id': device_id, 'timestamp': 0},  # timestamp=0 is "latest" record
                UpdateExpression=update_expr,
                ExpressionAttributeValues=expr_values
            )
            print(f"Updated telemetry for {device_id}: last_update={current_time}")
        except Exception as e:
            print(f"Failed to update telemetry: {e}")  # Non-fatal, continue

        # Extract calibration data from get_status response and update devices table
        if isinstance(result, dict):
            try:
                # Find user_id for this device (once for all updates)
                scan_response = devices_table.scan(
                    FilterExpression='device_id = :device',
                    ExpressionAttributeValues={':device': device_id}
                )
                if scan_response.get('Items'):
                    user_id = scan_response['Items'][0]['user_id']

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
