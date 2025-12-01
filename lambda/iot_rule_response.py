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
commands_table = dynamodb.Table(COMMANDS_TABLE)
telemetry_table = dynamodb.Table(TELEMETRY_TABLE)

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

        # Insert heartbeat record to telemetry table (proves device is online)
        # api_handler.py uses max(timestamp) as last_update, so inserting new record updates it
        try:
            current_time = int(time.time())
            telemetry_table.put_item(
                Item={
                    'device_id': device_id,
                    'timestamp': current_time,
                    'type': 'heartbeat',
                    'command_id': command_id,
                    'ttl': current_time + 604800  # 7 days TTL
                }
            )
            print(f"Inserted heartbeat for {device_id}: {current_time}")
        except Exception as e:
            print(f"Failed to insert heartbeat: {e}")  # Non-fatal, continue

        return {'statusCode': 200, 'body': 'Updated'}

    except Exception as e:
        print(f"Error updating command: {e}")
        return {'statusCode': 500, 'body': str(e)}
