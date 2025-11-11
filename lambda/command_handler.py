"""
AWS Lambda Function: Command Handler
Sends commands to ESP32 devices via AWS IoT MQTT

Topic: polivalka/{device_id}/command
"""

import json
import boto3
import uuid
from datetime import datetime

# Initialize AWS IoT Data client
iot_client = boto3.client('iot-data', region_name='us-east-1')


def lambda_handler(event, context):
    """
    Handle POST /command requests

    Request body:
    {
        "device_id": "BC67E9",
        "command": {
            "action": "water",
            "duration_sec": 10
        }
    }

    Response:
    {
        "status": "success",
        "command_id": "uuid",
        "message": "Command sent to BC67E9"
    }
    """

    print(f"Event: {json.dumps(event)}")

    try:
        # Parse request body
        body = json.loads(event['body'])
        device_id = body.get('device_id')
        command = body.get('command')

        # Validation
        if not device_id:
            return error_response(400, 'Missing device_id')

        if not command or 'action' not in command:
            return error_response(400, 'Missing command or action')

        # Validate action
        valid_actions = ['water', 'read_sensor', 'stop']
        if command['action'] not in valid_actions:
            return error_response(400, f'Invalid action. Must be one of: {valid_actions}')

        # Generate command ID
        command_id = str(uuid.uuid4())

        # Build MQTT payload
        mqtt_payload = {
            'command_id': command_id,
            'timestamp': int(datetime.now().timestamp()),
            'action': command['action']
        }

        # Add optional parameters
        if 'duration_sec' in command:
            mqtt_payload['duration_sec'] = int(command['duration_sec'])

        # Publish to MQTT topic
        topic = f'polivalka/{device_id}/command'

        print(f"Publishing to topic: {topic}")
        print(f"Payload: {json.dumps(mqtt_payload)}")

        iot_client.publish(
            topic=topic,
            qos=1,
            payload=json.dumps(mqtt_payload)
        )

        return success_response({
            'status': 'success',
            'command_id': command_id,
            'message': f'Command sent to {device_id}',
            'device_id': device_id,
            'action': command['action']
        })

    except json.JSONDecodeError as e:
        print(f"JSON decode error: {e}")
        return error_response(400, 'Invalid JSON in request body')

    except KeyError as e:
        print(f"KeyError: {e}")
        return error_response(400, f'Missing required field: {e}')

    except Exception as e:
        print(f"Unexpected error: {e}")
        return error_response(500, f'Internal server error: {str(e)}')


def success_response(data):
    """Return success response with CORS headers"""
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',  # Enable CORS for GitHub Pages
            'Access-Control-Allow-Headers': 'Content-Type,Authorization',
            'Access-Control-Allow-Methods': 'GET,POST,OPTIONS'
        },
        'body': json.dumps(data)
    }


def error_response(status_code, message):
    """Return error response with CORS headers"""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type,Authorization',
            'Access-Control-Allow-Methods': 'GET,POST,OPTIONS'
        },
        'body': json.dumps({
            'status': 'error',
            'message': message
        })
    }
