"""
AWS Lambda Function: Sensor Data Handler
Retrieves sensor data history from DynamoDB

Query: /sensor-data?device_id=BC67E9&days=7
"""

import json
import boto3
from datetime import datetime, timedelta
from decimal import Decimal

# Initialize DynamoDB client
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')

# DynamoDB table name (must be created beforehand)
TABLE_NAME = 'polivalka_sensor_data'


class DecimalEncoder(json.JSONEncoder):
    """Helper class to convert Decimal to float for JSON serialization"""

    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super(DecimalEncoder, self).default(obj)


def lambda_handler(event, context):
    """
    Handle GET /sensor-data requests

    Query parameters:
    - device_id: Device ID (required)
    - days: Number of days of history (default: 7, max: 90)

    Response:
    {
        "device_id": "BC67E9",
        "latest": {...},
        "history": [...],
        "count": 123
    }
    """

    print(f"Event: {json.dumps(event)}")

    try:
        # Parse query parameters
        params = event.get('queryStringParameters') or {}
        device_id = params.get('device_id')
        days = int(params.get('days', 7))

        # Validation
        if not device_id:
            return error_response(400, 'Missing device_id query parameter')

        if days < 1 or days > 90:
            return error_response(400, 'days must be between 1 and 90')

        # Calculate time range
        end_time = int(datetime.now().timestamp())
        start_time = int((datetime.now() - timedelta(days=days)).timestamp())

        print(f"Querying device_id={device_id}, from {start_time} to {end_time}")

        # Query DynamoDB
        table = dynamodb.Table(TABLE_NAME)

        response = table.query(
            KeyConditionExpression='device_id = :did AND #ts BETWEEN :start AND :end',
            ExpressionAttributeNames={'#ts': 'timestamp'},
            ExpressionAttributeValues={
                ':did': device_id,
                ':start': start_time,
                ':end': end_time
            },
            ScanIndexForward=False,  # Sort by timestamp descending (newest first)
            Limit=1000  # Max 1000 items
        )

        items = response.get('Items', [])

        print(f"Found {len(items)} items")

        # Get latest reading
        latest = items[0] if items else None

        return success_response({
            'device_id': device_id,
            'latest': latest,
            'history': items,
            'count': len(items),
            'time_range': {
                'start': start_time,
                'end': end_time,
                'days': days
            }
        })

    except ValueError as e:
        print(f"ValueError: {e}")
        return error_response(400, 'Invalid query parameter value')

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
        'body': json.dumps(data, cls=DecimalEncoder)
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
