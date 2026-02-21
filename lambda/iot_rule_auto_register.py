"""
IoT Rule: Auto-Register New Devices
Triggered on first MQTT publish from new device
Automatically adds device to polivalka_devices table

Trigger: Polivalka/+/system (first system message)
"""

import json
import boto3
import os
import time

dynamodb = boto3.resource('dynamodb', region_name='eu-central-1')
iot_client = boto3.client('iot', region_name='eu-central-1')

DEVICES_TABLE = os.environ.get('DEVICES_TABLE', 'polivalka_devices')
devices_table = dynamodb.Table(DEVICES_TABLE)


def lambda_handler(event, context):
    """
    Auto-register new device on first MQTT publish

    Event structure (from IoT Rule):
    {
        "topic": "Polivalka/BB00C1/system",
        "device_id": "BB00C1",  # extracted by IoT Rule SQL
        "data": {...}  # system message payload
    }
    """

    try:
        # Extract device_id from event
        # СТАНДАРТ: device_id ВСЕГДА должен быть "Polivalka-BC67E9"
        # IoT Rule может передать "BB00C1" (из topic(2)) или "Polivalka-BB00C1" (из payload)
        raw_device_id = event.get('device_id', '')

        # Нормализация: добавляем префикс если его нет
        if raw_device_id.startswith('Polivalka-'):
            device_id = raw_device_id  # Уже правильный формат
        else:
            device_id = f'Polivalka-{raw_device_id}'  # Добавляем префикс

        if not device_id or device_id == 'Polivalka-':
            print(f"[ERROR] No device_id in event: {event}")
            return {'statusCode': 400, 'body': 'Missing device_id'}

        print(f"[INFO] Processing device: {device_id}")

        # Check if device already registered (any owner, not just admin)
        from boto3.dynamodb.conditions import Key as DDBKey
        response = devices_table.query(
            IndexName='device_id-index',
            KeyConditionExpression=DDBKey('device_id').eq(device_id),
            Limit=1
        )

        if response.get('Items'):
            owner = response['Items'][0]['user_id']
            print(f"[INFO] Device {device_id} already registered (owner: {owner})")
            return {'statusCode': 200, 'body': 'Device already registered'}

        # Get Thing attributes (location, room) from IoT Core
        # ВАЖНО: Thing name = device_id (с дефисом!): "Polivalka-BC67E9"
        thing_name = device_id
        thing_attrs = {}

        try:
            thing_response = iot_client.describe_thing(thingName=thing_name)
            thing_attrs = thing_response.get('attributes', {})
        except Exception as e:
            print(f"[WARN] Could not get Thing attributes: {e}")

        # Auto-register device
        # device_id уже содержит префикс "Polivalka-BC67E9"
        # Use sensible defaults for new devices
        devices_table.put_item(
            Item={
                'user_id': 'admin',  # TODO: extract from invite code or Cognito
                'device_id': device_id,  # "Polivalka-BC67E9"
                'device_name': device_id,  # Same as device_id (display name)
                'location': thing_attrs.get('location', 'Home'),  # Default: Home
                'room': thing_attrs.get('room', 'Living Room'),  # Default: Living Room
                'registered_at': int(time.time()),
                'auto_registered': True
            }
        )

        print(f"[SUCCESS] Auto-registered device {device_id}")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'Device {device_id} auto-registered',
                'user_id': 'admin',
                'device_id': device_id
            })
        }

    except Exception as e:
        print(f"[ERROR] Auto-registration failed: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
