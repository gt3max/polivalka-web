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
import urllib.request
import urllib.parse
from decimal import Decimal
from boto3.dynamodb.conditions import Key

# ============ CORS Global State ============
# Used to pass origin through nested function calls without modifying all signatures
_current_origin = None

# ============ Admin Access Control ============
ADMIN_EMAILS = ['mrmaximshurigin@gmail.com', 'admin']

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

    email = payload.get('email')

    # Admin email maps to 'admin' user_id (consistent with auto-registration)
    ADMIN_EMAILS = ['mrmaximshurigin@gmail.com']
    if email in ADMIN_EMAILS:
        return 'admin'

    return email


# ============ End JWT ============

# ============ Input Validation (SECURITY - added 2025-12-06) ============
import re

def validate_device_id(device_id):
    """
    Validate device_id format.
    Accepts:
      - Short format: 6 uppercase hex characters (e.g., BC67E9, BB00C1)
      - Full format: Polivalka-XXXXXX (e.g., Polivalka-BC67E9)
    Returns: (is_valid, error_message)
    """
    if not device_id:
        return False, "Device ID is required"

    # Extract short ID if full format (case-insensitive check)
    short_id = device_id
    if device_id.upper().startswith('POLIVALKA-'):
        short_id = device_id[10:]  # Remove "Polivalka-" prefix

    if len(short_id) != 6:
        return False, f"Device ID must be 6 hex characters, got {len(short_id)}"

    # Must be uppercase hex
    if not re.match(r'^[A-F0-9]{6}$', short_id):
        return False, "Device ID must be 6 uppercase hex characters (A-F, 0-9)"

    return True, None


def validate_string_param(value, param_name, max_length=255, required=False):
    """
    Validate string parameter.
    Returns: (is_valid, error_message)
    """
    if value is None:
        if required:
            return False, f"{param_name} is required"
        return True, None

    if not isinstance(value, str):
        return False, f"{param_name} must be a string"

    if len(value) > max_length:
        return False, f"{param_name} exceeds maximum length ({max_length} chars)"

    return True, None


def validate_int_param(value, param_name, min_val=None, max_val=None, required=False):
    """
    Validate integer parameter.
    Returns: (is_valid, sanitized_value, error_message)
    """
    if value is None:
        if required:
            return False, None, f"{param_name} is required"
        return True, None, None

    try:
        int_val = int(value)
    except (ValueError, TypeError):
        return False, None, f"{param_name} must be an integer"

    if min_val is not None and int_val < min_val:
        return False, None, f"{param_name} must be at least {min_val}"

    if max_val is not None and int_val > max_val:
        return False, None, f"{param_name} must be at most {max_val}"

    return True, int_val, None


# ============ End Input Validation ============

# ============ Plant Recognition API (added 2025-12-06) ============

PLANTNET_API_KEY = os.environ.get('PLANTNET_API_KEY', '')
PERENUAL_API_KEY = os.environ.get('PERENUAL_API_KEY', '')
PLANTNET_URL = 'https://my-api.plantnet.org/v2/identify/all'
PERENUAL_URL = 'https://perenual.com/api/species-list'


def identify_plant_handler(event, origin):
    """
    POST /plants/identify
    Receives base64 image, sends to PlantNet, returns identification results.
    """
    if not PLANTNET_API_KEY:
        return {
            'statusCode': 500,
            'headers': cors_headers(origin),
            'body': json.dumps({'error': 'PlantNet API key not configured'})
        }

    try:
        body = json.loads(event.get('body', '{}'))
        image_base64 = body.get('image')

        if not image_base64:
            return {
                'statusCode': 400,
                'headers': cors_headers(origin),
                'body': json.dumps({'error': 'Missing image parameter'})
            }

        # Remove data URL prefix if present
        if ',' in image_base64:
            image_base64 = image_base64.split(',')[1]

        # Decode base64 to bytes
        image_bytes = base64.b64decode(image_base64)

        # Detect image type from magic bytes
        if image_bytes[:3] == b'\xff\xd8\xff':
            content_type = 'image/jpeg'
            filename = 'plant.jpg'
        elif image_bytes[:8] == b'\x89PNG\r\n\x1a\n':
            content_type = 'image/png'
            filename = 'plant.png'
        elif image_bytes[:4] == b'RIFF' and image_bytes[8:12] == b'WEBP':
            content_type = 'image/webp'
            filename = 'plant.webp'
        else:
            # Default to JPEG
            content_type = 'image/jpeg'
            filename = 'plant.jpg'

        print(f"[PlantNet] Image type detected: {content_type}, size: {len(image_bytes)} bytes")

        # Create proper multipart form data
        boundary = '----PlantsFormBoundary' + uuid.uuid4().hex[:16]

        # Build multipart body with correct format
        multipart_body = b''
        multipart_body += f'--{boundary}\r\n'.encode()
        multipart_body += f'Content-Disposition: form-data; name="images"; filename="{filename}"\r\n'.encode()
        multipart_body += f'Content-Type: {content_type}\r\n'.encode()
        multipart_body += b'\r\n'
        multipart_body += image_bytes
        multipart_body += b'\r\n'
        multipart_body += f'--{boundary}\r\n'.encode()
        multipart_body += b'Content-Disposition: form-data; name="organs"\r\n'
        multipart_body += b'\r\n'
        multipart_body += b'auto\r\n'
        multipart_body += f'--{boundary}--\r\n'.encode()

        # Build URL with parameters
        params = urllib.parse.urlencode({
            'api-key': PLANTNET_API_KEY,
            'include-related-images': 'true',
            'lang': 'en'
        })
        url = f'{PLANTNET_URL}?{params}'

        # Make request to PlantNet
        req = urllib.request.Request(
            url,
            data=multipart_body,
            method='POST',
            headers={
                'Content-Type': f'multipart/form-data; boundary={boundary}'
            }
        )

        with urllib.request.urlopen(req, timeout=30) as response:
            plantnet_data = json.loads(response.read().decode('utf-8'))

        # Transform PlantNet response to our format
        results = []
        for r in plantnet_data.get('results', [])[:5]:  # Top 5 results
            species = r.get('species', {})
            family_info = species.get('family', {})
            genus_info = species.get('genus', {})

            # Get preset based on family
            family_name = family_info.get('scientificNameWithoutAuthor', '')
            preset_key = FAMILY_PRESETS.get(family_name, 'standard')
            preset = PRESET_DETAILS.get(preset_key, PRESET_DETAILS['standard'])

            results.append({
                'id': species.get('scientificNameWithoutAuthor', '').lower().replace(' ', '_'),
                'scientific': species.get('scientificNameWithoutAuthor', ''),
                'commonNames': species.get('commonNames', [])[:3],
                'family': family_name,
                'genus': genus_info.get('scientificNameWithoutAuthor', ''),
                'score': round(r.get('score', 0) * 100, 1),
                'images': [img.get('url', {}).get('s', '') for img in r.get('images', [])[:3]],
                'care': {
                    'preset': preset['name'],
                    'start_pct': preset['start_pct'],
                    'stop_pct': preset['stop_pct'],
                    'watering': preset['watering_frequency'],
                    'light': preset['light'],
                    'temperature': preset['temperature'],
                    'humidity': preset['humidity'],
                    'tips': preset['tips']
                }
            })

        return {
            'statusCode': 200,
            'headers': cors_headers(origin),
            'body': json.dumps({
                'success': True,
                'results': results,
                'source': 'plantnet'
            })
        }

    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8') if e.fp else str(e)
        print(f"PlantNet API error: {e.code} - {error_body}")
        return {
            'statusCode': 502,
            'headers': cors_headers(origin),
            'body': json.dumps({'error': f'PlantNet API error: {e.code}'})
        }
    except Exception as e:
        print(f"Plant identification error: {e}")
        return {
            'statusCode': 500,
            'headers': cors_headers(origin),
            'body': json.dumps({'error': str(e)})
        }


# Family to preset mapping for houseplants
FAMILY_PRESETS = {
    # Tropical - high humidity, frequent watering
    'Araceae': 'tropical',        # Monstera, Philodendron, Pothos, Alocasia, Anthurium
    'Marantaceae': 'tropical',    # Calathea, Maranta, Stromanthe
    'Bromeliaceae': 'tropical',   # Bromeliads
    'Gesneriaceae': 'tropical',   # African violets
    'Piperaceae': 'tropical',     # Peperomia (though some are succulent-like)

    # Succulents - infrequent watering, drought tolerant
    'Cactaceae': 'succulents',    # All cacti
    'Crassulaceae': 'succulents', # Echeveria, Sedum, Crassula, Kalanchoe
    'Asphodelaceae': 'succulents', # Aloe, Haworthia, Gasteria
    'Aizoaceae': 'succulents',    # Lithops, living stones
    'Euphorbiaceae': 'succulents', # Euphorbia (some are succulent)

    # Herbs - moderate, consistent moisture
    'Lamiaceae': 'herbs',         # Basil, Mint, Rosemary, Lavender
    'Apiaceae': 'herbs',          # Parsley, Cilantro, Dill

    # Standard - average watering (default for most)
    'Moraceae': 'standard',       # Ficus
    'Asparagaceae': 'standard',   # Sansevieria, Dracaena, Yucca, Aspidistra
    'Araliaceae': 'standard',     # Schefflera, Ivy
    'Rutaceae': 'standard',       # Citrus
    'Apocynaceae': 'standard',    # Hoya (though some need less water)
    'Orchidaceae': 'standard',    # Orchids (specialized but moderate)
    'Polypodiaceae': 'tropical',  # Ferns - actually need more water
    'Pteridaceae': 'tropical',    # Ferns
    'Begoniaceae': 'standard',    # Begonias
    'Malvaceae': 'standard',      # Hibiscus
}

PRESET_DETAILS = {
    'succulents': {
        'name': 'Succulents',
        'start_pct': 15,
        'stop_pct': 25,
        'watering_frequency': 'Every 2-3 weeks',
        'watering_winter': 'Once a month',
        'light': 'Bright direct or indirect light',
        'temperature': '18-27°C (65-80°F)',
        'humidity': 'Low (30-40%)',
        'tips': 'Let soil dry completely between waterings. Overwatering is the #1 killer.'
    },
    'standard': {
        'name': 'Standard',
        'start_pct': 35,
        'stop_pct': 55,
        'watering_frequency': 'Every 7-10 days',
        'watering_winter': 'Every 2 weeks',
        'light': 'Bright indirect light',
        'temperature': '18-24°C (65-75°F)',
        'humidity': 'Average (40-60%)',
        'tips': 'Water when top inch of soil is dry. Most forgiving category.'
    },
    'tropical': {
        'name': 'Tropical',
        'start_pct': 55,
        'stop_pct': 75,
        'watering_frequency': 'Every 5-7 days',
        'watering_winter': 'Every 10-14 days',
        'light': 'Bright indirect light, no direct sun',
        'temperature': '21-29°C (70-85°F)',
        'humidity': 'High (60-80%)',
        'tips': 'Keep soil consistently moist but not soggy. Mist leaves or use humidifier.'
    },
    'herbs': {
        'name': 'Herbs',
        'start_pct': 30,
        'stop_pct': 45,
        'watering_frequency': 'Every 5-7 days',
        'watering_winter': 'Every 7-10 days',
        'light': 'Full sun (6+ hours)',
        'temperature': '15-24°C (60-75°F)',
        'humidity': 'Average (40-50%)',
        'tips': 'Herbs like consistent moisture. Harvest regularly to promote growth.'
    }
}


def get_plant_care_handler(event, origin):
    """
    GET /plants/care?name=scientific_name&family=family_name
    Gets plant care info from Wikipedia + our preset mapping.
    """
    try:
        query_params = event.get('queryStringParameters', {}) or {}
        plant_name = query_params.get('name', '')
        family = query_params.get('family', '')

        if not plant_name:
            return {
                'statusCode': 400,
                'headers': cors_headers(origin),
                'body': json.dumps({'error': 'Missing name parameter'})
            }

        # 1. Get preset from family mapping
        preset_key = FAMILY_PRESETS.get(family, 'standard')
        preset = PRESET_DETAILS.get(preset_key, PRESET_DETAILS['standard'])

        # 2. Get description from Wikipedia
        wiki_data = {}
        try:
            wiki_name = plant_name.replace(' ', '_')
            wiki_url = f'https://en.wikipedia.org/api/rest_v1/page/summary/{urllib.parse.quote(wiki_name)}'
            req = urllib.request.Request(wiki_url, headers={'User-Agent': 'PlantApp/1.0'})

            with urllib.request.urlopen(req, timeout=10) as response:
                wiki_response = json.loads(response.read().decode('utf-8'))
                wiki_data = {
                    'title': wiki_response.get('title'),
                    'description': wiki_response.get('description'),
                    'extract': wiki_response.get('extract'),
                    'image': wiki_response.get('thumbnail', {}).get('source'),
                    'wiki_url': wiki_response.get('content_urls', {}).get('desktop', {}).get('page')
                }
        except Exception as e:
            print(f"Wikipedia lookup failed: {e}")
            wiki_data = {'extract': f'{plant_name} - care information based on plant family.'}

        result = {
            'scientific_name': plant_name,
            'family': family,
            'common_name': wiki_data.get('title', plant_name),
            'description': wiki_data.get('extract', ''),
            'image': wiki_data.get('image'),
            'wiki_url': wiki_data.get('wiki_url'),
            'care': {
                'preset': preset['name'],
                'start_pct': preset['start_pct'],
                'stop_pct': preset['stop_pct'],
                'watering_frequency': preset['watering_frequency'],
                'watering_winter': preset['watering_winter'],
                'light': preset['light'],
                'humidity': preset['humidity'],
                'tips': preset['tips']
            }
        }

        return {
            'statusCode': 200,
            'headers': cors_headers(origin),
            'body': json.dumps({
                'success': True,
                'plant': result,
                'source': 'wikipedia+preset'
            })
        }

    except Exception as e:
        print(f"Plant care lookup error: {e}")
        return {
            'statusCode': 500,
            'headers': cors_headers(origin),
            'body': json.dumps({'error': str(e)})
        }


# ============ End Plant Recognition API ============

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
FIRMWARE_CDN_DOMAIN = os.environ.get('FIRMWARE_CDN_DOMAIN', 'dueyl7xkzas7u.cloudfront.net')

# All tables in eu-central-1
devices_table = dynamodb.Table(DEVICES_TABLE)
telemetry_table = dynamodb.Table(TELEMETRY_TABLE)
commands_table = dynamodb.Table(COMMANDS_TABLE)


def save_plant_profile(user_id, event, origin):
    """
    POST /plants/save
    Save plant profile to device record.
    Body: { device_id: "Polivalka-BB00C1", plant: {...} }
    """
    try:
        body = json.loads(event.get('body', '{}'))
        device_id = body.get('device_id', '')
        plant_data = body.get('plant', {})

        if not device_id or not plant_data:
            return {
                'statusCode': 400,
                'headers': cors_headers(origin),
                'body': json.dumps({'error': 'Missing device_id or plant data'})
            }

        # Normalize device_id
        if not device_id.startswith('Polivalka-'):
            device_id = f'Polivalka-{device_id}'

        # Verify user owns this device
        response = devices_table.query(
            IndexName='device_id-index',
            KeyConditionExpression=Key('device_id').eq(device_id)
        )
        items = response.get('Items', [])
        if not items:
            return {
                'statusCode': 404,
                'headers': cors_headers(origin),
                'body': json.dumps({'error': f'Device {device_id} not found'})
            }

        device_user_id = items[0].get('user_id')
        if device_user_id != user_id:
            return {
                'statusCode': 403,
                'headers': cors_headers(origin),
                'body': json.dumps({'error': 'You do not own this device'})
            }

        # Generate plant_id if not provided (for data isolation)
        current_time = int(time.time())
        if not plant_data.get('plant_id'):
            plant_data['plant_id'] = f"plant_{int(current_time * 1000)}"
            # New plant — set started_at for telemetry filtering
            plant_data['started_at'] = current_time

        # Add/update saved_at timestamp
        plant_data['saved_at'] = current_time

        # Update device record with plant profile
        devices_table.update_item(
            Key={'user_id': user_id, 'device_id': device_id},
            UpdateExpression='SET plant = :plant',
            ExpressionAttributeValues={':plant': plant_data}
        )

        print(f"[PLANTS] Saved plant profile for {device_id}: {plant_data.get('scientific', 'unknown')}")
        return {
            'statusCode': 200,
            'headers': cors_headers(origin),
            'body': json.dumps({'success': True, 'message': 'Plant profile saved'})
        }

    except Exception as e:
        print(f"[PLANTS] Error saving plant profile: {e}")
        return {
            'statusCode': 500,
            'headers': cors_headers(origin),
            'body': json.dumps({'error': str(e)})
        }


def get_plant_profile(user_id, device_id, origin):
    """
    GET /plants/{device_id}
    Get plant profile from device record.
    """
    try:
        # Normalize device_id
        if not device_id.startswith('Polivalka-'):
            device_id = f'Polivalka-{device_id}'

        # Get device record
        response = devices_table.query(
            IndexName='device_id-index',
            KeyConditionExpression=Key('device_id').eq(device_id)
        )
        items = response.get('Items', [])
        if not items:
            return {
                'statusCode': 404,
                'headers': cors_headers(origin),
                'body': json.dumps({'error': f'Device {device_id} not found'})
            }

        device = items[0]
        device_user_id = device.get('user_id')

        # Verify ownership (admin can access any device)
        is_admin = user_id in ADMIN_EMAILS
        if device_user_id != user_id and not is_admin:
            return {
                'statusCode': 403,
                'headers': cors_headers(origin),
                'body': json.dumps({'error': 'You do not own this device'})
            }

        plant = device.get('plant')
        return {
            'statusCode': 200,
            'headers': cors_headers(origin),
            'body': json.dumps({'success': True, 'plant': plant}, cls=DecimalEncoder)
        }

    except Exception as e:
        print(f"[PLANTS] Error getting plant profile: {e}")
        return {
            'statusCode': 500,
            'headers': cors_headers(origin),
            'body': json.dumps({'error': str(e)})
        }


def get_telemetry_device_id(device_id):
    """Convert API device_id (BB00C1) to telemetry format (Polivalka-BB00C1)
    ESP32 publishes telemetry with 'Polivalka-' prefix, but API uses short ID
    """
    if device_id.startswith('Polivalka-'):
        return device_id
    return f'Polivalka-{device_id}'


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

    # Get Origin header for CORS
    request_headers = event.get('headers', {})
    origin = request_headers.get('origin') or request_headers.get('Origin')

    # Set global origin for nested function calls
    global _current_origin
    _current_origin = origin

    # Handle CORS preflight
    if http_method == 'OPTIONS':
        return {
            'statusCode': 200,
            'headers': cors_headers(origin),
            'body': ''
        }

    # Extract user_id from JWT token
    user_id = get_user_from_event(event)

    # Public endpoints that don't require authentication
    PUBLIC_PATHS = ['/plants/identify', '/plants/care']

    # SECURITY: Require valid authentication for all API endpoints
    # MVP fallback removed 2025-12-06 (security hardening)
    # Exception: /plants/* endpoints are public (plant recognition for everyone)
    if not user_id and path not in PUBLIC_PATHS:
        return {
            'statusCode': 401,
            'headers': cors_headers(origin),
            'body': json.dumps({'error': 'Authentication required'})
        }

    # Route to appropriate handler
    print(f"[DEBUG] path={path}, user_id={user_id}")
    if path == '/devices' and http_method == 'GET':
        return get_devices(user_id)

    # Parse device_id from path /device/{id}/*
    if path.startswith('/device/'):
        parts = path.split('/')
        if len(parts) >= 3:
            device_id = parts[2]  # Keep original case (Polivalka-XXXXXX format)

            # SECURITY: Validate device_id format (added 2025-12-06)
            is_valid, error_msg = validate_device_id(device_id)
            if not is_valid:
                return {
                    'statusCode': 400,
                    'headers': cors_headers(origin),
                    'body': json.dumps({'error': f'Invalid device_id: {error_msg}'})
                }

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

            # Moisture endpoint (alias for sensor - used by calibration.html)
            if len(parts) == 4 and parts[3] == 'moisture' and http_method == 'GET':
                return get_sensor_realtime(device_id, user_id)

            if len(parts) == 5 and parts[3] == 'sensor' and parts[4] == 'history':
                return get_sensor_history(device_id, user_id)

            # Sensor presets endpoint - GET returns config from devices_table
            if len(parts) == 5 and parts[3] == 'sensor' and parts[4] == 'preset' and http_method == 'GET':
                # Get sensor config from devices_table (synced from ESP32)
                device_info = get_device_info(device_id, user_id)
                sensor_config = device_info.get('config_sensor', {})

                # Deep watering runtime stats come from system telemetry, not config
                latest = get_latest_telemetry(device_id)
                system_data = latest.get('system', {})

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
                        'max_water_cycle_ml': sensor_config.get('max_water_cycle_ml', 300),
                        'cooldown_min': sensor_config.get('cooldown_min', 120),
                        'max_water_day_ml': sensor_config.get('max_water_day_ml', 400),
                        'no_rise_check_ml': sensor_config.get('no_rise_check_ml', 60),
                        'idle_check_interval_min': sensor_config.get('idle_check_interval_min', 60),
                        'microprime_interval_hours': sensor_config.get('microprime_interval_hours', 48),
                        'microprime_pulse_sec': sensor_config.get('microprime_pulse_sec', 4),
                        'microprime_settle_sec': sensor_config.get('microprime_settle_sec', 90),
                        'baseline_delta_pct_per_ml': sensor_config.get('baseline_delta_pct_per_ml', 0.0),
                        'deep_watering_interval': sensor_config.get('deep_watering_interval', 0),
                        'last_deep_watering_ts': int(system_data.get('last_deep_watering_ts', 0)),
                        'cycles_since_deep': int(system_data.get('cycles_since_deep', 0))
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
                    'max_water_cycle_ml', 'cooldown_min', 'max_water_day_ml', 'no_rise_check_ml',
                    'idle_check_interval_min', 'microprime_interval_hours',
                    'microprime_pulse_sec', 'microprime_settle_sec',
                    'deep_watering_interval'
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

            # POST /device/{id}/sensor/deep_watering_confirm - mark deep watering as done
            if len(parts) == 5 and parts[3] == 'sensor' and parts[4] == 'deep_watering_confirm' and http_method == 'POST':
                return send_command_with_params(device_id, user_id, 'deep_watering_confirm', {}, 'Deep watering confirmed')

            # Sensor controller status endpoint - returns data from telemetry
            if len(parts) == 6 and parts[3] == 'sensor' and parts[4] == 'controller' and parts[5] == 'status':
                # SECURITY: Verify device ownership
                if not verify_device_access(device_id, user_id):
                    return {'statusCode': 403, 'headers': cors_headers(origin),
                            'body': json.dumps({'error': 'Access denied'})}
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
                # SECURITY: Verify device ownership
                if not verify_device_access(device_id, user_id):
                    return {'statusCode': 403, 'headers': cors_headers(origin),
                            'body': json.dumps({'error': 'Access denied'})}
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
                # SECURITY: Verify device ownership
                if not verify_device_access(device_id, user_id):
                    return {'statusCode': 403, 'headers': cors_headers(origin),
                            'body': json.dumps({'error': 'Access denied'})}
                latest = get_latest_telemetry(device_id)
                time_set = latest.get('system', {}).get('time_set', False)

                # Get timezone from devices_table (default: Europe/Warsaw for Poland)
                device_info = get_device_info(device_id, user_id)
                tz_string = device_info.get('timezone', 'Europe/Warsaw')

                # Use zoneinfo for proper DST handling
                current_time, tz_offset_minutes, tz_used = get_local_time_for_timezone(tz_string)

                print(f"DEBUG /time/status: stored={tz_string}, used={tz_used}, offset={tz_offset_minutes}min, local={current_time}")

                return {
                    'statusCode': 200,
                    'headers': cors_headers(),
                    'body': json.dumps({
                        'time_set': time_set,
                        'source': 'ntp' if time_set else 'none',
                        'timestamp': int(time.time()),
                        'current_time': current_time,
                        'timezone': tz_string,
                        'tz_offset_minutes': tz_offset_minutes
                    })
                }

            # Timezone GET endpoint - for settings.html
            if len(parts) == 5 and parts[3] == 'time' and parts[4] == 'timezone' and http_method == 'GET':
                device_info = get_device_info(device_id, user_id)
                tz_string = device_info.get('timezone', 'Europe/Warsaw')
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

            # Time set endpoint - manual time setting (for settings.html)
            if len(parts) == 5 and parts[3] == 'time' and parts[4] == 'set' and http_method == 'POST':
                body = json.loads(event.get('body', '{}'))

                # Accept both formats: {timestamp} or {year, month, day, hour, minute}
                timestamp = body.get('timestamp')
                if not timestamp:
                    # Convert year/month/day/hour/minute to timestamp
                    year = body.get('year')
                    month = body.get('month')
                    day = body.get('day')
                    hour = body.get('hour', 0)
                    minute = body.get('minute', 0)
                    second = body.get('second', 0)

                    if year and month and day:
                        from datetime import datetime, timezone as dt_timezone
                        dt = datetime(year, month, day, hour, minute, second, tzinfo=dt_timezone.utc)
                        timestamp = int(dt.timestamp())
                    else:
                        return {'statusCode': 400, 'headers': cors_headers(), 'body': json.dumps({'error': 'Missing timestamp or date components'})}

                # Send MQTT command to ESP32 to set time
                return send_command_with_params(device_id, user_id, 'set_time', {'timestamp': int(timestamp)}, 'Time set')

            # NOTE: Removed duplicate /schedules endpoint - schedules are returned later in code
            # Schedules are stored on ESP32, not in DynamoDB

            if len(parts) == 5 and parts[3] == 'battery' and parts[4] == 'history':
                return get_battery_history(device_id, user_id)

            # Battery status (for home.html Cloud mode)
            if len(parts) == 5 and parts[3] == 'battery' and parts[4] == 'status' and http_method == 'GET':
                return get_battery_status(device_id, user_id)

            # Pump status (for calibration.html and home.html speed slider)
            if len(parts) == 5 and parts[3] == 'pump' and parts[4] == 'status' and http_method == 'GET':
                # Get pump calibration and speed from device info
                device_info = get_device_info(device_id, user_id)
                pump_calib = device_info.get('pump_calibration')
                pump_speed = device_info.get('pump_speed', 100)

                # Handle both number (from iot_rule_response) and dict formats
                # ESP32 firmware default = 1.0 ml/sec (CALIBRATION_DEFAULT in pump.c)
                if isinstance(pump_calib, dict):
                    ml_per_sec = float(pump_calib.get('ml_per_sec', 1.0))
                    calibrated = pump_calib.get('calibrated', False)
                elif pump_calib is not None:
                    ml_per_sec = float(pump_calib)
                    # Sanity check: values <= 0 or > 20 are invalid (data corruption)
                    if ml_per_sec <= 0 or ml_per_sec > 20:
                        ml_per_sec = 1.0
                        calibrated = False
                    else:
                        calibrated = abs(ml_per_sec - 1.0) > 0.01  # Calibrated if not default (1.0)
                else:
                    ml_per_sec = 1.0
                    calibrated = False

                return {
                    'statusCode': 200,
                    'headers': cors_headers(),
                    'body': json.dumps({
                        'running': False,  # Can't know real-time pump state
                        'remaining_sec': 0,
                        'ml_per_sec': ml_per_sec,
                        'calibrated': calibrated,
                        'speed': int(pump_speed) if pump_speed else 100
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

            # Pump speed control (for home.html speed slider)
            if len(parts) == 5 and parts[3] == 'pump' and parts[4] == 'speed' and http_method == 'POST':
                query_params = event.get('queryStringParameters', {}) or {}
                speed_value = query_params.get('value', '100')
                try:
                    speed = int(speed_value)
                    if speed < 0:
                        speed = 0
                    if speed > 100:
                        speed = 100
                except:
                    speed = 100

                # Send MQTT command to ESP32 to set pump speed
                return send_command_with_params(device_id, user_id, 'set_pump_speed', {'speed': speed}, f'Pump speed set to {speed}%')

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
                # SECURITY: Verify user owns this device (added 2025-12-06)
                if not verify_device_access(device_id, user_id):
                    return {'statusCode': 403, 'headers': cors_headers(origin),
                            'body': json.dumps({'error': 'Access denied'})}

                # Read config_timer from devices table
                try:
                    query_response = devices_table.query(
                        IndexName='device_id-index',
                        KeyConditionExpression=Key('device_id').eq(device_id)
                    )
                    if query_response['Items'] and len(query_response['Items']) > 0:
                        device = query_response['Items'][0]
                        schedules = device.get('config_timer', [])
                        updated = device.get('config_timer_updated', 0)
                        return {
                            'statusCode': 200,
                            'headers': cors_headers(origin),
                            'body': json.dumps({
                                'schedules': schedules,
                                'config_updated': updated,
                                'source': 'cloud_sync'
                            }, cls=DecimalEncoder)
                        }
                    else:
                        return {
                            'statusCode': 200,
                            'headers': cors_headers(origin),
                            'body': json.dumps({
                                'schedules': [],
                                'message': 'Device not found or no config synced yet'
                            })
                        }
                except Exception as e:
                    print(f"Error reading config_timer: {e}")
                    return {
                        'statusCode': 500,
                        'headers': cors_headers(origin),
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

    # ============ Plant Recognition Routes (added 2025-12-06) ============
    # POST /plants/identify - Identify plant from image
    if path == '/plants/identify' and http_method == 'POST':
        return identify_plant_handler(event, origin)

    # GET /plants/care?name=xxx - Get plant care info
    if path == '/plants/care' and http_method == 'GET':
        return get_plant_care_handler(event, origin)

    # POST /plants/save - Save plant profile to device
    if path == '/plants/save' and http_method == 'POST':
        return save_plant_profile(user_id, event, origin)

    # GET /plants/{device_id} - Get plant profile from device
    if path.startswith('/plants/Polivalka-') and http_method == 'GET':
        device_id = path.split('/')[-1]  # Extract device_id from path
        return get_plant_profile(user_id, device_id, origin)

    # ============ Whitelist Check & Claim Routes (Security Migration 2026-01-20) ============
    # These are NOT admin-only - any authenticated user can check their whitelist status

    # GET /whitelist/check?device_id=XXX - Check if user can claim device
    if path == '/whitelist/check' and http_method == 'GET':
        return check_whitelist_status(user_id, event, origin)

    # POST /claims - Create new claim request (for non-whitelisted users)
    if path == '/claims' and http_method == 'POST':
        return create_user_claim(user_id, event, origin)

    # ============ Admin Device Management Routes (added 2025-12-06) ============
    # These endpoints are admin-only for device lifecycle management

    if path.startswith('/admin/'):
        # Verify admin access
        if user_id not in ADMIN_EMAILS:
            return {
                'statusCode': 403,
                'headers': cors_headers(origin),
                'body': json.dumps({'error': 'Admin access required'})
            }

        # GET /admin/devices/archived - List archived devices
        if path == '/admin/devices/archived' and http_method == 'GET':
            return admin_get_archived_devices()

        # GET /admin/devices/deleted - List deleted devices
        if path == '/admin/devices/deleted' and http_method == 'GET':
            return admin_get_deleted_devices()

        # POST /admin/device/{id}/archive - Archive device
        if path.startswith('/admin/device/') and path.endswith('/archive') and http_method == 'POST':
            device_id = path.split('/')[3]  # Already formatted as Polivalka-XXXXXX
            return admin_archive_device(device_id)

        # POST /admin/device/{id}/restore-archive - Restore from archive
        if path.startswith('/admin/device/') and path.endswith('/restore-archive') and http_method == 'POST':
            device_id = path.split('/')[3]  # Already formatted as Polivalka-XXXXXX
            return admin_restore_archive(device_id)

        # POST /admin/device/{id}/delete - Hard delete device
        if path.startswith('/admin/device/') and path.endswith('/delete') and http_method == 'POST':
            device_id = path.split('/')[3]  # Already formatted as Polivalka-XXXXXX
            return admin_delete_device(device_id)

        # POST /admin/device/{id}/restore - Restore deleted device
        if path.startswith('/admin/device/') and path.endswith('/restore') and http_method == 'POST':
            device_id = path.split('/')[3]  # Already formatted as Polivalka-XXXXXX
            return admin_restore_deleted(device_id)

        # GET /admin/users - List all registered users
        if path == '/admin/users' and http_method == 'GET':
            return admin_get_users()

        # ============ Whitelist Management (Security Migration - 2026-01-20) ============
        # GET /admin/whitelist - List all whitelisted users
        if path == '/admin/whitelist' and http_method == 'GET':
            return admin_get_whitelist()

        # POST /admin/whitelist - Add user to whitelist
        if path == '/admin/whitelist' and http_method == 'POST':
            return admin_add_whitelist(event)

        # PUT /admin/whitelist/{email} - Update whitelist user
        if path.startswith('/admin/whitelist/') and http_method == 'PUT':
            email = urllib.parse.unquote(path.split('/admin/whitelist/')[1])
            return admin_update_whitelist(email, event)

        # DELETE /admin/whitelist/{email} - Remove from whitelist
        if path.startswith('/admin/whitelist/') and http_method == 'DELETE':
            email = urllib.parse.unquote(path.split('/admin/whitelist/')[1])
            return admin_delete_whitelist(email)

        # ============ Claims Management ============
        # GET /admin/claims - List all pending claims
        if path == '/admin/claims' and http_method == 'GET':
            return admin_get_claims()

        # POST /admin/claims - Create new claim
        if path == '/admin/claims' and http_method == 'POST':
            return admin_create_claim(event)

        # PUT /admin/claims/{id} - Update claim (approve/reject)
        if path.startswith('/admin/claims/') and http_method == 'PUT':
            claim_id = path.split('/admin/claims/')[1]
            return admin_update_claim(claim_id, event)

        # DELETE /admin/claims/{id} - Delete claim
        if path.startswith('/admin/claims/') and http_method == 'DELETE':
            claim_id = path.split('/admin/claims/')[1]
            return admin_delete_claim(claim_id)

        # ============ Device History ============
        # GET /admin/history/{device_id} - Get device history
        if path.startswith('/admin/history/') and http_method == 'GET':
            device_id = path.split('/admin/history/')[1]
            return admin_get_history(device_id)

        # POST /admin/history - Add history entry
        if path == '/admin/history' and http_method == 'POST':
            return admin_add_history(event)

    return {
        'statusCode': 404,
        'headers': cors_headers(origin),
        'body': json.dumps({'error': 'Not found'})
    }


def get_devices(user_id):
    """GET /devices - List all user's devices with latest telemetry"""

    # Admin users see ALL devices (for fleet management)
    ADMIN_EMAILS = ['mrmaximshurigin@gmail.com', 'admin']

    if user_id in ADMIN_EMAILS:
        # Admin: scan ALL devices
        print(f"[DEBUG] get_devices: Admin user {user_id}, scanning ALL devices")
        response = devices_table.scan()
    else:
        # Regular user: only their devices
        print(f"[DEBUG] get_devices: Regular user {user_id}, querying own devices")
        response = devices_table.query(
            KeyConditionExpression=Key('user_id').eq(user_id)
        )

    items = response.get('Items', [])
    print(f"[DEBUG] get_devices: Found {len(items)} devices before filter: {[i['device_id'] for i in items]}")

    # Filter out archived and deleted devices (they go to separate lists)
    items = [i for i in items if not i.get('archived') and not i.get('deleted')]
    print(f"[DEBUG] get_devices: {len(items)} active devices after filter")

    devices = []
    for item in items:
        device_id = item['device_id']

        try:
            # Get latest telemetry (sensor, battery, system)
            latest = get_latest_telemetry(device_id)
            print(f"[DEBUG] Processing device {device_id}, telemetry keys: {list(latest.keys())}")

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

            # Pump calibration and speed from device record (set via admin panel or telemetry)
            pump_calib = item.get('pump_calibration', 2.5)
            pump_calib_float = float(pump_calib) if pump_calib else 2.5
            pump_speed = item.get('pump_speed', 100)
            pump_speed_int = int(pump_speed) if pump_speed else 100

            # Sensor calibration from device record (set via admin panel)
            sensor_calib = item.get('sensor_calibration', {})
            sensor_calib_dict = {
                'water': int(sensor_calib.get('water', 1200)) if sensor_calib else 1200,
                'dry_soil': int(sensor_calib.get('dry_soil', 2400)) if sensor_calib else 2400,
                'air': int(sensor_calib.get('air', 2800)) if sensor_calib else 2800
            }

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
                # firmware_version: prefer telemetry, fallback to devices table (skip "unknown" from both)
                'firmware_version': (lambda fw_tel, fw_dev: fw_tel if fw_tel and fw_tel != 'unknown' else (fw_dev if fw_dev and fw_dev != 'unknown' else 'v1.0.0'))(latest.get('system', {}).get('firmware_version'), item.get('firmware_version')),
                'reboot_count': item.get('reboot_count'),  # From devices table (persistent), not telemetry
                'clean_restarts': item.get('clean_restarts'),
                'unexpected_restarts': item.get('unexpected_restarts'),
                'ota_count': item.get('ota_count'),
                'ota_last_timestamp': item.get('ota_last_timestamp'),
                'uptime': format_uptime(latest.get('system', {}).get('uptime_ms')),
                'last_watering': item.get('last_watering_timestamp'),
                'last_update': latest.get('last_update'),
                'online': is_device_online(latest.get('last_update')),
                'warnings': generate_warnings(latest),
                'pump_calibration': pump_calib_float,
                'pump_speed': pump_speed_int,
                'sensor_calibration': sensor_calib_dict,
                'total_water_ml': int(item.get('total_water_ml', 0)) if item.get('total_water_ml') else None,
                'pump_runtime_sec': int(item.get('pump_runtime_sec', 0)) if item.get('pump_runtime_sec') else None
            }

            devices.append(device_data)
            print(f"[DEBUG] Device {device_id} processed successfully")

        except Exception as e:
            print(f"[ERROR] Failed to process device {device_id}: {str(e)}")
            import traceback
            traceback.print_exc()
            # Still add basic device info even if telemetry fails
            devices.append({
                'device_id': device_id,
                'name': item.get('device_name', device_id),
                'location': item.get('location', '—'),
                'room': item.get('room', '—'),
                'moisture_pct': None,
                'adc_raw': None,
                'battery_pct': None,
                'battery_charging': False,
                'battery_no_data': True,
                'mode': 'manual',
                'controller_enabled': False,
                'state': 'UNKNOWN',
                'firmware_version': item.get('firmware_version') if item.get('firmware_version') not in [None, '', 'unknown'] else 'v1.0.0',
                'reboot_count': None,
                'clean_restarts': item.get('clean_restarts'),
                'unexpected_restarts': item.get('unexpected_restarts'),
                'ota_count': item.get('ota_count'),
                'ota_last_timestamp': item.get('ota_last_timestamp'),
                'uptime': None,
                'last_watering': item.get('last_watering_timestamp'),
                'last_update': None,
                'online': False,
                'warnings': [],
                'pump_calibration': 2.5,
                'pump_speed': 100,
                'sensor_calibration': {'water': 1200, 'dry_soil': 2400, 'air': 2800}
            })

    print(f"[DEBUG] get_devices: Returning {len(devices)} devices")
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

    # Sensor calibration from devices table
    sensor_calib = device_meta.get('sensor_calibration', {})
    calib = {
        'adc_air': sensor_calib.get('air', 2800) if sensor_calib else 2800,
        'adc_water': sensor_calib.get('water', 1200) if sensor_calib else 1200,
        'adc_dry_soil': sensor_calib.get('dry_soil', 2400) if sensor_calib else 2400
    }
    # Check if calibrated (any value differs from default)
    sensor_calibrated = bool(sensor_calib) and (
        calib['adc_air'] != 2800 or
        calib['adc_water'] != 1200 or
        calib['adc_dry_soil'] != 2400
    )

    # Sensor 2 (Resistive J7) calibration - defaults: dry=100, wet=3000
    sensor2_calib = device_meta.get('sensor2_calibration', {})
    sensor2_calib_data = {
        'dry': int(sensor2_calib.get('dry', 100)) if sensor2_calib else 100,
        'wet': int(sensor2_calib.get('wet', 3000)) if sensor2_calib else 3000
    }
    sensor2_calibrated = bool(sensor2_calib) and (
        sensor2_calib_data['dry'] != 100 or
        sensor2_calib_data['wet'] != 3000
    )

    # Format response matching ESP32 /api/status structure
    sensor_data = latest.get('sensor', {})
    status = {
        'adc': sensor_data.get('adc_raw'),
        'percent': sensor_data.get('moisture_percent'),
        'percent_float': sensor_data.get('percent_float'),  # Decimal precision for sensor1
        'sensor2_adc': sensor_data.get('sensor2_adc'),      # Resistive sensor J7 - ADC
        'sensor2_percent': sensor_data.get('sensor2_percent'),  # Resistive sensor J7 - %
        'sensor2_percent_float': sensor_data.get('sensor2_percent_float'),  # Decimal precision
        'calib': calib,
        'sensor_calibrated': sensor_calibrated,
        'sensor2_calib': sensor2_calib_data,
        'sensor2_calibrated': sensor2_calibrated,
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

    # Special case: reset_stats is DynamoDB-only (no MQTT to ESP32)
    if command == 'reset_stats':
        group = params.get('group')
        if not group:
            return {'statusCode': 400, 'headers': cors_headers(),
                    'body': json.dumps({'error': 'Missing group parameter'})}

        try:
            if group == 'pump':
                # Reset pump stats in DynamoDB
                devices_table.update_item(
                    Key={'user_id': user_id, 'device_id': device_id},
                    UpdateExpression='SET total_water_ml = :zero, pump_runtime_sec = :zero',
                    ExpressionAttributeValues={':zero': 0}
                )
                return {'statusCode': 200, 'headers': cors_headers(),
                        'body': json.dumps({'status': 'success', 'message': 'Pump stats reset to 0'})}

            elif group == 'restarts':
                # Reset ALL restart counters in DynamoDB (reboot_count + clean + unexpected)
                devices_table.update_item(
                    Key={'user_id': user_id, 'device_id': device_id},
                    UpdateExpression='SET reboot_count = :zero, clean_restarts = :zero, unexpected_restarts = :zero',
                    ExpressionAttributeValues={':zero': 0}
                )

                # CRITICAL: Also send MQTT command to ESP32 to reset NVS counters
                # Without this, ESP32 will overwrite DynamoDB values on next telemetry publish
                mac_address = device_id.replace('Polivalka-', '')
                topic = f'Polivalka/{mac_address}/command'
                mqtt_payload = {
                    'command_id': str(uuid.uuid4()),
                    'command': 'admin_reset_counters',
                    'params': {}
                }
                try:
                    iot_client.publish(
                        topic=topic,
                        qos=1,
                        payload=json.dumps(mqtt_payload)
                    )
                    print(f"[INFO] Sent admin_reset_counters to {topic}")
                except Exception as mqtt_err:
                    print(f"[WARN] MQTT publish failed (device may be offline): {mqtt_err}")
                    # Don't fail - DynamoDB is already reset, ESP32 will sync eventually

                return {'statusCode': 200, 'headers': cors_headers(),
                        'body': json.dumps({'status': 'success', 'message': 'All restart counters reset to 0 (ESP32 sync sent)'})}

            else:
                return {'statusCode': 400, 'headers': cors_headers(),
                        'body': json.dumps({'error': f'Unknown group: {group}'})}

        except Exception as e:
            print(f"[ERROR] reset_stats failed: {e}")
            return {'statusCode': 500, 'headers': cors_headers(),
                    'body': json.dumps({'error': str(e)})}

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
    telem_device_id = get_telemetry_device_id(device_id)

    # Data isolation: filter by plant.started_at (unless admin)
    is_admin = user_id in ADMIN_EMAILS
    if not is_admin:
        device_info = get_device_info(device_id, user_id)
        plant = device_info.get('plant', {})
        plant_started_at = plant.get('started_at', 0)
        if plant_started_at > cutoff:
            cutoff = plant_started_at  # Only show data since current plant was assigned

    response = telemetry_table.query(
        KeyConditionExpression=Key('device_id').eq(telem_device_id) &
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
            point = {
                'timestamp': timestamp,
                'moisture_percent': sensor_data.get('moisture_percent'),
                'adc_raw': sensor_data.get('adc_raw')
            }
            # Include sensor2 data if present (resistive sensor J7)
            if 'sensor2_adc' in sensor_data:
                point['sensor2_adc'] = sensor_data.get('sensor2_adc')
            if 'sensor2_percent' in sensor_data:
                point['sensor2_percent'] = sensor_data.get('sensor2_percent')
            history.append(point)

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
    telem_device_id = get_telemetry_device_id(device_id)

    # Data isolation: filter by plant.started_at (unless admin)
    is_admin = user_id in ADMIN_EMAILS
    if not is_admin:
        device_info = get_device_info(device_id, user_id)
        plant = device_info.get('plant', {})
        plant_started_at = plant.get('started_at', 0)
        if plant_started_at > cutoff:
            cutoff = plant_started_at

    response = telemetry_table.query(
        KeyConditionExpression=Key('device_id').eq(telem_device_id) &
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
    """Get latest sensor, battery, system data for device.

    Merges data from two sources:
    1. timestamp=0 record - updated by command responses (iot_rule_response.py)
    2. Recent telemetry records - periodic publishes from ESP32

    For each data type (sensor, battery, system, pump), uses the NEWEST data
    based on timestamp comparison.
    """

    latest = {}
    latest_timestamps = {}  # Track timestamps for each data type
    telem_device_id = get_telemetry_device_id(device_id)

    # First, get the "latest" record (timestamp=0) which has last_update from command responses
    # IMPORTANT: Use telem_device_id (Polivalka-XX) because iot_rule_response.py saves with full ID
    try:
        latest_record = telemetry_table.get_item(
            Key={'device_id': telem_device_id, 'timestamp': 0}
        )
        if 'Item' in latest_record:
            item = latest_record['Item']
            # last_update = time of LAST command response (any command type)
            record_timestamp = int(item.get('last_update', 0))
            if record_timestamp > 0:
                latest['last_update'] = record_timestamp
            # Extract per-type data from timestamp=0 record (saved by iot_rule_response.py)
            # BUG FIX: Use per-type 'updated_at' timestamp instead of generic 'last_update'
            # Without this, a non-sensor command (e.g. stop_pump) bumps last_update
            # but doesn't update sensor data → stale sensor data appears "newer"
            # than real periodic telemetry → shows wrong moisture (e.g. 0% instead of 100%)
            if 'sensor' in item:
                sensor_data = dict(item['sensor'])
                sensor_ts = int(sensor_data.get('updated_at', 0))
                latest['sensor'] = sensor_data
                latest['sensor']['timestamp'] = sensor_ts
                latest_timestamps['sensor'] = sensor_ts

            # Battery from command response (was missing → Refresh battery reverted to stale data)
            if 'battery' in item:
                battery_data = dict(item['battery'])
                battery_ts = int(battery_data.get('updated_at', 0))
                latest['battery'] = battery_data
                latest['battery']['timestamp'] = battery_ts
                latest_timestamps['battery'] = battery_ts

            # System from command response (stored as 'system_data' to avoid DynamoDB reserved word)
            if 'system_data' in item:
                system_data = dict(item['system_data'])
                system_ts = int(system_data.get('updated_at', 0))
                latest['system'] = system_data
                latest['system']['timestamp'] = system_ts
                latest_timestamps['system'] = system_ts
    except Exception as e:
        print(f"Error getting latest record: {e}")

    # Query recent records (schema: device_id + timestamp)
    # Data types stored as top-level Maps: system, pump, sensor, battery
    cutoff = int(time.time()) - 86400  # Last 24 hours

    response = telemetry_table.query(
        KeyConditionExpression=Key('device_id').eq(telem_device_id) &
                               Key('timestamp').gt(cutoff),
        ScanIndexForward=False,  # Newest first
        Limit=100  # Get recent records to find latest of each type
    )

    # Extract latest of each data type - compare timestamps to use NEWEST data
    for item in response.get('Items', []):
        timestamp = int(item.get('timestamp', 0))

        # Check each data type and keep the NEWEST (by timestamp)
        for data_type in ['sensor', 'battery', 'system', 'pump']:
            if data_type in item:
                existing_ts = latest_timestamps.get(data_type, 0)
                # Use this record if it's NEWER than existing data
                if timestamp > existing_ts:
                    data = dict(item[data_type])  # Copy to avoid mutation
                    data['timestamp'] = timestamp  # Add record timestamp to data
                    latest[data_type] = data
                    latest_timestamps[data_type] = timestamp
                    # Update last_update if this record is newer
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
        # Admin: query by device_id via GSI (device may have any user_id in DB)
        response = devices_table.query(
            IndexName='device_id-index',
            KeyConditionExpression=Key('device_id').eq(device_id)
        )
        items = response.get('Items', [])
        return items[0] if items else {}
    else:
        # Regular user: query by user_id + device_id
        response = devices_table.get_item(
            Key={'user_id': user_id, 'device_id': device_id}
        )
        return response.get('Item', {})


def get_local_time_for_timezone(tz_name):
    """Get current local time for a named timezone.

    Uses Python's zoneinfo (standard library, Python 3.9+).
    Handles both IANA (Europe/Warsaw) and POSIX (CET-1CEST) formats.

    Args:
        tz_name: IANA timezone like 'Europe/Warsaw' or POSIX like 'CET-1CEST...'

    Returns:
        tuple: (datetime_str, offset_minutes, tz_used)
    """
    from datetime import datetime, timezone as dt_timezone, timedelta
    import re

    # Complete mapping: POSIX prefix → IANA timezone
    # Covers all timezones from settings.html dropdown
    posix_to_iana = {
        # Europe
        'GMT': 'Europe/London',
        'WET': 'Europe/Lisbon',
        'CET': 'Europe/Warsaw',       # Central European (Poland, Germany, etc)
        'EET': 'Europe/Kiev',         # Eastern European
        'MSK': 'Europe/Moscow',
        'TRT': 'Europe/Istanbul',
        # North America
        'AKST': 'America/Anchorage',
        'PST': 'America/Los_Angeles',
        'MST': 'America/Denver',
        'CST': 'America/Chicago',
        'EST': 'America/New_York',
        'AST': 'America/Puerto_Rico',
        'NST': 'America/St_Johns',
        'HST': 'Pacific/Honolulu',
        # Asia
        'JST': 'Asia/Tokyo',
        'KST': 'Asia/Seoul',
        'IST': 'Asia/Kolkata',        # India (also Israel, but different offset)
        # Australia/Oceania
        'AEST': 'Australia/Sydney',
        'ACST': 'Australia/Adelaide',
        'AWST': 'Australia/Perth',
        'NZST': 'Pacific/Auckland',
        # Africa
        'CAT': 'Africa/Johannesburg',
        'EAT': 'Africa/Nairobi',
        'WAT': 'Africa/Lagos',
    }

    iana_tz = None

    # Check if it's already IANA format (contains '/')
    if '/' in tz_name:
        iana_tz = tz_name
    else:
        # Extract POSIX prefix and map to IANA
        # Handle formats: CET-1CEST, GMT0BST, <TRT>-3, etc.
        prefix_match = re.match(r'^<?([A-Z]+)>?', tz_name)
        if prefix_match:
            prefix = prefix_match.group(1)
            iana_tz = posix_to_iana.get(prefix)

    # Try to use zoneinfo (Python 3.9+, built into AWS Lambda)
    try:
        from zoneinfo import ZoneInfo
        if iana_tz:
            tz = ZoneInfo(iana_tz)
            local_now = datetime.now(tz)
            offset = local_now.utcoffset()
            offset_minutes = int(offset.total_seconds() / 60) if offset else 0
            return (local_now.strftime('%Y-%m-%dT%H:%M:%S'), offset_minutes, iana_tz)
    except Exception as e:
        print(f"zoneinfo failed for {iana_tz}: {e}")

    # Fallback: parse POSIX offset manually (no DST - winter time only)
    offset_minutes = 0
    # Match: CET-1, MSK-3, EST5, <+07>-7, etc.
    match = re.search(r'([+-]?\d+(?::\d+)?)', tz_name)
    if match:
        offset_str = match.group(1)
        if ':' in offset_str:
            hours, mins = map(int, offset_str.split(':'))
            offset_minutes = -hours * 60 - (mins if hours >= 0 else -mins)
        else:
            # POSIX inverts sign: CET-1 means UTC+1
            offset_minutes = -int(offset_str) * 60

    utc_now = datetime.now(dt_timezone.utc)
    local_dt = utc_now + timedelta(minutes=offset_minutes)
    return (local_dt.strftime('%Y-%m-%dT%H:%M:%S'), offset_minutes, f'fallback:{tz_name}')


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


# ============ Admin Device Management Handlers (added 2025-12-06) ============

# AWS IoT client for certificate management (different from iot-data for MQTT!)
iot_mgmt_client = boto3.client('iot', region_name='eu-central-1')


def admin_archive_device(device_id):
    """Archive device - hide from Fleet but keep data flowing"""
    try:
        # Normalize device_id format
        if not device_id.startswith('Polivalka-'):
            device_id = f'Polivalka-{device_id}'

        # Find device to get user_id (query by GSI)
        response = devices_table.query(
            IndexName='device_id-index',
            KeyConditionExpression=Key('device_id').eq(device_id)
        )
        items = response.get('Items', [])
        if not items:
            return {
                'statusCode': 404,
                'headers': cors_headers(),
                'body': json.dumps({'error': f'Device {device_id} not found'})
            }

        device_user_id = items[0].get('user_id')

        # Update device record with archived flag
        devices_table.update_item(
            Key={'user_id': device_user_id, 'device_id': device_id},
            UpdateExpression='SET archived = :true, archived_at = :ts',
            ExpressionAttributeValues={
                ':true': True,
                ':ts': int(time.time())
            }
        )

        print(f"[ADMIN] Device {device_id} archived")
        return {
            'statusCode': 200,
            'headers': cors_headers(),
            'body': json.dumps({'success': True, 'message': f'Device {device_id} archived'})
        }
    except Exception as e:
        print(f"[ADMIN] Error archiving device: {e}")
        return {
            'statusCode': 500,
            'headers': cors_headers(),
            'body': json.dumps({'error': str(e)})
        }


def admin_restore_archive(device_id):
    """Restore device from archive - show on Fleet again"""
    try:
        if not device_id.startswith('Polivalka-'):
            device_id = f'Polivalka-{device_id}'

        # Find device to get user_id (query by GSI)
        response = devices_table.query(
            IndexName='device_id-index',
            KeyConditionExpression=Key('device_id').eq(device_id)
        )
        items = response.get('Items', [])
        if not items:
            return {
                'statusCode': 404,
                'headers': cors_headers(),
                'body': json.dumps({'error': f'Device {device_id} not found'})
            }

        device_user_id = items[0].get('user_id')

        # Remove archived flag
        devices_table.update_item(
            Key={'user_id': device_user_id, 'device_id': device_id},
            UpdateExpression='REMOVE archived, archived_at'
        )

        print(f"[ADMIN] Device {device_id} restored from archive")
        return {
            'statusCode': 200,
            'headers': cors_headers(),
            'body': json.dumps({'success': True, 'message': f'Device {device_id} restored from archive'})
        }
    except Exception as e:
        print(f"[ADMIN] Error restoring device: {e}")
        return {
            'statusCode': 500,
            'headers': cors_headers(),
            'body': json.dumps({'error': str(e)})
        }


def admin_delete_device(device_id):
    """Hard delete device - deactivate certificate and mark as deleted"""
    try:
        if not device_id.startswith('Polivalka-'):
            device_id = f'Polivalka-{device_id}'

        # Find device to get user_id (query by GSI)
        response = devices_table.query(
            IndexName='device_id-index',
            KeyConditionExpression=Key('device_id').eq(device_id)
        )
        items = response.get('Items', [])
        if not items:
            return {
                'statusCode': 404,
                'headers': cors_headers(),
                'body': json.dumps({'error': f'Device {device_id} not found'})
            }

        device_user_id = items[0].get('user_id')

        # 1. Find and deactivate the device's certificate in AWS IoT
        thing_name = device_id
        try:
            # List principals (certificates) attached to the thing
            principals = iot_mgmt_client.list_thing_principals(thingName=thing_name)
            for principal_arn in principals.get('principals', []):
                # Extract certificate ID from ARN
                cert_id = principal_arn.split('/')[-1]
                # Deactivate certificate
                iot_mgmt_client.update_certificate(
                    certificateId=cert_id,
                    newStatus='INACTIVE'
                )
                print(f"[ADMIN] Deactivated certificate {cert_id} for {device_id}")
        except iot_mgmt_client.exceptions.ResourceNotFoundException:
            print(f"[ADMIN] No IoT Thing found for {device_id}, skipping certificate deactivation")

        # 2. Mark device as deleted in DynamoDB (don't actually delete - keep history)
        devices_table.update_item(
            Key={'user_id': device_user_id, 'device_id': device_id},
            UpdateExpression='SET deleted = :true, deleted_at = :ts REMOVE archived, archived_at',
            ExpressionAttributeValues={
                ':true': True,
                ':ts': int(time.time())
            }
        )

        print(f"[ADMIN] Device {device_id} hard deleted (certificate deactivated)")
        return {
            'statusCode': 200,
            'headers': cors_headers(),
            'body': json.dumps({'success': True, 'message': f'Device {device_id} deleted and certificate deactivated'})
        }
    except Exception as e:
        print(f"[ADMIN] Error deleting device: {e}")
        return {
            'statusCode': 500,
            'headers': cors_headers(),
            'body': json.dumps({'error': str(e)})
        }


def admin_restore_deleted(device_id):
    """Restore deleted device - reactivate certificate"""
    try:
        if not device_id.startswith('Polivalka-'):
            device_id = f'Polivalka-{device_id}'

        # Find device to get user_id (query by GSI)
        response = devices_table.query(
            IndexName='device_id-index',
            KeyConditionExpression=Key('device_id').eq(device_id)
        )
        items = response.get('Items', [])
        if not items:
            return {
                'statusCode': 404,
                'headers': cors_headers(),
                'body': json.dumps({'error': f'Device {device_id} not found'})
            }

        device_user_id = items[0].get('user_id')

        # 1. Reactivate certificate in AWS IoT
        thing_name = device_id
        try:
            principals = iot_mgmt_client.list_thing_principals(thingName=thing_name)
            for principal_arn in principals.get('principals', []):
                cert_id = principal_arn.split('/')[-1]
                iot_mgmt_client.update_certificate(
                    certificateId=cert_id,
                    newStatus='ACTIVE'
                )
                print(f"[ADMIN] Reactivated certificate {cert_id} for {device_id}")
        except iot_mgmt_client.exceptions.ResourceNotFoundException:
            print(f"[ADMIN] No IoT Thing found for {device_id}")

        # 2. Remove deleted flag from DynamoDB
        devices_table.update_item(
            Key={'user_id': device_user_id, 'device_id': device_id},
            UpdateExpression='REMOVE deleted, deleted_at'
        )

        print(f"[ADMIN] Device {device_id} restored (certificate reactivated)")
        return {
            'statusCode': 200,
            'headers': cors_headers(),
            'body': json.dumps({'success': True, 'message': f'Device {device_id} restored and certificate reactivated'})
        }
    except Exception as e:
        print(f"[ADMIN] Error restoring device: {e}")
        return {
            'statusCode': 500,
            'headers': cors_headers(),
            'body': json.dumps({'error': str(e)})
        }


def admin_get_archived_devices():
    """Get list of archived devices"""
    try:
        # Scan for archived devices
        response = devices_table.scan(
            FilterExpression='archived = :true',
            ExpressionAttributeValues={':true': True}
        )

        devices = []
        for item in response.get('Items', []):
            devices.append({
                'device_id': item['device_id'],
                'name': item.get('device_name', item['device_id']),
                'location': item.get('location', '—'),
                'archived_at': item.get('archived_at')
            })

        return {
            'statusCode': 200,
            'headers': cors_headers(),
            'body': json.dumps(devices, cls=DecimalEncoder)
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': cors_headers(),
            'body': json.dumps({'error': str(e)})
        }


def admin_get_deleted_devices():
    """Get list of deleted devices"""
    try:
        # Scan for deleted devices
        response = devices_table.scan(
            FilterExpression='deleted = :true',
            ExpressionAttributeValues={':true': True}
        )

        devices = []
        for item in response.get('Items', []):
            devices.append({
                'device_id': item['device_id'],
                'name': item.get('device_name', item['device_id']),
                'location': item.get('location', '—'),
                'deleted_at': item.get('deleted_at')
            })

        return {
            'statusCode': 200,
            'headers': cors_headers(),
            'body': json.dumps(devices, cls=DecimalEncoder)
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': cors_headers(),
            'body': json.dumps({'error': str(e)})
        }


def admin_get_users():
    """Get list of registered users (admin only)"""
    try:
        # Access polivalka_users table
        users_table = dynamodb.Table('polivalka_users')
        response = users_table.scan()

        users = []
        for item in response.get('Items', []):
            users.append({
                'email': item.get('email', '?'),
                'verified': item.get('verified', False),
                'is_admin': item.get('is_admin', False),
                'devices': item.get('devices', []),
                'created_at': item.get('created_at', ''),
                'last_login': item.get('last_login', '')
            })

        # Sort by created_at descending (newest first)
        users.sort(key=lambda x: x.get('created_at', ''), reverse=True)

        return {
            'statusCode': 200,
            'headers': cors_headers(),
            'body': json.dumps(users)
        }
    except Exception as e:
        print(f"[Admin] Error getting users: {e}")
        return {
            'statusCode': 500,
            'headers': cors_headers(),
            'body': json.dumps({'error': str(e)})
        }


# ============ User Whitelist Check Functions (Security Migration - 2026-01-20) ============
# These are NOT admin-only - any authenticated user can use them

def check_whitelist_status(user_id, event, origin):
    """GET /whitelist/check?device_id=XXX - Check if user can claim a device"""
    try:
        # Get device_id from query params
        query_params = event.get('queryStringParameters') or {}
        device_id = query_params.get('device_id', '')

        if not device_id:
            return {
                'statusCode': 400,
                'headers': cors_headers(origin),
                'body': json.dumps({'error': 'device_id required'})
            }

        # Ensure full device_id format: Polivalka-XXXXXX
        device_id = device_id.upper()
        if not device_id.startswith('POLIVALKA-'):
            device_id = f'Polivalka-{device_id}'
        else:
            device_id = f'Polivalka-{device_id[10:]}'  # Normalize case

        # Check whitelist for user
        whitelist_table = dynamodb.Table('polivalka_admin_users')
        response = whitelist_table.get_item(Key={'email': user_id})

        if 'Item' not in response:
            # User not in whitelist
            return {
                'statusCode': 200,
                'headers': cors_headers(origin),
                'body': json.dumps({
                    'allowed': False,
                    'reason': 'not_whitelisted',
                    'message': 'You are not in the whitelist. Submit a claim request.'
                })
            }

        user_data = response['Item']
        status = user_data.get('status', 'active')

        if status == 'banned':
            return {
                'statusCode': 200,
                'headers': cors_headers(origin),
                'body': json.dumps({
                    'allowed': False,
                    'reason': 'banned',
                    'message': 'Your account has been banned. Contact admin.'
                })
            }

        if status == 'suspended':
            return {
                'statusCode': 200,
                'headers': cors_headers(origin),
                'body': json.dumps({
                    'allowed': False,
                    'reason': 'suspended',
                    'message': 'Your account is suspended. Contact admin.'
                })
            }

        # User is active - check if device is assigned
        devices = user_data.get('devices', [])
        if device_id in devices:
            return {
                'statusCode': 200,
                'headers': cors_headers(origin),
                'body': json.dumps({
                    'allowed': True,
                    'reason': 'whitelisted',
                    'message': 'Device is assigned to you.'
                })
            }
        else:
            return {
                'statusCode': 200,
                'headers': cors_headers(origin),
                'body': json.dumps({
                    'allowed': False,
                    'reason': 'device_not_assigned',
                    'message': f'Device {device_id} is not assigned to you. Contact admin.'
                })
            }

    except Exception as e:
        print(f"[Whitelist] Error checking status: {e}")
        return {
            'statusCode': 500,
            'headers': cors_headers(origin),
            'body': json.dumps({'error': str(e)})
        }


def create_user_claim(user_id, event, origin):
    """POST /claims - Create new claim request"""
    try:
        body = json.loads(event.get('body', '{}'))
        # Ensure full device_id format: Polivalka-XXXXXX
        raw_device_id = body.get('device_id', '').upper()
        if not raw_device_id:
            device_id = ''
        elif raw_device_id.startswith('POLIVALKA-'):
            device_id = f'Polivalka-{raw_device_id[10:]}'  # Normalize case
        else:
            device_id = f'Polivalka-{raw_device_id}'

        if not device_id:
            return {
                'statusCode': 400,
                'headers': cors_headers(origin),
                'body': json.dumps({'error': 'device_id required'})
            }

        claims_table = dynamodb.Table('polivalka_admin_claims')

        # Check if claim already exists
        response = claims_table.scan(
            FilterExpression='email = :email AND device_id = :device_id AND #s = :status',
            ExpressionAttributeNames={'#s': 'status'},
            ExpressionAttributeValues={
                ':email': user_id,
                ':device_id': device_id,
                ':status': 'pending'
            }
        )

        if response.get('Items'):
            return {
                'statusCode': 409,
                'headers': cors_headers(origin),
                'body': json.dumps({
                    'success': False,
                    'message': 'You already have a pending request for this device.'
                })
            }

        # Create new claim
        import datetime
        claim_id = str(uuid.uuid4())

        claims_table.put_item(Item={
            'claim_id': claim_id,
            'email': user_id,
            'device_id': device_id,
            'status': 'pending',
            'created_at': datetime.datetime.now().isoformat()
        })

        return {
            'statusCode': 201,
            'headers': cors_headers(origin),
            'body': json.dumps({
                'success': True,
                'claim_id': claim_id,
                'message': 'Claim request submitted. Admin will review your request.'
            })
        }

    except Exception as e:
        print(f"[Claims] Error creating claim: {e}")
        return {
            'statusCode': 500,
            'headers': cors_headers(origin),
            'body': json.dumps({'error': str(e)})
        }


# ============ Whitelist Management Functions (Security Migration - 2026-01-20) ============
# Data moved from public GitHub JSON files to private DynamoDB

def admin_get_whitelist():
    """GET /admin/whitelist - List all whitelisted users"""
    try:
        whitelist_table = dynamodb.Table('polivalka_admin_users')
        response = whitelist_table.scan()

        users = {}
        for item in response.get('Items', []):
            email = item.get('email')
            users[email] = {
                'status': item.get('status', 'active'),
                'devices': item.get('devices', []),
                'added_at': item.get('added_at', '')
            }

        return {
            'statusCode': 200,
            'headers': cors_headers(),
            'body': json.dumps({'users': users})
        }
    except Exception as e:
        print(f"[Admin] Error getting whitelist: {e}")
        return {
            'statusCode': 500,
            'headers': cors_headers(),
            'body': json.dumps({'error': str(e)})
        }


def admin_add_whitelist(event):
    """POST /admin/whitelist - Add user to whitelist"""
    try:
        body = json.loads(event.get('body', '{}'))
        email = body.get('email')

        if not email:
            return {
                'statusCode': 400,
                'headers': cors_headers(),
                'body': json.dumps({'error': 'Email required'})
            }

        whitelist_table = dynamodb.Table('polivalka_admin_users')

        # Check if already exists
        existing = whitelist_table.get_item(Key={'email': email})
        if 'Item' in existing:
            return {
                'statusCode': 409,
                'headers': cors_headers(),
                'body': json.dumps({'error': 'User already in whitelist'})
            }

        # Add new user
        import datetime
        whitelist_table.put_item(Item={
            'email': email,
            'status': body.get('status', 'active'),
            'devices': body.get('devices', []),
            'added_at': datetime.datetime.now().strftime('%Y-%m-%d')
        })

        return {
            'statusCode': 201,
            'headers': cors_headers(),
            'body': json.dumps({'success': True, 'email': email})
        }
    except Exception as e:
        print(f"[Admin] Error adding to whitelist: {e}")
        return {
            'statusCode': 500,
            'headers': cors_headers(),
            'body': json.dumps({'error': str(e)})
        }


def admin_update_whitelist(email, event):
    """PUT /admin/whitelist/{email} - Update whitelist user"""
    try:
        body = json.loads(event.get('body', '{}'))

        whitelist_table = dynamodb.Table('polivalka_admin_users')

        # Check if exists
        existing = whitelist_table.get_item(Key={'email': email})
        if 'Item' not in existing:
            return {
                'statusCode': 404,
                'headers': cors_headers(),
                'body': json.dumps({'error': 'User not found in whitelist'})
            }

        # Update fields
        update_expr = []
        expr_values = {}

        if 'status' in body:
            update_expr.append('status = :status')
            expr_values[':status'] = body['status']

        if 'devices' in body:
            update_expr.append('devices = :devices')
            expr_values[':devices'] = body['devices']

        if not update_expr:
            return {
                'statusCode': 400,
                'headers': cors_headers(),
                'body': json.dumps({'error': 'No fields to update'})
            }

        whitelist_table.update_item(
            Key={'email': email},
            UpdateExpression='SET ' + ', '.join(update_expr),
            ExpressionAttributeValues=expr_values
        )

        return {
            'statusCode': 200,
            'headers': cors_headers(),
            'body': json.dumps({'success': True, 'email': email})
        }
    except Exception as e:
        print(f"[Admin] Error updating whitelist: {e}")
        return {
            'statusCode': 500,
            'headers': cors_headers(),
            'body': json.dumps({'error': str(e)})
        }


def admin_delete_whitelist(email):
    """DELETE /admin/whitelist/{email} - Remove from whitelist"""
    try:
        whitelist_table = dynamodb.Table('polivalka_admin_users')

        # Check if exists
        existing = whitelist_table.get_item(Key={'email': email})
        if 'Item' not in existing:
            return {
                'statusCode': 404,
                'headers': cors_headers(),
                'body': json.dumps({'error': 'User not found in whitelist'})
            }

        whitelist_table.delete_item(Key={'email': email})

        return {
            'statusCode': 200,
            'headers': cors_headers(),
            'body': json.dumps({'success': True, 'email': email})
        }
    except Exception as e:
        print(f"[Admin] Error deleting from whitelist: {e}")
        return {
            'statusCode': 500,
            'headers': cors_headers(),
            'body': json.dumps({'error': str(e)})
        }


# ============ Claims Management Functions ============

def admin_get_claims():
    """GET /admin/claims - List all pending claims"""
    try:
        claims_table = dynamodb.Table('polivalka_admin_claims')
        response = claims_table.scan()

        claims = []
        for item in response.get('Items', []):
            claims.append({
                'claim_id': item.get('claim_id'),
                'email': item.get('email'),
                'device_id': item.get('device_id'),
                'status': item.get('status', 'pending'),
                'created_at': item.get('created_at', '')
            })

        # Sort by created_at descending (newest first)
        claims.sort(key=lambda x: x.get('created_at', ''), reverse=True)

        return {
            'statusCode': 200,
            'headers': cors_headers(),
            'body': json.dumps({'claims': claims})
        }
    except Exception as e:
        print(f"[Admin] Error getting claims: {e}")
        return {
            'statusCode': 500,
            'headers': cors_headers(),
            'body': json.dumps({'error': str(e)})
        }


def admin_create_claim(event):
    """POST /admin/claims - Create new claim"""
    try:
        body = json.loads(event.get('body', '{}'))
        email = body.get('email')
        device_id = body.get('device_id')

        if not email or not device_id:
            return {
                'statusCode': 400,
                'headers': cors_headers(),
                'body': json.dumps({'error': 'Email and device_id required'})
            }

        claims_table = dynamodb.Table('polivalka_admin_claims')

        import datetime
        claim_id = str(uuid.uuid4())

        claims_table.put_item(Item={
            'claim_id': claim_id,
            'email': email,
            'device_id': device_id,
            'status': 'pending',
            'created_at': datetime.datetime.now().isoformat()
        })

        return {
            'statusCode': 201,
            'headers': cors_headers(),
            'body': json.dumps({'success': True, 'claim_id': claim_id})
        }
    except Exception as e:
        print(f"[Admin] Error creating claim: {e}")
        return {
            'statusCode': 500,
            'headers': cors_headers(),
            'body': json.dumps({'error': str(e)})
        }


def admin_update_claim(claim_id, event):
    """PUT /admin/claims/{id} - Update claim (approve/reject)"""
    try:
        body = json.loads(event.get('body', '{}'))
        new_status = body.get('status')

        if new_status not in ['approved', 'rejected', 'pending']:
            return {
                'statusCode': 400,
                'headers': cors_headers(),
                'body': json.dumps({'error': 'Invalid status. Use: approved, rejected, pending'})
            }

        claims_table = dynamodb.Table('polivalka_admin_claims')

        # Check if exists
        existing = claims_table.get_item(Key={'claim_id': claim_id})
        if 'Item' not in existing:
            return {
                'statusCode': 404,
                'headers': cors_headers(),
                'body': json.dumps({'error': 'Claim not found'})
            }

        claims_table.update_item(
            Key={'claim_id': claim_id},
            UpdateExpression='SET #s = :status',
            ExpressionAttributeNames={'#s': 'status'},
            ExpressionAttributeValues={':status': new_status}
        )

        return {
            'statusCode': 200,
            'headers': cors_headers(),
            'body': json.dumps({'success': True, 'claim_id': claim_id, 'status': new_status})
        }
    except Exception as e:
        print(f"[Admin] Error updating claim: {e}")
        return {
            'statusCode': 500,
            'headers': cors_headers(),
            'body': json.dumps({'error': str(e)})
        }


def admin_delete_claim(claim_id):
    """DELETE /admin/claims/{id} - Delete claim"""
    try:
        claims_table = dynamodb.Table('polivalka_admin_claims')

        # Check if exists
        existing = claims_table.get_item(Key={'claim_id': claim_id})
        if 'Item' not in existing:
            return {
                'statusCode': 404,
                'headers': cors_headers(),
                'body': json.dumps({'error': 'Claim not found'})
            }

        claims_table.delete_item(Key={'claim_id': claim_id})

        return {
            'statusCode': 200,
            'headers': cors_headers(),
            'body': json.dumps({'success': True, 'claim_id': claim_id})
        }
    except Exception as e:
        print(f"[Admin] Error deleting claim: {e}")
        return {
            'statusCode': 500,
            'headers': cors_headers(),
            'body': json.dumps({'error': str(e)})
        }


# ============ Device History Functions ============

def admin_get_history(device_id):
    """GET /admin/history/{device_id} - Get device history"""
    try:
        # device_id format: "Polivalka-BC67E9" (standardized everywhere)
        history_table = dynamodb.Table('polivalka_admin_history')

        # Query all events for this device
        response = history_table.query(
            KeyConditionExpression=Key('device_id').eq(device_id)
        )

        events = []
        for item in response.get('Items', []):
            events.append({
                'timestamp': item.get('timestamp'),
                'event': item.get('event'),
                'user_email': item.get('user_email')
            })

        # Sort by timestamp ascending (oldest first)
        events.sort(key=lambda x: x.get('timestamp', ''))

        return {
            'statusCode': 200,
            'headers': cors_headers(),
            'body': json.dumps({'device_id': device_id, 'events': events})
        }
    except Exception as e:
        print(f"[Admin] Error getting history: {e}")
        return {
            'statusCode': 500,
            'headers': cors_headers(),
            'body': json.dumps({'error': str(e)})
        }


def admin_add_history(event):
    """POST /admin/history - Add history entry"""
    try:
        body = json.loads(event.get('body', '{}'))
        # device_id format: "Polivalka-BC67E9" (standardized everywhere)
        device_id = body.get('device_id', '')
        event_type = body.get('event')
        user_email = body.get('user_email')

        if not device_id or not event_type:
            return {
                'statusCode': 400,
                'headers': cors_headers(),
                'body': json.dumps({'error': 'device_id and event required'})
            }

        history_table = dynamodb.Table('polivalka_admin_history')

        import datetime
        timestamp = datetime.datetime.now().isoformat()

        item = {
            'device_id': device_id,
            'timestamp': timestamp,
            'event': event_type
        }
        if user_email:
            item['user_email'] = user_email

        history_table.put_item(Item=item)

        return {
            'statusCode': 201,
            'headers': cors_headers(),
            'body': json.dumps({'success': True, 'device_id': device_id, 'timestamp': timestamp})
        }
    except Exception as e:
        print(f"[Admin] Error adding history: {e}")
        return {
            'statusCode': 500,
            'headers': cors_headers(),
            'body': json.dumps({'error': str(e)})
        }


# SECURITY: Allowed origins for CORS (updated 2025-12-06)
ALLOWED_ORIGINS = [
    'https://gt3max.github.io',
    'https://plantapp.pro',
    'https://www.plantapp.pro',
    'http://localhost:8080',  # Local development
    'http://127.0.0.1:8080',
]

def cors_headers(origin=None):
    """CORS headers for API Gateway - restricted to allowed origins"""
    # Use passed origin, or fall back to global _current_origin from lambda_handler
    effective_origin = origin or _current_origin

    # If origin in allowed list, echo it back. Otherwise use primary domain
    if effective_origin and effective_origin in ALLOWED_ORIGINS:
        allowed_origin = effective_origin
    else:
        allowed_origin = 'https://plantapp.pro'  # Primary domain

    return {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': allowed_origin,
        'Access-Control-Allow-Headers': 'Content-Type,Authorization',
        'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
        'Access-Control-Allow-Credentials': 'true'
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
            'message': item.get('message'),
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
                sensor2 = result.get('sensor2', {})
                pump = result.get('pump', {})
                system = result.get('system', {})

                # Battery: use command response (real-time from device).
                # Previous bug (80% vs 99%) was caused by stale ts=0 data in
                # get_latest_telemetry(), NOT by command response being wrong.
                # Command response matches periodic telemetry at same timestamp.
                battery = result.get('battery', {})
                # Convert battery percent -1 to null (indicates AC power, no battery)
                if battery.get('percent') == -1 or battery.get('percent') == -1.0:
                    battery = {**battery, 'percent': None}

                return {
                    'statusCode': 200,
                    'headers': cors_headers(),
                    'body': json.dumps({
                        'moisture_pct': sensor.get('moisture'),
                        'adc_raw': sensor.get('adc'),
                        'percent_float': sensor.get('percent_float'),
                        'sensor_calibration': sensor.get('calibration'),
                        # Sensor2 (J7 resistive) - may not be present
                        'sensor2_adc': sensor2.get('adc') if sensor2 else None,
                        'sensor2_percent': sensor2.get('percent') if sensor2 else None,
                        'sensor2_percent_float': sensor2.get('percent_float') if sensor2 else None,
                        # Battery
                        'battery': battery if battery else None,
                        # Pump
                        'pump_running': pump.get('running', False),
                        'pump_calibration': pump.get('calibration'),
                        'pump_speed': pump.get('speed'),
                        # System
                        'mode': system.get('mode', 'manual'),
                        'state': system.get('state', 'DISABLED'),
                        'firmware_version': system.get('firmware'),
                        'reboot_count': system.get('reboot_count'),
                        'clean_restarts': system.get('clean_restarts'),
                        'unexpected_restarts': system.get('unexpected_restarts'),
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

        # CloudFront download URL — short and stable (no query params)
        # S3 stays private, CloudFront OAI provides access
        download_url = f"https://{FIRMWARE_CDN_DOMAIN}/{filename}"

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

        # 2. Get telemetry (last 7 days — matches trends.html Activity tab)
        cutoff = int(time.time()) - 604800  # Last 7 days
        telem_device_id = get_telemetry_device_id(device_id)

        # Data isolation: filter by plant.started_at (unless admin)
        is_admin = user_id in ADMIN_EMAILS
        if not is_admin:
            device_info = get_device_info(device_id, user_id)
            plant = device_info.get('plant', {})
            plant_started_at = plant.get('started_at', 0)
            if plant_started_at > cutoff:
                cutoff = plant_started_at
        telem_response = telemetry_table.query(
            KeyConditionExpression=Key('device_id').eq(telem_device_id) & Key('timestamp').gt(cutoff),
            ScanIndexForward=False  # Sort DESC
        )

        # Process all telemetry events (system, pump, sensor, battery)
        prev_firmware_version = None
        # Track reboot info to detect ACTUAL reboots (not just heartbeats)
        # When iterating DESC: prev = newer record, curr = older record
        # When reboot_count changes, use prev values (from the NEW boot session)
        prev_reboot_count = None
        prev_boot_type = None
        prev_previous_version = None
        prev_firmware_version = None
        prev_reset_reason = None
        prev_timestamp = None

        for telem in telem_response.get('Items', []):

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
                previous_version = system_data.get('previous_version')
                firmware_version = system_data.get('firmware_version')

                # Check for reboot events - ONLY when reboot_count CHANGES
                # (Iterating DESC: newest first, so we detect when count differs from previous)
                # When detected, use PREV values (from newer record = actual boot info)
                is_new_reboot = (reboot_count is not None and
                                 prev_reboot_count is not None and
                                 reboot_count != prev_reboot_count)

                if is_new_reboot and prev_boot_type and prev_boot_type != 'UNKNOWN':
                    # This is an ACTUAL reboot (reboot_count changed)
                    # Use prev values (from the NEWER record = the actual boot)
                    # prev_reboot_count is the NEW count, reboot_count is the OLD count
                    use_boot_type = prev_boot_type
                    use_reset_reason = prev_reset_reason
                    use_reboot_count = prev_reboot_count
                    use_timestamp = prev_timestamp if prev_timestamp else ts

                    # Handle all ESP32 boot types
                    if use_boot_type == 'OTA_BOOT':
                        # Include version transition if available
                        ver_info = ""
                        if prev_previous_version and prev_firmware_version:
                            ver_info = f" ({prev_previous_version} → {prev_firmware_version})"
                        elif prev_firmware_version:
                            ver_info = f" → {prev_firmware_version}"
                        activity_items.append({
                            'timestamp': use_timestamp,
                            'type': 'OTA',
                            'level': 'INFO',
                            'component': 'OTA_UPDATE',
                            'message': f"🔄 OTA Update completed{ver_info} (reboot #{use_reboot_count})",
                            'reset_reason': use_reset_reason,
                            'boot_type': use_boot_type
                        })

                    elif use_boot_type == 'CRASH_BOOT':
                        activity_items.append({
                            'timestamp': use_timestamp,
                            'type': 'REBOOT',
                            'level': 'WARNING',
                            'component': 'SYSTEM',
                            'message': f"💀 Device crashed: {use_reset_reason} (reboot #{use_reboot_count})",
                            'reset_reason': use_reset_reason,
                            'boot_type': use_boot_type
                        })

                    elif use_boot_type == 'BROWNOUT_BOOT':
                        activity_items.append({
                            'timestamp': use_timestamp,
                            'type': 'REBOOT',
                            'level': 'WARNING',
                            'component': 'BATTERY',
                            'message': f"🔋 Low battery restart (reboot #{use_reboot_count})",
                            'reset_reason': use_reset_reason,
                            'boot_type': use_boot_type
                        })

                    elif use_boot_type == 'POWER_ON':
                        activity_items.append({
                            'timestamp': use_timestamp,
                            'type': 'REBOOT',
                            'level': 'INFO',
                            'component': 'SYSTEM',
                            'message': f"⚡ Power on (reboot #{use_reboot_count})",
                            'reset_reason': use_reset_reason,
                            'boot_type': use_boot_type
                        })

                    elif use_boot_type == 'REBOOT':
                        activity_items.append({
                            'timestamp': use_timestamp,
                            'type': 'REBOOT',
                            'level': 'INFO',
                            'component': 'SYSTEM',
                            'message': f"🔄 Manual restart (reboot #{use_reboot_count})",
                            'reset_reason': use_reset_reason,
                            'boot_type': use_boot_type
                        })

                    elif use_boot_type == 'DEEPSLEEP':
                        activity_items.append({
                            'timestamp': use_timestamp,
                            'type': 'REBOOT',
                            'level': 'INFO',
                            'component': 'SYSTEM',
                            'message': f"😴 Wake from deep sleep (reboot #{use_reboot_count})",
                            'reset_reason': use_reset_reason,
                            'boot_type': use_boot_type
                        })

                    elif use_boot_type == 'LOW_POWER_WAKE':
                        # Device was in Low Power Mode (battery < 10%) and woke up
                        # Either battery charged to 20%+ or charger was connected
                        activity_items.append({
                            'timestamp': use_timestamp,
                            'type': 'REBOOT',
                            'level': 'WARNING',
                            'component': 'BATTERY',
                            'message': f"🔋 Exited Low Power Mode (reboot #{use_reboot_count})",
                            'reset_reason': use_reset_reason,
                            'boot_type': use_boot_type
                        })

                    elif use_boot_type == 'SYSTEM_BOOT':
                        # Fallback for rare reset reasons (SDIO, EXT, UNKNOWN)
                        activity_items.append({
                            'timestamp': use_timestamp,
                            'type': 'REBOOT',
                            'level': 'INFO',
                            'component': 'SYSTEM',
                            'message': f"🔧 System boot: {use_reset_reason} (reboot #{use_reboot_count})",
                            'reset_reason': use_reset_reason,
                            'boot_type': use_boot_type
                        })

                # Update prev values for next iteration
                # Save boot_type only if it's meaningful (not UNKNOWN)
                if reboot_count is not None:
                    prev_reboot_count = reboot_count
                if boot_type and boot_type != 'UNKNOWN':
                    prev_boot_type = boot_type
                    prev_reset_reason = reset_reason
                    prev_timestamp = ts
                if previous_version:
                    prev_previous_version = previous_version
                if firmware_version:
                    prev_firmware_version = firmware_version

                # Skip normal system heartbeats (no mode change tracking needed)
                # They just clutter the activity log

            # Parse pump events
            if 'pump' in telem:
                pump_data = telem.get('pump', {})
                action = pump_data.get('action')
                duration = pump_data.get('duration_sec', 0)
                volume = pump_data.get('volume_ml', 0)
                mode = pump_data.get('mode', 'manual')
                is_microprime = pump_data.get('is_microprime', False)

                # Build descriptive message
                # Microprime = flag + short duration (≤20s). Long pumps with stale flag = normal watering.
                if is_microprime and duration is not None and int(duration) <= 20:
                    source = 'microprime'
                    emoji_start = '🔧'
                    emoji_stop = '🔧'
                elif mode == 'sensor':
                    source = 'sensor'
                    emoji_start = '🌱'
                    emoji_stop = '🌱'
                elif mode == 'timer':
                    source = 'timer'
                    emoji_start = '⏰'
                    emoji_stop = '⏰'
                else:
                    source = 'manual'
                    emoji_start = '💧'
                    emoji_stop = '🛑'

                if action == 'start':
                    activity_items.append({
                        'timestamp': ts,
                        'type': 'PUMP',
                        'level': 'INFO',
                        'component': 'PUMP',
                        'message': f"{emoji_start} Pump started ({duration}s, {volume}ml)",
                        'duration_sec': duration,
                        'volume_ml': volume,
                        'mode': mode,
                        'source': source
                    })
                elif action == 'stop':
                    activity_items.append({
                        'timestamp': ts,
                        'type': 'PUMP',
                        'level': 'INFO',
                        'component': 'PUMP',
                        'message': f"{emoji_stop} Pump stopped ({duration}s, {volume}ml)",
                        'duration_sec': duration,
                        'volume_ml': volume,
                        'mode': mode,
                        'source': source
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

        # 4. Limit to 500 most recent (enough for 7 days at ~50-70 events/day)
        activity_items = activity_items[:500]

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

                # Extract logs array (ESP32 sends data inside 'data' key)
                data = result.get('data', result)  # Fallback to result itself
                logs = data.get('logs', [])
                count = data.get('count', 0)
                uptime_ms = data.get('uptime_ms', 0)

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
    """Find device in any user's collection (query by GSI)"""
    try:
        response = devices_table.query(
            IndexName='device_id-index',
            KeyConditionExpression=Key('device_id').eq(device_id)
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
