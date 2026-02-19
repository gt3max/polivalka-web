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
    # Note: uses actual email only (not 'admin' which is the user_id, not an email)
    if email == 'mrmaximshurigin@gmail.com':
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

            # Get toxicity based on family
            toxicity_data = TOXIC_FAMILIES.get(family_name)
            toxicity = None
            if toxicity_data:
                toxicity = {
                    'poisonous_to_pets': toxicity_data['pets'],
                    'poisonous_to_humans': toxicity_data['humans'],
                    'toxicity_note': toxicity_data['note']
                }

            results.append({
                'id': species.get('scientificNameWithoutAuthor', '').lower().replace(' ', '_'),
                'scientific': species.get('scientificNameWithoutAuthor', ''),
                'commonNames': species.get('commonNames', [])[:3],
                'family': family_name,
                'genus': genus_info.get('scientificNameWithoutAuthor', ''),
                'score': round(r.get('score', 0) * 100, 1),
                'images': [
                    img.get('url', {}).get('m', '') or img.get('url', {}).get('s', '') or img.get('url', {}).get('o', '')
                    for img in r.get('images', [])[:3]
                ],
                'care': {
                    'preset': preset['name'],
                    'start_pct': preset['start_pct'],
                    'stop_pct': preset['stop_pct'],
                    'watering': preset['watering_frequency'],
                    'light': preset['light'],
                    'temperature': preset['temperature'],
                    'humidity': preset['humidity'],
                    'tips': preset['tips']
                },
                'toxicity': toxicity
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


# Family to preset mapping for houseplants (76 families)
FAMILY_PRESETS = {
    # ===== Tropical - high humidity, frequent watering =====
    'Araceae': 'tropical',         # Monstera, Philodendron, Pothos, Alocasia, Anthurium, Spathiphyllum
    'Marantaceae': 'tropical',     # Calathea, Maranta, Stromanthe, Ctenanthe
    'Bromeliaceae': 'tropical',    # Bromeliads, Tillandsia (Air Plants), Aechmea
    'Gesneriaceae': 'tropical',    # African Violet (Saintpaulia), Streptocarpus
    'Piperaceae': 'tropical',      # Peperomia, Piper
    'Polypodiaceae': 'tropical',   # Ferns (Microsorum, Polypodium)
    'Pteridaceae': 'tropical',     # Ferns (Adiantum/Maidenhair, Pteris)
    'Commelinaceae': 'tropical',   # Tradescantia, Callisia, Zebrina
    'Acanthaceae': 'tropical',     # Fittonia, Aphelandra, Crossandra
    'Musaceae': 'tropical',        # Musa (Banana plant)
    'Heliconiaceae': 'tropical',   # Heliconia
    'Zingiberaceae': 'tropical',   # Curcuma, Zingiber (Ginger)
    'Costaceae': 'tropical',       # Costus (Spiral ginger)
    'Davalliaceae': 'tropical',    # Davallia (Rabbit's foot fern)
    'Aspleniaceae': 'tropical',    # Asplenium (Bird's nest fern)
    'Nephrolepidaceae': 'tropical', # Nephrolepis (Boston fern)
    'Dryopteridaceae': 'tropical', # Shield ferns
    'Blechnaceae': 'tropical',     # Hard ferns
    'Pandanaceae': 'tropical',     # Pandanus (Screw pine)
    'Passifloraceae': 'tropical',  # Passiflora (Passion flower)
    'Nepenthaceae': 'tropical',    # Nepenthes (Pitcher plant)
    'Sarraceniaceae': 'tropical',  # Sarracenia (Pitcher plant)
    'Droseraceae': 'tropical',     # Drosera (Sundew)
    'Cannaceae': 'tropical',       # Canna lily

    # ===== Succulents - infrequent watering, drought tolerant =====
    'Cactaceae': 'succulents',     # All cacti
    'Crassulaceae': 'succulents',  # Echeveria, Sedum, Crassula (Jade), Kalanchoe
    'Asphodelaceae': 'succulents', # Aloe, Haworthia, Gasteria
    'Aizoaceae': 'succulents',     # Lithops (Living stones)
    'Euphorbiaceae': 'succulents', # Euphorbia, Codiaeum (Croton)
    'Portulacaceae': 'succulents', # Portulaca
    'Didiereaceae': 'succulents',  # Alluaudia (Madagascar plants)

    # ===== Herbs - moderate, consistent moisture =====
    'Lamiaceae': 'herbs',          # Basil, Mint, Rosemary, Lavender, Coleus
    'Apiaceae': 'herbs',           # Parsley, Cilantro, Dill
    'Lauraceae': 'herbs',          # Laurus (Bay laurel)
    'Poaceae': 'herbs',            # Lemongrass, ornamental grasses

    # ===== Standard - average watering (default for most) =====
    'Moraceae': 'standard',        # Ficus (Fiddle Leaf, Rubber Plant, Weeping Fig)
    'Asparagaceae': 'standard',    # Sansevieria, Dracaena, Yucca, Chlorophytum (Spider Plant)
    'Araliaceae': 'standard',      # Schefflera, Hedera (Ivy), Fatsia
    'Rutaceae': 'standard',        # Citrus
    'Apocynaceae': 'standard',     # Hoya, Adenium, Plumeria
    'Orchidaceae': 'standard',     # Phalaenopsis, Paphiopedilum
    'Begoniaceae': 'standard',     # Begonia (various)
    'Malvaceae': 'standard',       # Hibiscus, Abutilon
    'Arecaceae': 'standard',       # Palms (Areca, Parlor, Kentia, Majesty)
    'Urticaceae': 'standard',      # Pilea (Chinese Money Plant, Aluminum Plant)
    'Amaryllidaceae': 'standard',  # Amaryllis, Hippeastrum, Clivia
    'Rubiaceae': 'standard',       # Gardenia, Coffea (Coffee plant)
    'Oleaceae': 'standard',        # Jasminum (Jasmine), Olea (Olive)
    'Geraniaceae': 'standard',     # Pelargonium (Geranium)
    'Oxalidaceae': 'standard',     # Oxalis (Shamrock plant)
    'Strelitziaceae': 'standard',  # Strelitzia (Bird of Paradise)
    'Solanaceae': 'standard',      # Capsicum, Solanum
    'Liliaceae': 'standard',       # Lilium (Lily)
    'Primulaceae': 'standard',     # Cyclamen, Primula
    'Rosaceae': 'standard',        # Rosa (miniature roses)
    'Hydrangeaceae': 'standard',   # Hydrangea
    'Myrtaceae': 'standard',       # Eucalyptus, Myrtus, Callistemon
    'Asteraceae': 'standard',      # Chrysanthemum, Gerbera, Senecio
    'Amaranthaceae': 'standard',   # Iresine, Alternanthera, Celosia
    'Nyctaginaceae': 'standard',   # Bougainvillea
    'Ericaceae': 'standard',       # Azalea, Rhododendron
    'Cycadaceae': 'standard',      # Cycas (Sago palm)
    'Zamiaceae': 'standard',       # Zamia
    'Vitaceae': 'standard',        # Cissus (Grape Ivy)
    'Onagraceae': 'standard',      # Fuchsia
    'Theaceae': 'standard',        # Camellia
    'Balsaminaceae': 'standard',   # Impatiens
    'Convolvulaceae': 'standard',  # Ipomoea (Sweet potato vine)
    'Verbenaceae': 'standard',     # Lantana
    'Ranunculaceae': 'standard',   # Clematis, Ranunculus
    'Plantaginaceae': 'standard',  # Digitalis (Foxglove)
    'Campanulaceae': 'standard',   # Campanula (Bellflower)
    'Gentianaceae': 'standard',    # Exacum
    'Sapindaceae': 'standard',     # Litchi
    'Saxifragaceae': 'standard',   # Saxifraga, Tolmiea
    'Lythraceae': 'standard',      # Cuphea, Lagerstroemia
    'Caryophyllaceae': 'standard', # Dianthus (Carnation)
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


# Family-based toxicity data (Source: ASPCA Poison Control, 22 families)
# Format: pets/humans = true if toxic, note = CAUSE → EFFECT → ACTION
TOXIC_FAMILIES = {
    'Araliaceae': {'pets': True, 'humans': True, 'note': 'Sap on skin → rash. Pet eats leaf → vomiting. Wash hands after pruning'},
    'Araceae': {'pets': True, 'humans': True, 'note': 'Chewing → mouth/throat swelling, drooling. Severe swelling → vet'},
    'Liliaceae': {'pets': True, 'humans': False, 'note': 'CATS: pollen/leaf contact → kidney failure in 24-72h. Any contact → vet immediately'},
    'Solanaceae': {'pets': True, 'humans': False, 'note': 'Ripe fruit = safe. Green leaves/stems → pet vomiting. Keep unripe away from pets'},
    'Amaryllidaceae': {'pets': True, 'humans': True, 'note': 'Bulb most toxic. Pet chews bulb → vomiting, tremors. Keep bulbs buried or out of reach'},
    'Apocynaceae': {'pets': True, 'humans': True, 'note': 'Any part eaten → heart rhythm problems. Even small amount → vet'},
    'Crassulaceae': {'pets': True, 'humans': False, 'note': 'Pet eats → vomiting, diarrhea. Humans safe to handle'},
    'Ericaceae': {'pets': True, 'humans': True, 'note': 'Any part eaten → vomiting, weakness, heart issues. Keep away from pets'},
    'Euphorbiaceae': {'pets': True, 'humans': True, 'note': 'Milky sap on skin → irritation. In eyes → rinse 15 min. Wear gloves when pruning'},
    'Cycadaceae': {'pets': True, 'humans': True, 'note': 'Seeds eaten → liver failure. Dogs love to chew them. Any ingestion → vet immediately'},
    'Zamiaceae': {'pets': True, 'humans': True, 'note': 'Seeds eaten → liver failure. Dogs love to chew them. Any ingestion → vet immediately'},
    'Ranunculaceae': {'pets': True, 'humans': True, 'note': 'Sap on skin → blisters. Eaten → mouth pain, vomiting. Wear gloves'},
    'Plantaginaceae': {'pets': True, 'humans': True, 'note': 'Any amount eaten → heart rhythm problems. Keep away from children and pets'},
    'Asteraceae': {'pets': True, 'humans': False, 'note': 'Pet eats → skin irritation, vomiting. Humans safe'},
    'Moraceae': {'pets': True, 'humans': True, 'note': 'Sap on skin → rash. Pet eats leaf → vomiting. Wash hands after pruning'},
    'Asparagaceae': {'pets': True, 'humans': False, 'note': 'Pet eats berries → vomiting, diarrhea. Keep berries away from pets'},
    # New additions (Phase 2)
    'Begoniaceae': {'pets': True, 'humans': False, 'note': 'Tubers most toxic. Pet chews → mouth irritation, vomiting. Humans safe to handle'},
    'Commelinaceae': {'pets': True, 'humans': False, 'note': 'Sap contact → mild skin irritation. Pet eats → stomach upset. Generally low toxicity'},
    'Primulaceae': {'pets': True, 'humans': True, 'note': 'Cyclamen tubers highly toxic. Pet ingests → severe vomiting, heart rhythm problems. Skin contact → irritation'},
    'Hydrangeaceae': {'pets': True, 'humans': True, 'note': 'All parts contain cyanogenic glycosides. Ingestion → vomiting, diarrhea, lethargy'},
    'Strelitziaceae': {'pets': True, 'humans': False, 'note': 'Seeds/fruit if ingested → nausea, vomiting, drowsiness. Low severity for humans'},
    'Verbenaceae': {'pets': True, 'humans': True, 'note': 'Lantana: unripe berries → liver damage. Pet ingests → vomiting, weakness, liver failure'},
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
DEVICES_TABLE = os.environ.get('DEVICES_TABLE', 'polivalka_devices')
TELEMETRY_TABLE = os.environ.get('TELEMETRY_TABLE', 'polivalka_telemetry')
COMMANDS_TABLE = os.environ.get('COMMANDS_TABLE', 'polivalka_commands')
FIRMWARE_BUCKET = os.environ.get('FIRMWARE_BUCKET', 'polivalka-firmware')
FIRMWARE_CDN_DOMAIN = os.environ.get('FIRMWARE_CDN_DOMAIN', 'dueyl7xkzas7u.cloudfront.net')

# All tables in eu-central-1
devices_table = dynamodb.Table(DEVICES_TABLE)
telemetry_table = dynamodb.Table(TELEMETRY_TABLE)
commands_table = dynamodb.Table(COMMANDS_TABLE)
history_table = dynamodb.Table('polivalka_admin_history')


def add_device_history(device_id, event_type, user_email, details=None):
    """Add entry to device history (polivalka_admin_history table)"""
    try:
        import datetime
        item = {
            'device_id': device_id,
            'timestamp': datetime.datetime.now().isoformat(),
            'event': event_type,
            'user_email': user_email
        }
        if details:
            item['details'] = details
        history_table.put_item(Item=item)
        print(f"[History] Added: {event_type} for {device_id} by {user_email}")
    except Exception as e:
        print(f"[History] Error adding history: {e}")  # Non-fatal


def _to_dynamo_type(value):
    """Convert Python value to DynamoDB low-level type format for transact_write_items."""
    if value is None:
        return {'NULL': True}
    elif isinstance(value, bool):
        return {'BOOL': value}
    elif isinstance(value, Decimal):
        return {'N': str(value)}
    elif isinstance(value, (int, float)):
        return {'N': str(value)}
    elif isinstance(value, str):
        return {'S': value}
    elif isinstance(value, list):
        return {'L': [_to_dynamo_type(v) for v in value]}
    elif isinstance(value, dict):
        return {'M': {k: _to_dynamo_type(v) for k, v in value.items()}}
    else:
        return {'S': str(value)}


def _to_dynamo_map(obj):
    """Convert Python dict to DynamoDB Map type for transact_write_items."""
    return {'M': {k: _to_dynamo_type(v) for k, v in obj.items()}}


PLANT_LIBRARY_LIMIT = 50  # Max entries per device (including soft-deleted)


def _enforce_library_limit(plant_library):
    """
    Enforce plant_library size limit per device.
    When over limit: purge oldest soft-deleted first, then oldest detached.
    Returns trimmed library.
    """
    if len(plant_library) <= PLANT_LIBRARY_LIMIT:
        return plant_library

    # Sort candidates for removal: deleted first (oldest first), then non-deleted oldest
    over = len(plant_library) - PLANT_LIBRARY_LIMIT
    deleted = sorted([p for p in plant_library if p.get('deleted')],
                     key=lambda p: p.get('deleted_at', 0) or p.get('saved_at', 0))
    if len(deleted) >= over:
        # Purge oldest deleted entries
        purge_ids = {p.get('plant_id') for p in deleted[:over]}
        print(f"[PLANTS] Library limit: purging {over} oldest deleted entries")
        return [p for p in plant_library if p.get('plant_id') not in purge_ids]

    # Not enough deleted — purge all deleted + oldest detached
    purge_ids = {p.get('plant_id') for p in deleted}
    remaining_over = over - len(deleted)
    non_deleted = sorted([p for p in plant_library if not p.get('deleted')],
                         key=lambda p: p.get('ended_at', 0) or p.get('saved_at', 0))
    purge_ids.update(p.get('plant_id') for p in non_deleted[:remaining_over])
    print(f"[PLANTS] Library limit: purging {over} entries ({len(deleted)} deleted + {remaining_over} oldest)")
    return [p for p in plant_library if p.get('plant_id') not in purge_ids]


def _auto_detach_plant(device, current_time):
    """
    Auto-detach current plant from device into plant_library.
    Returns updated plant_library list and detached plant name (or None).
    Called automatically when saving/assigning a new plant — seamless, no user action.
    """
    existing_plant = device.get('plant')
    plant_library = list(device.get('plant_library', []))

    if existing_plant and existing_plant.get('plant_id') and not existing_plant.get('archived'):
        existing_plant['ended_at'] = current_time
        existing_plant['detached_at'] = current_time
        plant_library.append(existing_plant)
        plant_library = _enforce_library_limit(plant_library)
        plant_name = existing_plant.get('common_name') or existing_plant.get('scientific', 'Unknown')
        print(f"[PLANTS] Auto-detached: {plant_name} (plant_id={existing_plant['plant_id']})")
        return plant_library, plant_name

    return plant_library, None


def save_plant_profile(user_id, event, origin):
    """
    POST /plants/save
    Save plant profile to device record.
    If device already has a plant — auto-detach it to plant_library (seamless).
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
        response = devices_table.get_item(
            Key={'user_id': user_id, 'device_id': device_id}
        )
        if 'Item' not in response:
            return {
                'statusCode': 404,
                'headers': cors_headers(origin),
                'body': json.dumps({'error': f'Device {device_id} not found for your account'})
            }

        device = response['Item']
        current_time = int(time.time())

        # Auto-detach current plant (seamless — no user action needed)
        plant_library, detached_name = _auto_detach_plant(device, current_time)
        plant_library = _enforce_library_limit(plant_library)

        # Generate plant_id if not provided (for data isolation)
        if not plant_data.get('plant_id'):
            plant_data['plant_id'] = f"plant_{int(current_time * 1000)}"
            plant_data['started_at'] = current_time
            plant_data['created_at'] = current_time
            plant_data['device_history'] = [{'device_id': device_id, 'started_at': current_time}]

        # Add/update saved_at timestamp
        plant_data['saved_at'] = current_time

        # Update device: new plant + updated library
        devices_table.update_item(
            Key={'user_id': user_id, 'device_id': device_id},
            UpdateExpression='SET plant = :plant, plant_library = :library',
            ExpressionAttributeValues={':plant': plant_data, ':library': plant_library}
        )

        # Add to device history
        plant_name = plant_data.get('common_name') or plant_data.get('scientific', 'Unknown')
        if detached_name:
            add_device_history(device_id, 'plant_detached', user_id, detached_name)
        add_device_history(device_id, 'plant_saved', user_id, plant_name)

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


def archive_plant_profile(user_id, device_id, origin):
    """
    POST /plants/{device_id}/archive
    Archive current plant profile.
    Moves plant from device.plant → device.plant_library with archived flag.
    Device becomes free (plant = null).
    """
    try:
        if not device_id.startswith('Polivalka-'):
            device_id = f'Polivalka-{device_id}'

        response = devices_table.get_item(
            Key={'user_id': user_id, 'device_id': device_id}
        )
        if 'Item' not in response:
            return {
                'statusCode': 404,
                'headers': cors_headers(origin),
                'body': json.dumps({'error': f'Device {device_id} not found for your account'})
            }

        device = response['Item']
        plant = device.get('plant')
        if not plant:
            return {
                'statusCode': 404,
                'headers': cors_headers(origin),
                'body': json.dumps({'error': 'No plant profile to archive'})
            }

        # Archive: move to library, free up device
        current_time = int(time.time())
        plant['archived'] = True
        plant['archived_at'] = current_time
        plant['ended_at'] = current_time

        plant_library = list(device.get('plant_library', []))
        plant_library.append(plant)
        plant_library = _enforce_library_limit(plant_library)

        devices_table.update_item(
            Key={'user_id': user_id, 'device_id': device_id},
            UpdateExpression='SET plant_library = :library REMOVE plant',
            ExpressionAttributeValues={':library': plant_library}
        )

        plant_name = plant.get('common_name') or plant.get('scientific', 'Unknown')
        add_device_history(device_id, 'plant_archived', user_id, plant_name)

        print(f"[PLANTS] Archived plant profile for {device_id}: {plant.get('scientific', 'unknown')}")
        return {
            'statusCode': 200,
            'headers': cors_headers(origin),
            'body': json.dumps({'success': True, 'message': 'Plant profile archived'})
        }

    except Exception as e:
        print(f"[PLANTS] Error archiving plant profile: {e}")
        return {
            'statusCode': 500,
            'headers': cors_headers(origin),
            'body': json.dumps({'error': str(e)})
        }


def unarchive_plant_profile(user_id, device_id, origin, event=None):
    """
    POST /plants/{device_id}/unarchive?plant_id=xxx
    Restore plant from plant_library back to device.plant.
    With plant_id — restores specific plant (archived or detached).
    Without plant_id — restores most recent archived plant (backward compat).
    If device has an active plant — auto-detach it first (seamless).
    Deleted plants cannot be restored (admin-only visibility).
    """
    try:
        if not device_id.startswith('Polivalka-'):
            device_id = f'Polivalka-{device_id}'

        response = devices_table.get_item(
            Key={'user_id': user_id, 'device_id': device_id}
        )
        if 'Item' not in response:
            return {
                'statusCode': 404,
                'headers': cors_headers(origin),
                'body': json.dumps({'error': f'Device {device_id} not found for your account'})
            }

        device = response['Item']
        plant_library = list(device.get('plant_library', []))
        query_params = (event.get('queryStringParameters', {}) or {}) if event else {}
        target_plant_id = query_params.get('plant_id')

        if target_plant_id:
            # Restore specific plant by plant_id
            plant = next((p for p in plant_library
                         if p.get('plant_id') == target_plant_id and not p.get('deleted')), None)
            if not plant:
                return {
                    'statusCode': 404,
                    'headers': cors_headers(origin),
                    'body': json.dumps({'error': f'Plant {target_plant_id} not found in library'})
                }
        else:
            # Backward compat: find most recent archived plant
            archived_plants = [p for p in plant_library if p.get('archived') and not p.get('deleted')]
            if not archived_plants:
                return {
                    'statusCode': 404,
                    'headers': cors_headers(origin),
                    'body': json.dumps({'error': 'No archived plant to restore'})
                }
            archived_plants.sort(key=lambda p: p.get('archived_at', 0), reverse=True)
            plant = archived_plants[0]

        # Remove from library
        plant_library = [p for p in plant_library if p.get('plant_id') != plant.get('plant_id')]

        # Auto-detach current plant if exists
        current_time = int(time.time())
        existing_plant = device.get('plant')
        if existing_plant and existing_plant.get('plant_id'):
            existing_plant['ended_at'] = current_time
            existing_plant['detached_at'] = current_time
            plant_library.append(existing_plant)
            plant_library = _enforce_library_limit(plant_library)
            detached_name = existing_plant.get('common_name') or existing_plant.get('scientific', 'Unknown')
            add_device_history(device_id, 'plant_detached', user_id, detached_name)

        # Restore: remove archive/detach flags, set new started_at
        plant.pop('archived', None)
        plant.pop('archived_at', None)
        plant.pop('ended_at', None)
        plant.pop('detached_at', None)
        plant['started_at'] = current_time
        plant['saved_at'] = current_time

        devices_table.update_item(
            Key={'user_id': user_id, 'device_id': device_id},
            UpdateExpression='SET plant = :plant, plant_library = :library',
            ExpressionAttributeValues={':plant': plant, ':library': plant_library}
        )

        plant_name = plant.get('common_name') or plant.get('scientific', 'Unknown')
        add_device_history(device_id, 'plant_unarchived', user_id, plant_name)

        print(f"[PLANTS] Unarchived plant profile for {device_id}: {plant_name}")
        return {
            'statusCode': 200,
            'headers': cors_headers(origin),
            'body': json.dumps({'success': True, 'message': 'Plant profile restored'})
        }

    except Exception as e:
        print(f"[PLANTS] Error unarchiving plant profile: {e}")
        return {
            'statusCode': 500,
            'headers': cors_headers(origin),
            'body': json.dumps({'error': str(e)})
        }


def delete_plant_profile(user_id, device_id, origin, event=None):
    """
    DELETE /plants/{device_id}?plant_id=xxx
    Soft-delete: moves plant to plant_library with deleted=true flag.
    Without plant_id — soft-deletes active plant.
    With plant_id — marks plant in plant_library as deleted.
    User never sees deleted plants. Admin sees all via admin API.
    """
    try:
        if not device_id.startswith('Polivalka-'):
            device_id = f'Polivalka-{device_id}'

        response = devices_table.get_item(
            Key={'user_id': user_id, 'device_id': device_id}
        )
        if 'Item' not in response:
            return {
                'statusCode': 404,
                'headers': cors_headers(origin),
                'body': json.dumps({'error': f'Device {device_id} not found for your account'})
            }

        device = response['Item']
        current_time = int(time.time())
        query_params = (event.get('queryStringParameters', {}) or {}) if event else {}
        target_plant_id = query_params.get('plant_id')

        plant_library = list(device.get('plant_library', []))

        if target_plant_id:
            # Soft-delete specific plant from plant_library
            target = next((p for p in plant_library if p.get('plant_id') == target_plant_id), None)
            if not target:
                return {
                    'statusCode': 404,
                    'headers': cors_headers(origin),
                    'body': json.dumps({'error': f'Plant {target_plant_id} not found in library'})
                }
            if target.get('deleted'):
                return {
                    'statusCode': 400,
                    'headers': cors_headers(origin),
                    'body': json.dumps({'error': f'Plant {target_plant_id} is already deleted'})
                }
            plant_name = target.get('common_name') or target.get('scientific', 'Unknown')
            # Mark as deleted (don't remove from library)
            target['deleted'] = True
            target['deleted_at'] = current_time
            devices_table.update_item(
                Key={'user_id': user_id, 'device_id': device_id},
                UpdateExpression='SET plant_library = :library',
                ExpressionAttributeValues={':library': plant_library}
            )
        else:
            # Soft-delete active plant: move to library with deleted flag
            plant = device.get('plant', {})
            if not plant or not plant.get('plant_id'):
                return {
                    'statusCode': 404,
                    'headers': cors_headers(origin),
                    'body': json.dumps({'error': 'No active plant on this device'})
                }
            plant_name = plant.get('common_name') or plant.get('scientific', 'Unknown')
            plant['deleted'] = True
            plant['deleted_at'] = current_time
            plant['ended_at'] = current_time
            plant_library.append(plant)
            plant_library = _enforce_library_limit(plant_library)
            devices_table.update_item(
                Key={'user_id': user_id, 'device_id': device_id},
                UpdateExpression='SET plant_library = :library REMOVE plant',
                ExpressionAttributeValues={':library': plant_library}
            )

        add_device_history(device_id, 'plant_deleted', user_id, plant_name)

        print(f"[PLANTS] Soft-deleted plant for {device_id}: {plant_name}")
        return {
            'statusCode': 200,
            'headers': cors_headers(origin),
            'body': json.dumps({'success': True, 'message': 'Plant profile deleted'})
        }

    except Exception as e:
        print(f"[PLANTS] Error deleting plant profile: {e}")
        return {
            'statusCode': 500,
            'headers': cors_headers(origin),
            'body': json.dumps({'error': str(e)})
        }


def _plant_to_entry(plant, device_id, device, active=True):
    """Helper: convert plant data to library entry format."""
    return {
        'plant_id': plant.get('plant_id'),
        'scientific': plant.get('scientific'),
        'common_name': plant.get('common_name'),
        'family': plant.get('family'),
        'image_url': plant.get('image_url'),
        'preset': plant.get('preset'),
        'start_pct': plant.get('start_pct'),
        'stop_pct': plant.get('stop_pct'),
        'poisonous_to_pets': plant.get('poisonous_to_pets'),
        'poisonous_to_humans': plant.get('poisonous_to_humans'),
        'toxicity_note': plant.get('toxicity_note'),
        'started_at': plant.get('started_at'),
        'ended_at': plant.get('ended_at'),
        'created_at': plant.get('created_at'),
        'saved_at': plant.get('saved_at'),
        'archived': plant.get('archived', False),
        'deleted': plant.get('deleted', False),
        'active': active,
        'device_id': device_id,
        'device_location': device.get('location', ''),
        'device_room': device.get('room', ''),
    }


def get_plant_library(user_id, origin):
    """
    GET /plants/library
    Get all plant profiles for this user (active + library from all devices).
    Returns list with 'active' flag to distinguish current vs detached/archived.
    """
    try:
        response = devices_table.query(
            KeyConditionExpression=Key('user_id').eq(user_id)
        )

        plants = []
        for device in response.get('Items', []):
            device_id = device.get('device_id')

            # Active plant on device
            plant = device.get('plant')
            if plant and plant.get('plant_id'):
                plants.append(_plant_to_entry(plant, device_id, device, active=True))

            # Detached/archived plants in library (exclude soft-deleted for regular users)
            for lib_plant in device.get('plant_library', []):
                if lib_plant.get('plant_id') and not lib_plant.get('deleted'):
                    plants.append(_plant_to_entry(lib_plant, device_id, device, active=False))

        # Sort: active first, then by saved_at descending
        plants.sort(key=lambda x: (not x.get('active', False), -(x.get('saved_at', 0) or 0)))

        print(f"[PLANTS] Library for {user_id}: {len(plants)} plants")
        return {
            'statusCode': 200,
            'headers': cors_headers(origin),
            'body': json.dumps({'success': True, 'plants': plants}, cls=DecimalEncoder)
        }

    except Exception as e:
        print(f"[PLANTS] Error getting plant library: {e}")
        return {
            'statusCode': 500,
            'headers': cors_headers(origin),
            'body': json.dumps({'error': str(e)})
        }


def assign_plant_to_device(user_id, device_id, event, origin):
    """
    POST /plants/{device_id}/assign
    MOVE plant from source (active on another device or plant_library) to this device.
    Body: { plant_id: "plant_1707123456789" }

    No duplicates: plant is REMOVED from source and SET on target.
    Same plant_id preserved. Uses TransactWriteItems for atomicity.
    """
    try:
        body = json.loads(event.get('body', '{}'))
        source_plant_id = body.get('plant_id')

        if not source_plant_id:
            return {
                'statusCode': 400,
                'headers': cors_headers(origin),
                'body': json.dumps({'error': 'plant_id required'})
            }

        # Normalize device_id
        if not device_id.startswith('Polivalka-'):
            device_id = f'Polivalka-{device_id}'

        # Verify user owns target device
        target_response = devices_table.get_item(
            Key={'user_id': user_id, 'device_id': device_id}
        )
        if 'Item' not in target_response:
            return {
                'statusCode': 404,
                'headers': cors_headers(origin),
                'body': json.dumps({'error': f'Device {device_id} not found for your account'})
            }

        # Find source plant in user's devices (active plants + plant_library)
        all_devices = devices_table.query(
            KeyConditionExpression=Key('user_id').eq(user_id)
        )

        source_plant = None
        source_device_id = None
        source_device = None
        source_is_active = False
        for dev in all_devices.get('Items', []):
            # Check active plant
            plant = dev.get('plant')
            if plant and plant.get('plant_id') == source_plant_id:
                source_plant = dict(plant)
                source_device_id = dev.get('device_id')
                source_device = dev
                source_is_active = True
                break
            # Check plant_library (exclude deleted)
            for lib_plant in dev.get('plant_library', []):
                if lib_plant.get('plant_id') == source_plant_id and not lib_plant.get('deleted'):
                    source_plant = dict(lib_plant)
                    source_device_id = dev.get('device_id')
                    source_device = dev
                    source_is_active = False
                    break
            if source_plant:
                break

        if not source_plant:
            return {
                'statusCode': 404,
                'headers': cors_headers(origin),
                'body': json.dumps({'error': f'Plant {source_plant_id} not found in your library'})
            }

        # Cannot assign to the same device if plant is already active there
        if source_is_active and source_device_id == device_id:
            return {
                'statusCode': 400,
                'headers': cors_headers(origin),
                'body': json.dumps({'error': 'Plant is already active on this device'})
            }

        current_time = int(time.time())
        target_device = target_response['Item']

        # Auto-detach current plant on target device (seamless)
        target_library, detached_name = _auto_detach_plant(target_device, current_time)

        # Prepare the moved plant: clean archive/detach flags, update timestamps
        source_plant.pop('archived', None)
        source_plant.pop('archived_at', None)
        source_plant.pop('ended_at', None)
        source_plant.pop('detached_at', None)
        source_plant.pop('deleted', None)
        source_plant.pop('deleted_at', None)
        source_plant['started_at'] = current_time
        source_plant['saved_at'] = current_time

        # Update device_history
        history = source_plant.get('device_history', [])
        history.append({'device_id': device_id, 'started_at': current_time})
        source_plant['device_history'] = history

        # Two cases: same device (single update) or different devices (transaction)
        if source_device_id == device_id and not source_is_active:
            # Source is in library of the SAME device as target — single update
            # target_library contains: auto-detached active plant + old library entries including source
            # Remove source from library since it becomes the new active plant
            target_library = [p for p in target_library if p.get('plant_id') != source_plant_id]
            devices_table.update_item(
                Key={'user_id': user_id, 'device_id': device_id},
                UpdateExpression='SET plant = :plant, plant_library = :library',
                ExpressionAttributeValues={':plant': source_plant, ':library': target_library}
            )
        else:
            # Different devices — use TransactWriteItems for atomicity
            if source_is_active:
                source_update_expr = 'REMOVE plant'
                source_attr_values = None
            else:
                source_library = [p for p in source_device.get('plant_library', [])
                                if p.get('plant_id') != source_plant_id]
                source_update_expr = 'SET plant_library = :library'
                source_attr_values = {':library': {'L': [_to_dynamo_map(p) for p in source_library]}}

            transact_items = []

            source_item = {
                'Update': {
                    'TableName': DEVICES_TABLE,
                    'Key': {
                        'user_id': {'S': user_id},
                        'device_id': {'S': source_device_id}
                    },
                    'UpdateExpression': source_update_expr,
                }
            }
            if source_attr_values:
                source_item['Update']['ExpressionAttributeValues'] = source_attr_values
            transact_items.append(source_item)

            target_item = {
                'Update': {
                    'TableName': DEVICES_TABLE,
                    'Key': {
                        'user_id': {'S': user_id},
                        'device_id': {'S': device_id}
                    },
                    'UpdateExpression': 'SET plant = :plant, plant_library = :library',
                    'ExpressionAttributeValues': {
                        ':plant': _to_dynamo_map(source_plant),
                        ':library': {'L': [_to_dynamo_map(p) for p in target_library]}
                    }
                }
            }
            transact_items.append(target_item)

            dynamodb_client = boto3.client('dynamodb', region_name='eu-central-1')
            dynamodb_client.transact_write_items(TransactItems=transact_items)

        plant_name = source_plant.get('common_name') or source_plant.get('scientific', 'Unknown')

        if detached_name:
            add_device_history(device_id, 'plant_detached', user_id, detached_name)
        add_device_history(device_id, 'plant_assigned', user_id, f"{plant_name} (moved from {source_device_id})")

        print(f"[PLANTS] Moved {source_plant_id} from {source_device_id} to {device_id}")
        return {
            'statusCode': 200,
            'headers': cors_headers(origin),
            'body': json.dumps({
                'success': True,
                'message': f'Plant moved to {device_id}',
                'plant': source_plant
            }, cls=DecimalEncoder)
        }

    except Exception as e:
        print(f"[PLANTS] Error assigning plant: {e}")
        return {
            'statusCode': 500,
            'headers': cors_headers(origin),
            'body': json.dumps({'error': str(e)})
        }


def get_plant_profile(user_id, device_id, origin):
    """
    GET /plants/{device_id}
    Get plant profile from device record.

    IMPORTANT: Each user has their OWN device record with their own plant profile.
    When device is transferred, new user has separate record with no plant profile.
    This ensures data isolation between users.
    """
    try:
        # Normalize device_id
        if not device_id.startswith('Polivalka-'):
            device_id = f'Polivalka-{device_id}'

        # Get THIS user's device record directly (not via GSI which returns all users)
        response = devices_table.get_item(
            Key={'user_id': user_id, 'device_id': device_id}
        )

        if 'Item' not in response:
            # User doesn't have this device
            return {
                'statusCode': 404,
                'headers': cors_headers(origin),
                'body': json.dumps({'error': f'Device {device_id} not found for your account'})
            }

        device = response['Item']
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

                # Deep watering runtime stats from devices.latest (Phase 3)
                latest = device_info.get('latest') or {}
                # devices.latest is populated by dual-write (iot_rule_telemetry + iot_rule_response)
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
                # FLEET ARCHITECTURE: Read from devices.latest (single source of truth)
                device_info = get_device_info(device_id, user_id)
                latest = device_info.get('latest') or {}
                # devices.latest is populated by dual-write (iot_rule_telemetry + iot_rule_response)
                mode = latest.get('system', {}).get('mode', 'manual')
                state = latest.get('system', {}).get('state', 'DISABLED')
                # Sensor data with ADC < 100 check (defense against pre-fix data)
                sensor_data = latest.get('sensor', {})
                adc_raw = sensor_data.get('adc_raw')
                sensor_disconnected = adc_raw is not None and int(adc_raw) < 100
                moisture_pct = None if sensor_disconnected else sensor_data.get('moisture_percent')

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
                # FLEET ARCHITECTURE: Read from devices.latest (single source of truth)
                device_info = get_device_info(device_id, user_id)
                latest = device_info.get('latest') or {}
                # devices.latest is populated by dual-write (iot_rule_telemetry + iot_rule_response)
                mode = latest.get('system', {}).get('mode', 'manual')
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
                # FLEET ARCHITECTURE: Read from devices.latest
                device_info = get_device_info(device_id, user_id)
                latest = device_info.get('latest') or {}
                # devices.latest is populated by dual-write (iot_rule_telemetry + iot_rule_response)
                time_set = latest.get('system', {}).get('time_set', False)
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

    # GET /plants/library - Get all plant profiles for user
    if path == '/plants/library' and http_method == 'GET':
        return get_plant_library(user_id, origin)

    # GET /plants/{device_id} - Get plant profile from device
    if path.startswith('/plants/Polivalka-') and http_method == 'GET' and path.count('/') == 2:
        device_id = path.split('/')[-1]  # Extract device_id from path
        return get_plant_profile(user_id, device_id, origin)

    # POST /plants/{device_id}/archive - Archive plant profile
    if path.startswith('/plants/Polivalka-') and path.endswith('/archive') and http_method == 'POST':
        device_id = path.split('/')[2]  # /plants/Polivalka-XXX/archive -> Polivalka-XXX
        return archive_plant_profile(user_id, device_id, origin)

    # POST /plants/{device_id}/unarchive - Restore plant profile from archive
    if path.startswith('/plants/Polivalka-') and path.endswith('/unarchive') and http_method == 'POST':
        device_id = path.split('/')[2]  # /plants/Polivalka-XXX/unarchive -> Polivalka-XXX
        return unarchive_plant_profile(user_id, device_id, origin, event)

    # POST /plants/{device_id}/assign - Assign plant from library to device
    if path.startswith('/plants/Polivalka-') and path.endswith('/assign') and http_method == 'POST':
        device_id = path.split('/')[2]  # /plants/Polivalka-XXX/assign -> Polivalka-XXX
        return assign_plant_to_device(user_id, device_id, event, origin)

    # DELETE /plants/{device_id} - Delete plant profile
    if path.startswith('/plants/Polivalka-') and http_method == 'DELETE' and path.count('/') == 2:
        device_id = path.split('/')[-1]  # Extract device_id from path
        return delete_plant_profile(user_id, device_id, origin, event)

    # ============ Whitelist Check & Claim Routes (Security Migration 2026-01-20) ============
    # These are NOT admin-only - any authenticated user can check their whitelist status

    # GET /whitelist/check?device_id=XXX - Check if user can claim device
    if path == '/whitelist/check' and http_method == 'GET':
        return check_whitelist_status(user_id, event, origin)

    # POST /claims - Create new claim request (for non-whitelisted users)
    if path == '/claims' and http_method == 'POST':
        return create_user_claim(user_id, event, origin)

    # POST /devices/claim - Claim device (for whitelisted users or admin)
    if path == '/devices/claim' and http_method == 'POST':
        return claim_device(user_id, event, origin)

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

        # POST /admin/revoke-device - Revoke device from user, transfer back to admin
        if path == '/admin/revoke-device' and http_method == 'POST':
            return admin_revoke_device(event)

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

    # Filter out archived and deleted devices
    # For admin: keep transferred devices (show who they're assigned to)
    # For regular users: filter out transferred devices
    is_admin = user_id in ADMIN_EMAILS
    if is_admin:
        # Admin sees all devices including transferred (to show assignments)
        items = [i for i in items if not i.get('archived') and not i.get('deleted')]
    else:
        # Regular users don't see transferred devices
        items = [i for i in items if not i.get('archived') and not i.get('deleted') and not i.get('transferred')]
    print(f"[DEBUG] get_devices: {len(items)} devices after filter (is_admin={is_admin})")

    # Admin: group by device_id to avoid duplicates (same device may have multiple owners)
    is_admin = user_id in ADMIN_EMAILS
    if is_admin:
        device_groups = {}
        for item in items:
            did = item['device_id']
            if did not in device_groups:
                device_groups[did] = []
            device_groups[did].append(item)

        # For each group, pick primary item (prefer non-admin owner, then newest claimed_at)
        items = []
        for did, group in device_groups.items():
            group.sort(key=lambda x: (x['user_id'] in ADMIN_EMAILS, -(x.get('claimed_at') or 0)))
            primary = group[0]
            primary['_all_owners'] = [i['user_id'] for i in group]
            # Merge metadata from all records (device_name, location, room may be in any)
            for other in group[1:]:
                if not primary.get('device_name') and other.get('device_name'):
                    primary['device_name'] = other['device_name']
                if not primary.get('location') and other.get('location'):
                    primary['location'] = other['location']
                if not primary.get('room') and other.get('room'):
                    primary['room'] = other['room']
            items.append(primary)
        print(f"[DEBUG] get_devices: Admin grouped to {len(items)} unique devices")

    devices = []
    for item in items:
        device_id = item['device_id']

        try:
            # FLEET ARCHITECTURE: Read from devices.latest (single source of truth)
            latest = item.get('latest') or {}

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

            # Pump calibration: prefer telemetry (pump.calibration = working value from ESP32)
            # This is the actual ml/sec value the pump uses (either preset or user-calibrated)
            # Fallback chain: telemetry → devices_table → 1.0 (CALIBRATION_DEFAULT)
            pump_calib_from_telem = latest.get('pump', {}).get('calibration')
            pump_calib_from_db = item.get('pump_calibration')
            pump_calib = pump_calib_from_telem if pump_calib_from_telem is not None else pump_calib_from_db
            pump_calib_float = float(pump_calib) if pump_calib else 1.0
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
                # ADC < 100 = capacitive sensor not connected (same check as ESP32 sensor_is_connected)
                'moisture_pct': latest.get('sensor', {}).get('moisture_percent') if not (latest.get('sensor', {}).get('adc_raw') is not None and latest.get('sensor', {}).get('adc_raw') < 100) else None,
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
                'pump_runtime_sec': int(item.get('pump_runtime_sec', 0)) if item.get('pump_runtime_sec') else None,
                'pump_running': latest.get('pump', {}).get('running', False),  # For state display
                # Owner info (for admin fleet view)
                'owner': item.get('user_id'),
                'all_owners': item.get('_all_owners', [item.get('user_id')]) if is_admin else None,
                # Transfer status (for admin to see where device went)
                'transferred': item.get('transferred', False),
                'transferred_to': item.get('transferred_to')
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
                'pump_calibration': 1.0,  # CALIBRATION_DEFAULT
                'pump_speed': 100,
                'sensor_calibration': {'water': 1200, 'dry_soil': 2400, 'air': 2800},
                'owner': item.get('user_id'),
                'all_owners': item.get('_all_owners', [item.get('user_id')]) if is_admin else None
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

    # FLEET ARCHITECTURE: Read from devices.latest (single source of truth)
    # This was migrated from get_latest_telemetry() which read from telemetry table
    latest = device_meta.get('latest') or {}
    # devices.latest is populated by dual-write (iot_rule_telemetry + iot_rule_response)

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
    adc_raw = sensor_data.get('adc_raw')
    # ADC < 100 = capacitive sensor not connected (defense against pre-fix data in devices.latest)
    sensor_disconnected = adc_raw is not None and int(adc_raw) < 100
    status = {
        'adc': adc_raw,
        'percent': None if sensor_disconnected else sensor_data.get('moisture_percent'),
        'percent_float': None if sensor_disconnected else sensor_data.get('percent_float'),  # Decimal precision for sensor1
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

    # Data isolation: filter by plant.started_at or claimed_at (unless admin)
    # Priority: plant.started_at > claimed_at > 0
    is_admin = user_id in ADMIN_EMAILS
    if not is_admin:
        device_info = get_device_info(device_id, user_id)
        plant = device_info.get('plant', {})
        plant_started_at = plant.get('started_at')
        # Fallback to claimed_at if no plant profile yet (device just claimed)
        if plant_started_at is None:
            plant_started_at = device_info.get('claimed_at', 0)
        if plant_started_at and plant_started_at > cutoff:
            cutoff = plant_started_at  # Only show data since device was claimed/plant assigned

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

    # FLEET ARCHITECTURE: Read from devices.latest (single source of truth)
    device_info = get_device_info(device_id, user_id)
    latest = (device_info.get('latest') or {}) if device_info else {}
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

    # Data isolation: filter by plant.started_at or claimed_at (unless admin)
    # Priority: plant.started_at > claimed_at > 0
    is_admin = user_id in ADMIN_EMAILS
    if not is_admin:
        device_info = get_device_info(device_id, user_id)
        plant = device_info.get('plant', {})
        plant_started_at = plant.get('started_at')
        # Fallback to claimed_at if no plant profile yet (device just claimed)
        if plant_started_at is None:
            plant_started_at = device_info.get('claimed_at', 0)
        if plant_started_at and plant_started_at > cutoff:
            cutoff = plant_started_at  # Only show data since device was claimed/plant assigned

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

def verify_device_access(device_id, user_id):
    """Check if user owns this device (admins have access to all devices)"""

    # Admin has access to ALL devices
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
    if user_id in ADMIN_EMAILS:
        # Admin: query by device_id via GSI (device may have any user_id in DB)
        response = devices_table.query(
            IndexName='device_id-index',
            KeyConditionExpression=Key('device_id').eq(device_id)
        )
        items = response.get('Items', [])
        # Prefer active (non-transferred) record — transferred records have stale devices.latest
        # because iot_rule_response.py and iot_rule_telemetry.py skip transferred records
        active = [i for i in items if not i.get('transferred')]
        if active:
            return active[0]
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


def claim_device(user_id, event, origin):
    """POST /devices/claim - Claim device for whitelisted user or admin

    Creates a new device record for the user in polivalka_devices.
    Requires either: admin access OR user is whitelisted for this device.
    """
    try:
        body = json.loads(event.get('body', '{}'))
        raw_device_id = body.get('device_id', '').upper()

        if not raw_device_id:
            return {
                'statusCode': 400,
                'headers': cors_headers(origin),
                'body': json.dumps({'error': 'device_id required'})
            }

        # Normalize device_id format
        if raw_device_id.startswith('POLIVALKA-'):
            device_id = f'Polivalka-{raw_device_id[10:]}'
        else:
            device_id = f'Polivalka-{raw_device_id}'

        # Check authorization: admin can claim any device
        is_admin = user_id in ADMIN_EMAILS

        if not is_admin:
            # Check whitelist
            whitelist_table = dynamodb.Table('polivalka_admin_users')
            response = whitelist_table.get_item(Key={'email': user_id})

            if 'Item' not in response:
                return {
                    'statusCode': 403,
                    'headers': cors_headers(origin),
                    'body': json.dumps({'error': 'You are not in the whitelist'})
                }

            user_data = response['Item']
            status = user_data.get('status', 'active')

            if status != 'active':
                return {
                    'statusCode': 403,
                    'headers': cors_headers(origin),
                    'body': json.dumps({'error': f'Your account is {status}'})
                }

            # Check if device is assigned to this user
            devices = user_data.get('devices', [])
            if device_id not in devices:
                return {
                    'statusCode': 403,
                    'headers': cors_headers(origin),
                    'body': json.dumps({'error': f'Device {device_id} is not assigned to you'})
                }

        # Check if user already has this device
        existing = devices_table.get_item(
            Key={'user_id': user_id, 'device_id': device_id}
        )

        user_record_exists = False
        if 'Item' in existing:
            # Check if it's a transferred record (user reclaiming)
            if not existing['Item'].get('transferred'):
                user_record_exists = True
                print(f"[Transfer] User {user_id} already has record for {device_id}, but CONTINUING to process transfers")
                # DON'T RETURN EARLY! Must still process transfers for OTHER owners

        current_time = int(time.time())

        # ============ DEVICE TRANSFER ARCHITECTURE ============
        # Find ALL existing records for this device (all owners)
        all_records = devices_table.query(
            IndexName='device_id-index',
            KeyConditionExpression=Key('device_id').eq(device_id)
        )

        transfer_count = 0
        # Archive previous owners' data and mark as transferred
        for record in all_records.get('Items', []):
            prev_owner = record['user_id']
            if prev_owner == user_id:
                continue  # Skip if same user

            # Move plant to plant_library (same format as _auto_detach_plant)
            plant = record.get('plant')
            plant_library = list(record.get('plant_library', []))
            if plant and plant.get('plant_id'):
                plant['ended_at'] = current_time
                plant['detached_at'] = current_time
                plant['archived'] = True
                plant['archived_at'] = current_time
                plant_library.append(plant)
                plant_library = _enforce_library_limit(plant_library)

            # Mark record as transferred (preserves history, stops latest updates)
            try:
                update_expr = 'SET transferred = :t, transferred_to = :to, transferred_at = :at'
                expr_values = {
                    ':t': True,
                    ':to': user_id,
                    ':at': current_time
                }

                if plant_library:
                    update_expr += ', plant_library = :lib'
                    expr_values[':lib'] = plant_library

                # Remove latest field (no longer updated for transferred records)
                update_expr += ' REMOVE plant, latest'

                devices_table.update_item(
                    Key={'user_id': prev_owner, 'device_id': device_id},
                    UpdateExpression=update_expr,
                    ExpressionAttributeValues=expr_values
                )
                transfer_count += 1
                print(f"[Transfer] *** ARCHIVED *** {prev_owner}'s data for {device_id} (#{transfer_count})")
                add_device_history(device_id, 'transferred', prev_owner,
                                   {'transferred_to': user_id, 'plant_archived': plant is not None})
            except Exception as e:
                print(f"[Transfer] Error archiving {prev_owner}: {e}")

        # Create new device record for this user (skip if record already exists)
        if not user_record_exists:
            devices_table.put_item(Item={
                'user_id': user_id,
                'device_id': device_id,
                'device_name': 'Polivalka',  # Default name for new owner
                'claimed_at': current_time,
                'location': 'Home',
                'room': 'Room'
                # plant = None - user will set via identify.html
            })
            print(f"[Claim] Created new record for {user_id} -> {device_id}")
        else:
            # User record exists - update claimed_at to reset data isolation cutoff
            # NOTE: Do NOT remove plant here - user may want to keep their plant profile
            devices_table.update_item(
                Key={'user_id': user_id, 'device_id': device_id},
                UpdateExpression='SET claimed_at = :ca, device_name = :dn REMOVE transferred',
                ExpressionAttributeValues={
                    ':ca': current_time,
                    ':dn': 'Polivalka'
                }
            )
            print(f"[Claim] Updated existing record for {user_id} -> {device_id}, reset claimed_at for data isolation")

        # Send MQTT command to ESP32 to reset device_name
        # Command is update_device_info (not set_device_name!)
        try:
            topic = f'Polivalka/{device_id.replace("Polivalka-", "")}/command'
            mqtt_payload = {
                'command_id': str(uuid.uuid4()),
                'command': 'update_device_info',
                'params': {'name': 'Polivalka'}
            }
            iot_client.publish(
                topic=topic,
                qos=1,
                payload=json.dumps(mqtt_payload)
            )
            print(f"[Transfer] Sent update_device_info name=Polivalka to {topic}")
        except Exception as mqtt_err:
            print(f"[Transfer] MQTT publish failed: {mqtt_err}")
            # Non-fatal - user can change name manually

        # Add to device history - CRITICAL EVENT LOGGING
        add_device_history(device_id, 'claimed', user_id, {
            'existing_record': user_record_exists,
            'claimed_at': current_time,
            'previous_owners_archived': transfer_count
        })

        print(f"[Claim] *** DEVICE TRANSFER COMPLETE *** {device_id} -> {user_id} (archived {transfer_count} previous owner(s))")
        return {
            'statusCode': 201,
            'headers': cors_headers(origin),
            'body': json.dumps({
                'success': True,
                'message': f'Device {device_id} is now yours!',
                'device_id': device_id
            })
        }

    except Exception as e:
        print(f"[Claim] Error claiming device: {e}")
        import traceback
        traceback.print_exc()
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


def admin_revoke_device(event):
    """POST /admin/revoke-device - Revoke device from user, transfer back to admin

    This is a CRITICAL operation that:
    1. Marks user's record as transferred (back to admin)
    2. Archives user's plant profile
    3. Removes user's latest field (stops Fleet display)
    4. Restores admin's record (removes transferred flag)
    5. Logs the revocation event
    """
    try:
        body = json.loads(event.get('body', '{}'))
        device_id = body.get('device_id', '').upper()
        user_email = body.get('user_email', '')
        admin_email = body.get('admin_email', 'admin')  # Default admin

        # Normalize device_id
        if not device_id:
            return {
                'statusCode': 400,
                'headers': cors_headers(),
                'body': json.dumps({'error': 'device_id required'})
            }

        if device_id.startswith('POLIVALKA-'):
            device_id = f'Polivalka-{device_id[10:]}'
        else:
            device_id = f'Polivalka-{device_id}'

        if not user_email:
            return {
                'statusCode': 400,
                'headers': cors_headers(),
                'body': json.dumps({'error': 'user_email required'})
            }

        devices_table = dynamodb.Table('polivalka_devices')
        current_time = int(time.time())

        print(f"[Revoke] *** DEVICE REVOCATION STARTED *** {device_id} from {user_email} to {admin_email}")

        # ============ STEP 1: Mark user's record as transferred ============
        user_record = devices_table.get_item(
            Key={'user_id': user_email, 'device_id': device_id}
        )

        if 'Item' not in user_record:
            return {
                'statusCode': 404,
                'headers': cors_headers(),
                'body': json.dumps({'error': f'User {user_email} does not have device {device_id}'})
            }

        user_item = user_record['Item']

        # Check if already transferred
        if user_item.get('transferred'):
            return {
                'statusCode': 400,
                'headers': cors_headers(),
                'body': json.dumps({'error': f'Device already transferred from {user_email}'})
            }

        # Move plant to plant_library (consistent with claim_device)
        plant = user_item.get('plant')
        plant_library = list(user_item.get('plant_library', []))
        if plant and plant.get('plant_id'):
            plant['ended_at'] = current_time
            plant['detached_at'] = current_time
            plant['archived'] = True
            plant['archived_at'] = current_time
            plant_library.append(plant)
            plant_library = _enforce_library_limit(plant_library)

        # Mark user's record as transferred
        update_expr = 'SET transferred = :t, transferred_to = :to, transferred_at = :at, revoked_by = :rb'
        expr_values = {
            ':t': True,
            ':to': admin_email,
            ':at': current_time,
            ':rb': admin_email
        }

        if plant_library:
            update_expr += ', plant_library = :lib'
            expr_values[':lib'] = plant_library

        # Remove latest and plant
        update_expr += ' REMOVE plant, latest'

        devices_table.update_item(
            Key={'user_id': user_email, 'device_id': device_id},
            UpdateExpression=update_expr,
            ExpressionAttributeValues=expr_values
        )

        print(f"[Revoke] *** ARCHIVED *** {user_email}'s data for {device_id}")
        add_device_history(device_id, 'revoked', user_email, {
            'revoked_by': admin_email,
            'plant_archived': plant is not None
        })

        # ============ STEP 2: Restore admin's record ============
        admin_record = devices_table.get_item(
            Key={'user_id': admin_email, 'device_id': device_id}
        )

        if 'Item' in admin_record:
            # Admin record exists - just remove transferred flag
            devices_table.update_item(
                Key={'user_id': admin_email, 'device_id': device_id},
                UpdateExpression='REMOVE transferred, transferred_to, transferred_at'
            )
            print(f"[Revoke] Restored admin record for {device_id}")
        else:
            # Create new admin record
            devices_table.put_item(Item={
                'user_id': admin_email,
                'device_id': device_id,
                'device_name': 'Polivalka',
                'claimed_at': current_time,
                'location': 'Home',
                'room': 'Room'
            })
            print(f"[Revoke] Created new admin record for {device_id}")

        add_device_history(device_id, 'reclaimed', admin_email, {
            'reclaimed_from': user_email
        })

        # ============ STEP 3: Remove device from user's whitelist ============
        whitelist_table = dynamodb.Table('polivalka_admin_users')
        try:
            wl_response = whitelist_table.get_item(Key={'email': user_email})
            if 'Item' in wl_response:
                devices_list = wl_response['Item'].get('devices', [])
                if device_id in devices_list:
                    devices_list.remove(device_id)
                    whitelist_table.update_item(
                        Key={'email': user_email},
                        UpdateExpression='SET devices = :d',
                        ExpressionAttributeValues={':d': devices_list}
                    )
                    print(f"[Revoke] Removed {device_id} from {user_email}'s whitelist")
        except Exception as wl_err:
            print(f"[Revoke] Whitelist update failed (non-fatal): {wl_err}")

        print(f"[Revoke] *** DEVICE REVOCATION COMPLETE *** {device_id} from {user_email} to {admin_email}")

        return {
            'statusCode': 200,
            'headers': cors_headers(),
            'body': json.dumps({
                'success': True,
                'message': f'Device {device_id} revoked from {user_email}',
                'device_id': device_id,
                'user_email': user_email,
                'admin_email': admin_email
            })
        }

    except Exception as e:
        print(f"[Revoke] Error revoking device: {e}")
        import traceback
        traceback.print_exc()
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
                # FLEET ARCHITECTURE Phase 3: Read from devices.latest (single source of truth)
                # iot_rule_response.py already updated devices.latest with normalized data
                # (ADC < 100 → moisture_percent=null, battery from periodic telemetry only, etc.)
                # No need to parse raw command result — devices.latest is authoritative.
                device_info = get_device_info(device_id, user_id)
                latest_data = device_info.get('latest', {}) if device_info else {}

                sensor = latest_data.get('sensor', {})
                battery = latest_data.get('battery', {})
                system = latest_data.get('system', {})
                pump = latest_data.get('pump', {})

                # Convert battery percent -1 to null (indicates AC power, no battery)
                if battery and (battery.get('percent') == -1 or battery.get('percent') == -1.0):
                    battery = {**battery, 'percent': None}

                return {
                    'statusCode': 200,
                    'headers': cors_headers(),
                    'body': json.dumps({
                        # Sensor — already normalized by iot_rule_response.py
                        # (ADC < 100 → moisture_percent=null, no fake 100%)
                        'moisture_pct': sensor.get('moisture_percent'),
                        'adc_raw': sensor.get('adc_raw'),
                        'percent_float': sensor.get('percent_float'),
                        'sensor_calibration': sensor.get('calibration'),
                        # Sensor2 (J7 resistive) — merged into sensor by iot_rule_response.py
                        'sensor2_adc': sensor.get('sensor2_adc'),
                        'sensor2_percent': sensor.get('sensor2_percent'),
                        'sensor2_percent_float': sensor.get('sensor2_percent_float'),
                        # Battery — from periodic telemetry only (reliable source)
                        'battery': battery if battery else None,
                        # Pump
                        'pump_running': pump.get('running', False),
                        'pump_calibration': pump.get('calibration'),
                        'pump_speed': pump.get('speed'),
                        # System
                        'mode': system.get('mode', 'manual'),
                        'state': system.get('state', 'DISABLED'),
                        'firmware_version': system.get('firmware_version') or system.get('firmware'),
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

        # Data isolation: filter by plant.started_at or claimed_at (unless admin)
        # Priority: plant.started_at > claimed_at > 0
        is_admin = user_id in ADMIN_EMAILS
        if not is_admin:
            device_info = get_device_info(device_id, user_id)
            plant = device_info.get('plant', {})
            plant_started_at = plant.get('started_at')
            # Fallback to claimed_at if no plant profile yet (device just claimed)
            if plant_started_at is None:
                plant_started_at = device_info.get('claimed_at', 0)
            if plant_started_at and plant_started_at > cutoff:
                cutoff = plant_started_at  # Only show data since device was claimed/plant assigned
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
