"""
Weekly Aggregator Lambda
Runs every Sunday at 23:59 UTC via CloudWatch Events/EventBridge

Purpose:
- Query DynamoDB for telemetry data from the past week
- Aggregate statistics (moisture avg/min/max, battery, watering events, etc.)
- Commit JSON to GitHub repository (polivalka-web/data/weekly/{device_id}.json)

Environment Variables:
- TELEMETRY_TABLE: DynamoDB table name (polivalka_telemetry)
- DEVICES_TABLE: DynamoDB table name (polivalka_devices)
- GITHUB_TOKEN: Personal Access Token with repo scope
- GITHUB_REPO: Repository name (gt3max/polivalka-web)
- GITHUB_BRANCH: Branch name (main)

CloudWatch Events Rule:
  cron(59 23 ? * SUN *)  # Every Sunday at 23:59 UTC
"""

import json
import boto3
import os
import time
import base64
from datetime import datetime, timedelta
from decimal import Decimal
from boto3.dynamodb.conditions import Key
import urllib.request
import urllib.error

# AWS clients
dynamodb = boto3.resource('dynamodb', region_name='eu-central-1')

# Environment
TELEMETRY_TABLE = os.environ.get('TELEMETRY_TABLE', 'polivalka_telemetry')
DEVICES_TABLE = os.environ.get('DEVICES_TABLE', 'polivalka_devices')
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', '')
GITHUB_REPO = os.environ.get('GITHUB_REPO', 'gt3max/polivalka-web')
GITHUB_BRANCH = os.environ.get('GITHUB_BRANCH', 'main')

telemetry_table = dynamodb.Table(TELEMETRY_TABLE)
devices_table = dynamodb.Table(DEVICES_TABLE)


def decimal_default(obj):
    """JSON serializer for Decimal objects"""
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def get_week_info(target_week=None):
    """Get ISO week info and date range. If target_week given (e.g. '2026-W05'), use that instead of current."""
    if target_week:
        # Parse '2026-W05' format
        year, wnum = int(target_week[:4]), int(target_week.split('W')[1])
        # ISO week 1 day 1 (Monday)
        jan4 = datetime(year, 1, 4)
        week_start = jan4 - timedelta(days=jan4.weekday()) + timedelta(weeks=wnum - 1)
    else:
        now = datetime.utcnow()
        days_since_monday = now.weekday()
        week_start = now - timedelta(days=days_since_monday)

    week_end = week_start + timedelta(days=6)
    iso_calendar = week_start.isocalendar()
    week = f"{iso_calendar[0]}-W{iso_calendar[1]:02d}"

    return {
        'week': week,
        'start_date': week_start.strftime('%Y-%m-%d'),
        'end_date': week_end.strftime('%Y-%m-%d'),
        'start_timestamp': int((week_start.replace(hour=0, minute=0, second=0)).timestamp()),
        'end_timestamp': int((week_end.replace(hour=23, minute=59, second=59)).timestamp())
    }


def get_all_devices():
    """Get list of all device IDs from devices table (small table, ~33 records)"""
    devices = set()

    try:
        # Scan devices table (small, ~33 records) instead of huge telemetry table
        response = devices_table.scan(
            ProjectionExpression='device_id',
        )

        for item in response.get('Items', []):
            device_id = item.get('device_id', '')
            if device_id.startswith('Polivalka-'):
                devices.add(device_id)

        # Handle pagination (unlikely for ~33 records, but safe)
        while 'LastEvaluatedKey' in response:
            response = devices_table.scan(
                ProjectionExpression='device_id',
                ExclusiveStartKey=response['LastEvaluatedKey'],
            )
            for item in response.get('Items', []):
                device_id = item.get('device_id', '')
                if device_id.startswith('Polivalka-'):
                    devices.add(device_id)

    except Exception as e:
        print(f"[ERROR] Failed to get devices: {e}")

    return list(devices)


def extract_raw_points(items):
    """Extract individual telemetry readings as compact raw data points.

    Compact field names to minimize JSON size:
    - Sensor: {ts, pct, adc, s2p, s2a} — timestamp, moisture%, ADC, sensor2%, sensor2ADC
    - Battery: {ts, pct, v, chg} — timestamp, percent, voltage, charging
    - Pump: {ts, ml, sec, src} — timestamp, volume_ml, duration_sec, source
    """
    sensor_points = []
    battery_points = []
    pump_points = []

    for item in items:
        ts = int(item.get('timestamp', 0))
        if not ts:
            continue

        # Sensor raw points
        sensor = item.get('sensor', {})
        pct = sensor.get('moisture_percent')
        if pct is None:
            pct = sensor.get('percent')
        if pct is None:
            pct = sensor.get('moisture')
        adc = sensor.get('adc_raw')
        if adc is None:
            adc = sensor.get('adc')

        if pct is not None:
            point = {'ts': ts, 'pct': round(float(pct), 1)}
            if adc is not None:
                point['adc'] = int(adc)
            s2p = sensor.get('sensor2_percent')
            s2a = sensor.get('sensor2_adc')
            if s2p is not None:
                point['s2p'] = round(float(s2p), 1)
            if s2a is not None:
                point['s2a'] = int(s2a)
            sensor_points.append(point)

        # Battery raw points
        battery = item.get('battery', {})
        b_pct = battery.get('percent')
        if b_pct is not None:
            point = {'ts': ts, 'pct': round(float(b_pct), 1)}
            voltage = battery.get('voltage')
            if voltage is not None:
                point['v'] = round(float(voltage), 3)
            charging = battery.get('charging', False)
            if charging:
                point['chg'] = True
            battery_points.append(point)

        # Pump raw points (only stop events with volume/duration)
        pump = item.get('pump', {})
        if pump.get('action') == 'stop':
            ml = pump.get('volume_ml', 0) or pump.get('ml', 0)
            sec = pump.get('duration_sec', 0) or pump.get('duration', 0)
            source = pump.get('source', 'unknown')
            point = {'ts': ts}
            if ml:
                point['ml'] = int(ml)
            if sec:
                point['sec'] = int(sec)
            if source and source != 'unknown':
                point['src'] = source
            pump_points.append(point)

    # Health raw points (RSSI timeline for long-term chart)
    health_points = []

    for item in items:
        ts = int(item.get('timestamp', 0))
        if not ts:
            continue

        system = item.get('system', {})
        rssi = system.get('sta_rssi')
        if rssi is not None:
            health_points.append({'ts': ts, 'rssi': int(rssi)})

    return {
        'sensor': sensor_points,
        'battery': battery_points,
        'pump': pump_points,
        'health': health_points
    }


def aggregate_device_data(device_id, start_ts, end_ts):
    """Aggregate telemetry data for a device within the time range"""

    # Query telemetry for this device
    response = telemetry_table.query(
        KeyConditionExpression=Key('device_id').eq(device_id) &
                               Key('timestamp').between(start_ts, end_ts),
        Limit=2000
    )

    items = response.get('Items', [])

    # Handle pagination
    while 'LastEvaluatedKey' in response:
        response = telemetry_table.query(
            KeyConditionExpression=Key('device_id').eq(device_id) &
                                   Key('timestamp').between(start_ts, end_ts),
            ExclusiveStartKey=response['LastEvaluatedKey'],
            Limit=2000
        )
        items.extend(response.get('Items', []))

    if not items:
        return None

    # Extract raw data points for long-term charts
    raw_points = extract_raw_points(items)

    # Aggregate moisture (percent + ADC)
    moisture_pct_values = []
    moisture_adc_values = []
    sensor2_pct_values = []
    sensor2_adc_values = []

    for item in items:
        sensor = item.get('sensor', {})
        # Handle multiple field names; use explicit None checks (0 is valid value)
        pct = sensor.get('moisture_percent')
        if pct is None:
            pct = sensor.get('percent')
        if pct is None:
            pct = sensor.get('moisture')
        adc = sensor.get('adc_raw')
        if adc is None:
            adc = sensor.get('adc')
        if pct is not None:
            moisture_pct_values.append(float(pct))
        if adc is not None:
            moisture_adc_values.append(int(adc))

        # Sensor 2 (J7)
        s2_pct = sensor.get('sensor2_percent')
        s2_adc = sensor.get('sensor2_adc')
        if s2_pct is not None:
            sensor2_pct_values.append(float(s2_pct))
        if s2_adc is not None:
            sensor2_adc_values.append(int(s2_adc))

    moisture_stats = None
    if moisture_pct_values:
        moisture_stats = {
            'avg_percent': round(sum(moisture_pct_values) / len(moisture_pct_values), 1),
            'min_percent': round(min(moisture_pct_values), 1),
            'max_percent': round(max(moisture_pct_values), 1),
            'readings_count': len(moisture_pct_values)
        }
        if moisture_adc_values:
            moisture_stats['avg_adc'] = round(sum(moisture_adc_values) / len(moisture_adc_values))
            moisture_stats['min_adc'] = min(moisture_adc_values)
            moisture_stats['max_adc'] = max(moisture_adc_values)

    sensor2_stats = None
    if sensor2_pct_values:
        sensor2_stats = {
            'avg_percent': round(sum(sensor2_pct_values) / len(sensor2_pct_values), 1),
            'min_percent': round(min(sensor2_pct_values), 1),
            'max_percent': round(max(sensor2_pct_values), 1),
            'readings_count': len(sensor2_pct_values)
        }
        if sensor2_adc_values:
            sensor2_stats['avg_adc'] = round(sum(sensor2_adc_values) / len(sensor2_adc_values))
            sensor2_stats['min_adc'] = min(sensor2_adc_values)
            sensor2_stats['max_adc'] = max(sensor2_adc_values)

    # Aggregate battery (percent + voltage)
    battery_pct_values = []
    battery_voltage_values = []
    charging_hours = 0
    last_charging_ts = None

    for item in items:
        battery = item.get('battery', {})
        pct = battery.get('percent')
        voltage = battery.get('voltage')
        if pct is not None:
            battery_pct_values.append(float(pct))
        if voltage is not None:
            battery_voltage_values.append(float(voltage))

        # Track charging time
        charging = battery.get('charging', False)
        ts = int(item.get('timestamp', 0))
        if charging:
            if last_charging_ts is not None:
                charging_hours += (ts - last_charging_ts) / 3600
            last_charging_ts = ts
        else:
            last_charging_ts = None

    battery_stats = None
    if battery_pct_values:
        battery_stats = {
            'avg_percent': round(sum(battery_pct_values) / len(battery_pct_values), 1),
            'min_percent': round(min(battery_pct_values), 1),
            'max_percent': round(max(battery_pct_values), 1),
            'charging_hours': round(charging_hours, 1)
        }
        if battery_voltage_values:
            battery_stats['avg_voltage'] = round(sum(battery_voltage_values) / len(battery_voltage_values), 2)
            battery_stats['min_voltage'] = round(min(battery_voltage_values), 2)
            battery_stats['max_voltage'] = round(max(battery_voltage_values), 2)

    # Aggregate watering events
    watering_events = 0
    total_ml = 0
    auto_events = 0
    manual_events = 0

    for item in items:
        pump = item.get('pump', {})
        if pump.get('action') == 'stop':
            watering_events += 1
            ml = pump.get('volume_ml', 0) or pump.get('ml', 0)
            if ml:
                total_ml += int(ml)

            source = pump.get('source', 'unknown')
            if source in ['sensor', 'timer', 'auto']:
                auto_events += 1
            else:
                manual_events += 1

    watering_stats = {
        'events_count': watering_events,
        'total_ml': total_ml,
        'auto_events': auto_events,
        'manual_events': manual_events
    }

    # Aggregate system stats
    online_readings = 0
    offline_readings = 0
    restarts = 0
    firmware_version = None

    for item in items:
        system = item.get('system', {})

        # Count online/offline
        wifi = system.get('wifi_connected', True)
        if wifi:
            online_readings += 1
        else:
            offline_readings += 1

        # Count restarts (boot_reason)
        boot = system.get('boot_reason')
        if boot:
            restarts += 1

        # Get latest firmware version
        fw = system.get('firmware_version') or system.get('version')
        if fw:
            firmware_version = fw

    # Estimate hours based on readings (assuming 30 min intervals)
    total_readings = online_readings + offline_readings
    if total_readings > 0:
        online_hours = round(online_readings * 0.5, 1)  # 30 min per reading
        offline_hours = round(offline_readings * 0.5, 1)
    else:
        online_hours = 0
        offline_hours = 0

    system_stats = {
        'online_hours': online_hours,
        'offline_hours': offline_hours,
        'restarts': restarts,
        'firmware_version': firmware_version
    }

    # Aggregate health diagnostics
    rssi_values = []
    wifi_disconnect_values = []
    unexpected_restart_values = []
    heap_values = []
    brownout_count = 0
    crash_count = 0

    for item in items:
        system = item.get('system', {})

        rssi = system.get('sta_rssi')
        if rssi is not None:
            rssi_values.append(int(rssi))

        wdc = system.get('wifi_disconnect_count')
        if wdc is not None:
            wifi_disconnect_values.append(int(wdc))

        ur = system.get('unexpected_restarts')
        if ur is not None:
            unexpected_restart_values.append(int(ur))

        heap = system.get('heap_free')
        if heap is not None:
            heap_values.append(int(heap))

        # Count brownouts and crashes from boot_type/reset_reason
        bt = system.get('boot_type', '')
        rr = system.get('reset_reason', '')
        if bt and 'BROWNOUT' in str(bt).upper():
            brownout_count += 1
        if rr and any(x in str(rr).upper() for x in ['PANIC', 'CRASH', 'WATCHDOG']):
            crash_count += 1

    health_stats = None
    if rssi_values or wifi_disconnect_values or brownout_count or crash_count:
        health_stats = {}
        if rssi_values:
            health_stats['avg_rssi'] = round(sum(rssi_values) / len(rssi_values))
            health_stats['min_rssi'] = min(rssi_values)
            health_stats['max_rssi'] = max(rssi_values)
        if wifi_disconnect_values:
            # Cumulative counter: delta = max - min for the period
            health_stats['wifi_disconnects'] = max(wifi_disconnect_values) - min(wifi_disconnect_values)
        if unexpected_restart_values:
            health_stats['unexpected_restarts'] = max(unexpected_restart_values) - min(unexpected_restart_values)
        if heap_values:
            health_stats['avg_heap_free'] = round(sum(heap_values) / len(heap_values))
            health_stats['min_heap_free'] = min(heap_values)
        if brownout_count:
            health_stats['brownouts'] = brownout_count
        if crash_count:
            health_stats['crashes'] = crash_count

    result = {
        'moisture': moisture_stats,
        'battery': battery_stats,
        'watering': watering_stats,
        'system': system_stats,
        'raw': raw_points
    }

    # Add sensor2 if present
    if sensor2_stats:
        result['sensor2'] = sensor2_stats

    # Add health diagnostics if present
    if health_stats:
        result['health'] = health_stats

    return result


def github_api_request(method, path, data=None):
    """Make a request to GitHub API"""
    url = f"https://api.github.com/repos/{GITHUB_REPO}/{path}"

    headers = {
        'Authorization': f'token {GITHUB_TOKEN}',
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'Polivalka-WeeklyAggregator'
    }

    body = None
    if data:
        body = json.dumps(data).encode('utf-8')
        headers['Content-Type'] = 'application/json'

    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        error_body = e.read().decode('utf-8')
        print(f"[ERROR] GitHub API error {e.code}: {error_body}")
        raise


def get_github_file(path):
    """Get file content from GitHub"""
    result = github_api_request('GET', f'contents/{path}?ref={GITHUB_BRANCH}')
    if result and 'content' in result:
        content = base64.b64decode(result['content']).decode('utf-8')
        return {
            'content': json.loads(content),
            'sha': result['sha']
        }
    return None


def put_github_file(path, content, sha=None, message=None):
    """Create or update file on GitHub"""
    # Compact JSON (no spaces) to minimize file size — raw points can be large
    encoded_content = base64.b64encode(json.dumps(content, separators=(',', ':'), default=decimal_default).encode('utf-8')).decode('utf-8')

    data = {
        'message': message or f'Update {path}',
        'content': encoded_content,
        'branch': GITHUB_BRANCH
    }

    if sha:
        data['sha'] = sha

    return github_api_request('PUT', f'contents/{path}', data)


def update_device_weekly_data(device_id, week_summary):
    """Update weekly data file for a device"""

    # Extract short ID (BB00C1 from Polivalka-BB00C1)
    short_id = device_id.replace('Polivalka-', '')
    file_path = f'data/weekly/{short_id}.json'

    # Try to get existing file
    existing = get_github_file(file_path)

    if existing:
        # Update existing file
        data = existing['content']
        summaries = data.get('summaries', [])

        # Check if this week already exists (update if so)
        week_exists = False
        for i, s in enumerate(summaries):
            if s.get('week') == week_summary['week']:
                summaries[i] = week_summary
                week_exists = True
                break

        if not week_exists:
            summaries.append(week_summary)

        # Sort by week descending
        summaries.sort(key=lambda x: x['week'], reverse=True)

        data['summaries'] = summaries
        data['last_updated'] = datetime.utcnow().isoformat() + 'Z'

        put_github_file(
            file_path,
            data,
            sha=existing['sha'],
            message=f'Update weekly data for {short_id} ({week_summary["week"]})'
        )

    else:
        # Create new file
        data = {
            'device_id': short_id,
            'last_updated': datetime.utcnow().isoformat() + 'Z',
            'summaries': [week_summary]
        }

        put_github_file(
            file_path,
            data,
            message=f'Create weekly data for {short_id}'
        )

    print(f"[INFO] Updated weekly data for {device_id}")


def lambda_handler(event, context):
    """Main Lambda handler"""

    print(f"[INFO] Starting weekly aggregation")

    # Validate GitHub token
    if not GITHUB_TOKEN:
        print("[ERROR] GITHUB_TOKEN not set")
        return {'statusCode': 500, 'body': 'GITHUB_TOKEN not configured'}

    # Get week info (supports target_week for backfill: {"target_week": "2026-W05"})
    target_week = event.get('target_week') if isinstance(event, dict) else None
    week_info = get_week_info(target_week=target_week)
    print(f"[INFO] Processing week {week_info['week']} ({week_info['start_date']} to {week_info['end_date']})")

    # Get all active devices
    devices = get_all_devices()
    print(f"[INFO] Found {len(devices)} active devices")

    processed = 0
    errors = 0

    for device_id in devices:
        try:
            # Aggregate data
            stats = aggregate_device_data(
                device_id,
                week_info['start_timestamp'],
                week_info['end_timestamp']
            )

            if stats:
                # Create week summary
                week_summary = {
                    'week': week_info['week'],
                    'start_date': week_info['start_date'],
                    'end_date': week_info['end_date'],
                    'generated_at': datetime.utcnow().isoformat() + 'Z',
                    **stats
                }

                # Update GitHub
                update_device_weekly_data(device_id, week_summary)
                processed += 1
            else:
                print(f"[INFO] No data for {device_id} this week")

        except Exception as e:
            print(f"[ERROR] Failed to process {device_id}: {e}")
            errors += 1

    result = {
        'week': week_info['week'],
        'devices_processed': processed,
        'errors': errors
    }

    print(f"[INFO] Aggregation complete: {result}")

    return {
        'statusCode': 200,
        'body': json.dumps(result)
    }


# For local testing
if __name__ == '__main__':
    # Test with mock event
    result = lambda_handler({}, None)
    print(result)
