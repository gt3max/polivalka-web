# 🌱 Polivalka Remote Dashboard

Remote web dashboard for Polivalka plant watering system.

## Architecture

**Frontend:** GitHub Pages (static HTML/CSS/JS)
**Backend:** AWS Lambda + API Gateway
**Communication:** AWS IoT Core (MQTT)
**Database:** DynamoDB

```
Browser → GitHub Pages → API Gateway → Lambda → AWS IoT MQTT → ESP32
                                      ↓
                                  DynamoDB
```

## Setup

### 1. Deploy Lambda Functions

See `lambda/` directory for Python code:
- `command_handler.py` - Send commands to device
- `sensor_data_handler.py` - Get sensor history
- `devices_handler.py` - List devices

Deploy to AWS Lambda and create API Gateway endpoints.

### 2. Configure Frontend

Update `api.js`:
```javascript
const API_BASE = 'https://YOUR_API_GATEWAY_ID.execute-api.us-east-1.amazonaws.com';
```

### 3. Enable GitHub Pages

1. Go to repository Settings
2. Pages → Source: `main` branch
3. Save

Your site will be available at:
`https://maximshurygin.github.io/polivalka-web/`

## Features

- ✅ Real-time device status
- ✅ Remote water control
- ✅ Sensor reading
- ✅ Emergency stop
- ✅ 7-day moisture history chart
- ✅ Command log

## Device Commands

### Water Plant
```json
{
  "action": "water",
  "duration_sec": 10
}
```

### Read Sensor
```json
{
  "action": "read_sensor"
}
```

### Stop Pump
```json
{
  "action": "stop"
}
```

## Cost

**Total: $0-12/year**

- GitHub Pages: $0 (unlimited traffic)
- AWS Lambda: $0 (1M requests/month free tier)
- API Gateway: $0 first year, $0.26/year after
- DynamoDB: $0 (25GB free tier)
- Domain (optional): $12/year

## Development

Local testing:
```bash
python3 -m http.server 8080
open http://localhost:8080
```

## License

MIT
