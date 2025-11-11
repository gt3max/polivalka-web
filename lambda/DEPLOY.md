# Lambda Deployment Guide

## Prerequisites

1. AWS CLI installed and configured
2. AWS account with appropriate permissions
3. DynamoDB table created: `polivalka_sensor_data`

## Step 1: Create IAM Role for Lambda

Create IAM role with these permissions:
- AWSLambdaBasicExecutionRole (CloudWatch Logs)
- AWSIoTDataAccess (MQTT publish)
- AmazonDynamoDBReadOnlyAccess (read sensor data)

```bash
# Create trust policy
cat > trust-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

# Create role
aws iam create-role \
  --role-name PolivalkaLambdaRole \
  --assume-role-policy-document file://trust-policy.json

# Attach policies
aws iam attach-role-policy \
  --role-name PolivalkaLambdaRole \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

aws iam attach-role-policy \
  --role-name PolivalkaLambdaRole \
  --policy-arn arn:aws:iam::aws:policy/AWSIoTDataAccess

aws iam attach-role-policy \
  --role-name PolivalkaLambdaRole \
  --policy-arn arn:aws:iam::aws:policy/AmazonDynamoDBReadOnlyAccess
```

## Step 2: Package Lambda Functions

```bash
cd lambda

# Package command handler
zip command_handler.zip command_handler.py

# Package sensor data handler
zip sensor_data_handler.zip sensor_data_handler.py
```

## Step 3: Deploy Lambda Functions

Get your IAM role ARN:
```bash
aws iam get-role --role-name PolivalkaLambdaRole --query 'Role.Arn' --output text
```

Deploy command handler:
```bash
aws lambda create-function \
  --function-name polivalka-command-handler \
  --runtime python3.11 \
  --role arn:aws:iam::YOUR_ACCOUNT_ID:role/PolivalkaLambdaRole \
  --handler command_handler.lambda_handler \
  --zip-file fileb://command_handler.zip \
  --timeout 10 \
  --memory-size 128 \
  --region us-east-1
```

Deploy sensor data handler:
```bash
aws lambda create-function \
  --function-name polivalka-sensor-data-handler \
  --runtime python3.11 \
  --role arn:aws:iam::YOUR_ACCOUNT_ID:role/PolivalkaLambdaRole \
  --handler sensor_data_handler.lambda_handler \
  --zip-file fileb://sensor_data_handler.zip \
  --timeout 10 \
  --memory-size 128 \
  --region us-east-1
```

## Step 4: Create API Gateway (HTTP API)

```bash
# Create HTTP API
aws apigatewayv2 create-api \
  --name polivalka-api \
  --protocol-type HTTP \
  --cors-configuration AllowOrigins="*",AllowMethods="GET,POST,OPTIONS",AllowHeaders="Content-Type"

# Get API ID
API_ID=$(aws apigatewayv2 get-apis --query 'Items[?Name==`polivalka-api`].ApiId' --output text)

echo "API ID: $API_ID"

# Get Lambda ARNs
COMMAND_ARN=$(aws lambda get-function --function-name polivalka-command-handler --query 'Configuration.FunctionArn' --output text)
SENSOR_ARN=$(aws lambda get-function --function-name polivalka-sensor-data-handler --query 'Configuration.FunctionArn' --output text)

# Create integrations
COMMAND_INT=$(aws apigatewayv2 create-integration \
  --api-id $API_ID \
  --integration-type AWS_PROXY \
  --integration-uri $COMMAND_ARN \
  --payload-format-version 2.0 \
  --query 'IntegrationId' --output text)

SENSOR_INT=$(aws apigatewayv2 create-integration \
  --api-id $API_ID \
  --integration-type AWS_PROXY \
  --integration-uri $SENSOR_ARN \
  --payload-format-version 2.0 \
  --query 'IntegrationId' --output text)

# Create routes
aws apigatewayv2 create-route \
  --api-id $API_ID \
  --route-key 'POST /command' \
  --target integrations/$COMMAND_INT

aws apigatewayv2 create-route \
  --api-id $API_ID \
  --route-key 'GET /sensor-data' \
  --target integrations/$SENSOR_INT

# Create stage
aws apigatewayv2 create-stage \
  --api-id $API_ID \
  --stage-name prod \
  --auto-deploy

# Grant API Gateway permission to invoke Lambda
aws lambda add-permission \
  --function-name polivalka-command-handler \
  --statement-id apigateway-invoke \
  --action lambda:InvokeFunction \
  --principal apigateway.amazonaws.com \
  --source-arn "arn:aws:execute-api:us-east-1:YOUR_ACCOUNT_ID:${API_ID}/*/*"

aws lambda add-permission \
  --function-name polivalka-sensor-data-handler \
  --statement-id apigateway-invoke \
  --action lambda:InvokeFunction \
  --principal apigateway.amazonaws.com \
  --source-arn "arn:aws:execute-api:us-east-1:YOUR_ACCOUNT_ID:${API_ID}/*/*"

# Get API URL
echo "API URL: https://${API_ID}.execute-api.us-east-1.amazonaws.com"
```

## Step 5: Update Frontend

Copy the API URL and update `api.js`:

```javascript
const API_BASE = 'https://YOUR_API_ID.execute-api.us-east-1.amazonaws.com';
```

## Step 6: Test

Test command endpoint:
```bash
curl -X POST https://YOUR_API_ID.execute-api.us-east-1.amazonaws.com/command \
  -H "Content-Type: application/json" \
  -d '{
    "device_id": "BC67E9",
    "command": {
      "action": "read_sensor"
    }
  }'
```

Test sensor data endpoint:
```bash
curl "https://YOUR_API_ID.execute-api.us-east-1.amazonaws.com/sensor-data?device_id=BC67E9&days=7"
```

## Update Lambda Functions (after changes)

```bash
# Update command handler
zip command_handler.zip command_handler.py
aws lambda update-function-code \
  --function-name polivalka-command-handler \
  --zip-file fileb://command_handler.zip

# Update sensor data handler
zip sensor_data_handler.zip sensor_data_handler.py
aws lambda update-function-code \
  --function-name polivalka-sensor-data-handler \
  --zip-file fileb://sensor_data_handler.zip
```

## Monitoring

View logs:
```bash
aws logs tail /aws/lambda/polivalka-command-handler --follow
aws logs tail /aws/lambda/polivalka-sensor-data-handler --follow
```

## Cost Estimate

**Free Tier (first 12 months + forever):**
- Lambda: 1M requests/month (forever free)
- API Gateway: 1M requests/month (12 months free)
- DynamoDB: 25GB + 25 read/write units (forever free)
- CloudWatch Logs: 5GB (forever free)

**After 12 months (for 1000 requests/month):**
- Lambda: $0
- API Gateway: $0.0035
- DynamoDB: $0
- **Total: ~$0.04/month = $0.48/year**

## Troubleshooting

**Lambda function not found:**
- Check region (must be us-east-1)
- Check function name spelling

**Permission denied:**
- Verify IAM role has correct policies attached
- Check Lambda resource-based policy for API Gateway

**CORS errors:**
- Verify CORS headers in Lambda response
- Check API Gateway CORS configuration

**No data in DynamoDB:**
- ESP32 must be running and publishing sensor data
- Check DynamoDB table name matches code
- Verify ESP32 is connected to AWS IoT
