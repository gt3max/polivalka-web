#!/bin/bash
# Lambda Deploy Script - deploys with CORRECT filenames
# Usage: ./deploy.sh [function_name]  or  ./deploy.sh all
#
# Maps: local filename -> AWS Lambda function name -> handler
# The zip MUST contain the file matching the handler module name.

set -e

REGION="eu-central-1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Mapping: local_file -> lambda_function_name
declare -A LAMBDA_MAP
LAMBDA_MAP=(
    ["api_handler.py"]="polivalka-api-handler"
    ["iot_rule_response.py"]="ProcessCommandResponseEU"
    ["iot_rule_telemetry.py"]="SaveTelemetryToDynamoDB"
    ["weekly_aggregator.py"]="polivalka-weekly-aggregator"
)

deploy_one() {
    local file="$1"
    local func="${LAMBDA_MAP[$file]}"

    if [ -z "$func" ]; then
        echo "ERROR: Unknown file '$file'. Known files:"
        for f in "${!LAMBDA_MAP[@]}"; do echo "  $f -> ${LAMBDA_MAP[$f]}"; done
        return 1
    fi

    local zipfile="${file%.py}.zip"

    echo "Deploying: $file -> $func"

    # Zip with ORIGINAL filename (not lambda_function.py!)
    cd /tmp
    cp "$SCRIPT_DIR/$file" "$file"
    zip -j "$zipfile" "$file" > /dev/null
    rm "$file"

    # Deploy
    local result
    result=$(aws lambda update-function-code \
        --region "$REGION" \
        --function-name "$func" \
        --zip-file "fileb://$zipfile" \
        --query 'LastModified' \
        --output text 2>&1)

    if [ $? -eq 0 ]; then
        echo "  OK: $func updated at $result"
    else
        echo "  FAILED: $result"
        return 1
    fi

    # Verify: invoke and check for import errors
    echo "  Verifying..."
    local invoke_result
    invoke_result=$(aws lambda invoke \
        --region "$REGION" \
        --function-name "$func" \
        --payload '{}' \
        --log-type Tail \
        --query 'LogResult' \
        --output text /tmp/lambda_invoke_out.json 2>&1)

    # Decode base64 logs and check for ImportModuleError
    if echo "$invoke_result" | base64 -d 2>/dev/null | grep -q "ImportModuleError"; then
        echo "  BROKEN! ImportModuleError detected - wrong filename in zip!"
        echo "  Rolling back..."
        return 1
    else
        echo "  Verified OK"
    fi

    rm -f "/tmp/$zipfile" /tmp/lambda_invoke_out.json
}

# Main
if [ -z "$1" ]; then
    echo "Usage: ./deploy.sh <filename.py>  or  ./deploy.sh all"
    echo ""
    echo "Available:"
    for f in "${!LAMBDA_MAP[@]}"; do echo "  $f -> ${LAMBDA_MAP[$f]}"; done
    exit 0
fi

export PATH="$HOME/Library/Python/3.12/bin:$PATH"

if [ "$1" = "all" ]; then
    echo "Deploying ALL Lambda functions..."
    echo ""
    failed=0
    for file in "${!LAMBDA_MAP[@]}"; do
        deploy_one "$file" || ((failed++))
        echo ""
    done
    if [ $failed -gt 0 ]; then
        echo "DONE with $failed FAILURES!"
        exit 1
    else
        echo "ALL deployed successfully."
    fi
else
    deploy_one "$1"
fi
