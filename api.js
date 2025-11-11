/**
 * API wrapper for AWS Lambda backend
 *
 * SETUP: Replace API_BASE with your actual API Gateway URL after deployment
 */

// API Gateway URL (deployed to AWS)
const API_BASE = 'https://9iv2areho4.execute-api.us-east-1.amazonaws.com';

// Device ID (currently hardcoded, will be dynamic later with auth)
const DEVICE_ID = 'BC67E9';

/**
 * Send command to device via AWS IoT MQTT
 * @param {string} deviceId - Device ID (e.g., 'BC67E9')
 * @param {object} command - Command object {action: 'water', duration_sec: 10}
 * @returns {Promise<object>} - Response with command_id
 */
async function sendCommand(deviceId, command) {
    try {
        const response = await fetch(`${API_BASE}/command`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                // TODO: Add authorization header when Cognito is setup
                // 'Authorization': `Bearer ${getAuthToken()}`
            },
            body: JSON.stringify({
                device_id: deviceId,
                command: command
            })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        return await response.json();
    } catch (error) {
        console.error('Error sending command:', error);
        throw error;
    }
}

/**
 * Get list of devices for current user
 * @returns {Promise<object>} - List of devices
 */
async function getDevices() {
    try {
        const response = await fetch(`${API_BASE}/devices`, {
            headers: {
                // TODO: Add authorization header
                // 'Authorization': `Bearer ${getAuthToken()}`
            }
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        return await response.json();
    } catch (error) {
        console.error('Error fetching devices:', error);
        throw error;
    }
}

/**
 * Get sensor data history for device
 * @param {string} deviceId - Device ID
 * @param {number} days - Number of days of history (default: 7)
 * @returns {Promise<object>} - Sensor data with history
 */
async function getSensorData(deviceId, days = 7) {
    try {
        const response = await fetch(
            `${API_BASE}/sensor-data?device_id=${deviceId}&days=${days}`,
            {
                headers: {
                    // TODO: Add authorization header
                    // 'Authorization': `Bearer ${getAuthToken()}`
                }
            }
        );

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        return await response.json();
    } catch (error) {
        console.error('Error fetching sensor data:', error);
        throw error;
    }
}

/**
 * Check if API is configured
 * @returns {boolean}
 */
function isAPIConfigured() {
    return !API_BASE.includes('YOUR_API_GATEWAY_ID');
}
