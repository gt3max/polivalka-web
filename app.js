/**
 * Polivalka Dashboard - Main Application Logic
 */

let chart = null;

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    // Check if API is configured
    if (!isAPIConfigured()) {
        showError('⚠️ API not configured. Please update API_BASE in api.js with your Lambda URL');
        return;
    }

    // Load initial data
    loadData();

    // Refresh data every minute
    setInterval(loadData, 60000);
});

/**
 * Load current device data and history
 */
async function loadData() {
    try {
        updateStatus('Loading data...');

        const data = await getSensorData(DEVICE_ID, 7);

        // Update current values
        if (data.latest) {
            document.getElementById('moisture').textContent = data.latest.moisture_pct || '--';
            document.getElementById('battery').textContent =
                data.latest.battery_v ? data.latest.battery_v.toFixed(2) : '--';

            // Format timestamp
            if (data.latest.timestamp) {
                const date = new Date(data.latest.timestamp * 1000);
                document.getElementById('last-update').textContent =
                    date.toLocaleString('en-US', {
                        month: 'short',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit'
                    });
            }

            updateStatus('✅ Connected');
        } else {
            updateStatus('⚠️ No data available');
        }

        // Draw chart
        if (data.history && data.history.length > 0) {
            drawChart(data.history);
        }
    } catch (error) {
        console.error('Error loading data:', error);
        updateStatus('❌ Error loading data');
    }
}

/**
 * Water plant command
 */
async function waterPlant() {
    try {
        updateStatus('💧 Sending water command...');
        logCommand('Water Plant (10 sec)');

        const result = await sendCommand(DEVICE_ID, {
            action: 'water',
            duration_sec: 10
        });

        updateStatus('✅ Water command sent');
        logCommand(`✓ Command ID: ${result.command_id}`, 'success');

        // Refresh data after 15 seconds
        setTimeout(loadData, 15000);
    } catch (error) {
        console.error('Error watering plant:', error);
        updateStatus('❌ Error sending command');
        logCommand('✗ Failed to send command', 'error');
    }
}

/**
 * Read sensor command
 */
async function readSensor() {
    try {
        updateStatus('📊 Reading sensor...');
        logCommand('Read Sensor');

        const result = await sendCommand(DEVICE_ID, {
            action: 'read_sensor'
        });

        updateStatus('✅ Sensor read requested');
        logCommand(`✓ Command ID: ${result.command_id}`, 'success');

        // Refresh data after 5 seconds
        setTimeout(loadData, 5000);
    } catch (error) {
        console.error('Error reading sensor:', error);
        updateStatus('❌ Error sending command');
        logCommand('✗ Failed to send command', 'error');
    }
}

/**
 * Stop pump command
 */
async function stopPump() {
    try {
        updateStatus('🛑 Stopping pump...');
        logCommand('Stop Pump');

        const result = await sendCommand(DEVICE_ID, {
            action: 'stop'
        });

        updateStatus('✅ Stop command sent');
        logCommand(`✓ Command ID: ${result.command_id}`, 'success');
    } catch (error) {
        console.error('Error stopping pump:', error);
        updateStatus('❌ Error sending command');
        logCommand('✗ Failed to send command', 'error');
    }
}

/**
 * Update status text
 */
function updateStatus(text) {
    document.getElementById('status').textContent = text;
}

/**
 * Show error message
 */
function showError(message) {
    updateStatus(message);
}

/**
 * Log command to command log
 */
function logCommand(message, type = 'info') {
    const log = document.getElementById('command-log');
    const entry = document.createElement('div');
    entry.className = `log-entry log-${type}`;

    const time = new Date().toLocaleTimeString('en-US', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });

    entry.textContent = `[${time}] ${message}`;
    log.insertBefore(entry, log.firstChild);

    // Keep only last 10 entries
    while (log.children.length > 10) {
        log.removeChild(log.lastChild);
    }
}

/**
 * Draw moisture chart
 */
function drawChart(history) {
    const canvas = document.getElementById('moistureChart');
    const ctx = canvas.getContext('2d');

    // Sort by timestamp (oldest first)
    const sorted = history.sort((a, b) => a.timestamp - b.timestamp);

    // Prepare data
    const labels = sorted.map((item) => {
        const date = new Date(item.timestamp * 1000);
        return date.toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric',
            hour: '2-digit'
        });
    });

    const moistureData = sorted.map((item) => item.moisture_pct);

    // Destroy existing chart
    if (chart) {
        chart.destroy();
    }

    // Create new chart
    chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Moisture %',
                    data: moistureData,
                    borderColor: '#4caf50',
                    backgroundColor: 'rgba(76, 175, 80, 0.1)',
                    tension: 0.4,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: true,
                    position: 'top'
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    ticks: {
                        callback: function (value) {
                            return value + '%';
                        }
                    }
                }
            }
        }
    });
}
