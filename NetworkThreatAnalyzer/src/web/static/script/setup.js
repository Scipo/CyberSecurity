        let currentResults = null;

        // Load initial data
        document.addEventListener('DOMContentLoaded', function() {
            loadNetworkInfo();
            loadScanHistory();
            loadConfig();
        });

        function showTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });

            // Show selected tab
            document.getElementById(tabName + 'Tab').classList.add('active');
            document.querySelector(`.tab[onclick="showTab('${tabName}')"]`).classList.add('active');
        }

        async function loadNetworkInfo() {
            try {
                const response = await fetch('/api/network_info');
                const data = await response.json();

                if (!data.error) {
                    document.getElementById('totalConnections').textContent = data.total_connections;
                    document.getElementById('publicIPs').textContent = data.public_ips_count;
                }
            } catch (error) {
                console.error('Error loading network info:', error);
            }
        }

        async function runScan() {
            document.getElementById('loading').style.display = 'block';
            document.getElementById('resultsSection').style.display = 'none';
            document.getElementById('noResults').style.display = 'block';

            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });

                const data = await response.json();

                if (data.success) {
                    currentResults = data.results;
                    displayResults(data.results);
                    loadScanHistory();
                } else {
                    alert('Scan failed: ' + data.error);
                }
            } catch (error) {
                alert('Scan failed: ' + error.message);
            } finally {
                document.getElementById('loading').style.display = 'none';
            }
        }

        function displayResults(results) {
            const threatList = document.getElementById('threatList');
            const noResults = document.getElementById('noResults');
            const resultsSection = document.getElementById('resultsSection');

            if (!results.threat_results || Object.keys(results.threat_results).length === 0) {
                noResults.style.display = 'block';
                resultsSection.style.display = 'none';
                return;
            }

            threatList.innerHTML = '';
            let maliciousCount = 0;
            let highThreatCount = 0;

            Object.entries(results.threat_results).forEach(([ip, data]) => {
                if (data.is_malicious) {
                    maliciousCount++;
                    if (data.threat_level === 'high') highThreatCount++;

                    const threatItem = document.createElement('div');
                    threatItem.className = `threat-item ${data.threat_level}`;

                    const threatLevelClass = data.threat_level === 'high' ? 'threat-high' : 'threat-medium';
                    const threatLevelText = data.threat_level === 'high' ? 'HIGH' : 'MEDIUM';

                    threatItem.innerHTML = `
                        <div class="ip-address">${ip}</div>
                        <span class="threat-level ${threatLevelClass}">${threatLevelText}</span>
                        <div style="margin-top: 10px; font-size: 0.9em;">
                            <strong>Abuse Score:</strong> ${data.details.abuseipdb?.abuseConfidenceScore || 0}% |
                            <strong>Reports:</strong> ${data.details.abuseipdb?.totalReports || 0} |
                            <strong>ISP:</strong> ${data.details.abuseipdb?.isp || 'Unknown'}
                        </div>
                    `;

                    threatList.appendChild(threatItem);
                }
            });

            document.getElementById('maliciousIPs').textContent = maliciousCount;
            document.getElementById('highThreats').textContent = highThreatCount;

            noResults.style.display = 'none';
            resultsSection.style.display = 'block';
            showTab('results');
        }

    async function loadScanHistory() {
            try {
                const response = await fetch('/api/history');
                const history = await response.json();

                const historyList = document.getElementById('historyList');
                historyList.innerHTML = '';

                if (history.length === 0) {
                    historyList.innerHTML = '<p style="text-align: center; color: #6b7280;">No scan history available.</p>';
                    return;
                }

                history.reverse().forEach(scan => {
                    const historyItem = document.createElement('div');
                    historyItem.className = 'history-item';
                    historyItem.onclick = () => loadScanResult(scan.id);

                    historyItem.innerHTML = `
                        <div style="font-weight: bold;">Scan ${scan.id}</div>
                        <div style="font-size: 0.9em; color: #6b7280;">
                            ${new Date(scan.timestamp).toLocaleString()} |
                            IPs: ${scan.total_ips} |
                            Threats: <span style="color: ${scan.malicious_ips > 0 ? '#dc2626' : '#059669'}">${scan.malicious_ips}</span>
                        </div>
                    `;

                    historyList.appendChild(historyItem);
                });
                return historyList;
            } catch (error) {
                console.error('Error loading history:', error);
            }
        }

        async function loadScanResult(scanId) {
            try {
                const response = await fetch(`/api/results/${scanId}`);
                const results = await response.json();

                if (results.error) {
                   alert('Failed to load scan: ' + results.error);
                   return;
                }
                currentResults = results;
                displayResults(results);
            } catch (error) {
                console.error('Error loading scan result:', error);
            }
        }

        async function testAPI() {
            const statusDiv = document.getElementById('apiStatus');
            statusDiv.style.display = 'block';
            statusDiv.innerHTML = '<div style="color: #d97706;">Testing API connection...</div>';

            try {
                const response = await fetch('/api/test_api');
                const data = await response.json();

                if (data.success) {
                    statusDiv.innerHTML = `<div style="color: #059669;">✅ API connection successful! Tested IP: 8.8.8.8</div>`;
                } else {
                    statusDiv.innerHTML = `<div style="color: #dc2626;">❌ API test failed: ${data.error}</div>`;
                }
            } catch (error) {
                statusDiv.innerHTML = `<div style="color: #dc2626;">❌ API test failed: ${error.message}</div>`;
            }
        }

        async function loadConfig() {
            try {
                const response = await fetch('/api/config');
                const config = await response.json();

                // Don't pre-fill API key for security
                document.getElementById('apiKey').value = '';
            } catch (error) {
                console.error('Error loading config:', error);
            }
        }

        async function saveConfig() {
            const apiKey = document.getElementById('apiKey').value;
            const statusDiv = document.getElementById('configStatus');

            if (!apiKey) {
                statusDiv.innerHTML = '<div style="color: #dc2626;">Please enter an API key</div>';
                return;
            }

            try {
                const response = await fetch('/api/config', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        'ABUSEIPDB_API_KEY': apiKey
                    })
                });

                const data = await response.json();

                if (data.success) {
                    statusDiv.innerHTML = '<div style="color: #059669;">Configuration saved successfully!</div>';
                    document.getElementById('apiKey').value = '';
                } else {
                    statusDiv.innerHTML = `<div style="color: #dc2626;">Failed to save configuration: ${data.error}</div>`;
                }
            } catch (error) {
                statusDiv.innerHTML = `<div style="color: #dc2626;">Error saving configuration: ${error.message}</div>`;
            }
        }