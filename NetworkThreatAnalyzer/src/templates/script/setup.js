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
        // TO_DO