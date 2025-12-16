import json, csv, os, tempfile, re
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, Union, List

try:
    from weasyprint import HTML

    HAS_WEASYPRINT = True
except ImportError:
    HAS_WEASYPRINT = False


# Generate reports in CSV, PDF, HTML, and JSON formats.
class ReportGenerator:
    TOOL_VERSION = '1.0.0'
    REPORT_TYPE = 'threat_intelligence'

    def __init__(self, output_dir='reports'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _secure_filename(self, filename: str) -> str:
        # Remove any directory components first
        filename = os.path.basename(filename)

        # Remove any potentially dangerous characters
        # Allow only alphanumeric, dots, hyphens, underscores, and spaces
        filename = re.sub(r'[^\w\-. ]', '', filename)
        # Remove any attempt at path traversal
        filename = filename.replace('..', '').replace('//', '').replace('\\', '')
        # Ensure we have a valid filename
        if not filename or filename in ('.', '..'):
            # Generate a safe default filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            return f"threat_report_{timestamp}"
        return filename

    def _generate_default_filename(self, extension: str) -> str:
        # Generate a default filename with timestamp.
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"threat_report_{timestamp}{extension}"

    def _validate_and_prepare_path(self, filename: Optional[str], default_extension: str) -> Path:
        # Validate filename and prepare full file path.
        if not filename:
            filename = self._generate_default_filename(default_extension)
        else:
            filename = self._secure_filename(filename)

            # Ensure correct extension
            if not filename.endswith(default_extension):
                # Remove any existing extension and add the correct one
                base_name = os.path.splitext(filename)[0]
                filename = f"{base_name}{default_extension}"
        return self.output_dir / filename

    # Generate HTML report
    def generate_html_repot(self, results: Dict[str, Any], filename: Optional[str] = None) -> str:
        try:
            if not results or isinstance(results, dict):
                raise ValueError("Invalid results data provided")
            filepath = self._validate_and_prepare_path(filename, '.html')
            # Extract summary and threat data
            summary = self._generate_summary(results)
            threat_data = self._extract_threat_data(results)

            # Generate HTML content
            html_content = self._create_html_template(summary, threat_data)

            # Write to file
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"HTML report generated: {filepath}")
            return str(filepath)
        except Exception as e:
            raise RuntimeError(f"Failed to generate HTML report: {str(e)}")

    # Generate JSON report
    def generate_json_report(self, results: Dict[str, Any], filename: Optional[str] = None) -> str:
        try:
            if not results or not isinstance(results, dict):
                raise ValueError("Invalid results data provided")
            filepath = self._validate_and_prepare_path(filename, '.json')

            report_data = {
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'tool_version': self.TOOL_VERSION,
                    'report_type': self.REPORT_TYPE
                },
                'summary': self._generate_summary(results),
                'detailed_results': results
            }
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, default=str)

            print(f"JSON report generated: {filepath}")
            return str(filepath)
        except Exception as e:
            raise RuntimeError(f"Failed to generate JSON report: {str(e)}")

    # Generate CSV report
    def generate_csv_report(self, results: Dict[str, Any], filename: Optional[str] = None) -> str:
        try:
            if not results or not isinstance(results, dict):
                raise ValueError("Invalid results data provided")

            filepath = self._validate_and_prepare_path(filename, '.csv')
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)

                # Write headers
                writer.writerow([
                    'IP Address', 'Is Malicious', 'Threat Level',
                    'Abuse Score', 'Total Reports', 'ISP', 'Country',
                    'FireHOL Listed', 'Blocklist', 'Last Reported'
                ])
                # Write data rows
                threat_results = results.get('threat_results', {})
                if not threat_results:
                    print("Warning: No threat results found in data")

                for ip, data in threat_results.items():
                    abuse_data = data.get('details', {}).get('abuseipdb', {})
                    firehol_data = data.get('details', {}).get('firehol', {})

                    writer.writerow([
                        ip,
                        data.get('is_malicious', False),
                        data.get('threat_level', 'low'),
                        abuse_data.get('abuseConfidenceScore', 0),
                        abuse_data.get('totalReports', 0),
                        abuse_data.get('isp', 'Unknown'),
                        abuse_data.get('countryCode', 'Unknown'),
                        firehol_data.get('listed', False),
                        firehol_data.get('blocklist', ''),
                        abuse_data.get('lastReportedAt', '')
                    ])

            print(f"CSV report generated: {filepath}")
            return str(filepath)
        except Exception as e:
            raise RuntimeError(f"Failed to generate CSV report: {str(e)}")

    # Generate PDF report
    def generate_pdf_report(self, results: Dict[str, Any], filename: Optional[str] = None) -> str:
        try:
            if not results or not isinstance(results, dict):
                raise ValueError("Invalid results data provided")
            filepath = self._validate_and_prepare_path(filename, '.pdf')

            # Create temporary HTML file
            with tempfile.NamedTemporaryFile(
                    mode='w',
                    suffix='.html',
                    encoding='utf-8',
                    delete=False
            ) as tmp:
                # Generate HTML directly
                summary = self._generate_summary(results)
                threat_data = self._extract_threat_data(results)
                html_content = self._create_html_template(summary, threat_data)
                tmp.write(html_content)
                temp_html_path = tmp.name
            try:
                # Convert HTML to PDF
                HTML(temp_html_path).write_pdf(filepath)
                print(f"PDF report generated: {filepath}")
                return str(filepath)
            finally:
                # Always clean up tmp HTML file
                if os.path.exists(temp_html_path):
                    os.unlink(temp_html_path)

        except Exception as e:
            # Clean up tmp file even if generation fails
            if 'temp_html_path' in locals() and os.path.exists(temp_html_path):
                os.unlink(temp_html_path)
            raise RuntimeError(f"Failed to generate PDF report: {str(e)}")

    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        threat_results = results.get('threat_results', {})
        total_ips = len(threat_results)
        malicious_ips = 0
        high_threats = 0
        medium_threats = 0
        low_threats = 0
        malicious_scores = []
        for data in threat_results.values():
            is_malicious = data.get('is_malicious', False)
            threat_level = data.get('threat_level')
            if is_malicious:
                malicious_ips += 1
                if threat_level == 'high':
                    high_threats += 1
                elif threat_level == 'medium':
                    medium_threats += 1
            if threat_level == 'low':
                 low_threats += 1
            score = data.get('details', {}).get('abuseipdb', {}).get('abuseConfidenceScore', 0)
            malicious_scores.append(score)
        avg_abuse_score = sum(malicious_scores) / len(malicious_scores) if malicious_scores else 0
        return {
            'total_ips_checked': total_ips,
            'malicious_ips_found': malicious_ips,
            'high_threat_ips': high_threats,
            'medium_threat_ips': medium_threats,
            'low_threat_ips': low_threats,
            'clean_ips':  total_ips - malicious_ips,
            'threat_percentage': (malicious_ips / total_ips * 100) if total_ips > 0 else 0,
            'average_abuse_score': round(avg_abuse_score, 2),
            'generated_at': datetime.now().isoformat()
        }

    # Extract and organize threat data
    def _extract_threat_data(self, results: Dict[str, Any]) -> Dict[str, List[Dict]]:
        threat_results = results.get('threat_results', {})
        high_threats = []
        medium_threats = []
        low_threats = []

        for ip, data in threat_results.items():
            threat_info = {
                'ip': ip,
                'threat_level': data.get('threat_level'),
                'abuse_score': data.get('details', {}).get('abuseipdb', {}).get('abuseConfidenceScore', 0),
                'total_reports': data.get('details', {}).get('abuseipdb', {}).get('totalReports', 0),
                'isp': data.get('details', {}).get('abuseipdb', {}).get('countryCode', 'Unknown'),
                'country': data.get('details', {}).get('abuseipdb', {}).get('countryCode', 'Unknown'),
                'firehol_listed': data.get('details', {}).get('firehol', {}).get('listed', False),
                'blocklist': data.get('details', {}).get('firehol', {}).get('blocklist', ''),
            }
            if data.get('is_malicious', False):
                if data.get('threat_level') == 'high':
                    high_threats.append(threat_info)
                elif data.get('threat_level') == 'medium':
                    medium_threats.append(threat_info)
            else:
                if data.get('threat_level') == 'low':
                    low_threats.append(threat_info)
        high_threats.sort(key=lambda x: x['abuse_score'], reverse=True)
        medium_threats.sort(key=lambda x: x['abuse_score'], reverse=True)
        low_threats.sort(key=lambda x: x['abuse_score'], reverse=True)
        return {
            'high_threats': high_threats,
            'medium_threats': medium_threats,
            'low_threats': low_threats
        }

    # HTML report template
    def _create_html_template(self, summary: Dict[str, Any], threat_data: Dict[str, List[Dict]]) -> str:
        # Escape special characters to prevent XSS
        def escape_html(text):
            if not isinstance(text, str):
                text = str(text)
            return (text.replace('&', '&amp;')
                    .replace('<', '&lt;')
                    .replace('>', '&gt;')
                    .replace('"', '&quot;')
                    .replace("'", '&#x27;'))

        # Generate threat tables HTML
        high_threats_html = self._create_threat_section_html(
            'High Threats', threat_data['high_threats'], 'high-threat'
        )
        medium_threats_html = self._create_threat_section_html(
            'Medium Threats', threat_data['medium_threats'], 'medium-threat'
        )
        low_threats_html = self._create_threat_section_html(
            'Low Threats / Clean Ips', threat_data['low_threats'], 'low-threat'
        )
        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Network Threat Intelligence Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; color: #333; }}
                .header {{ text-align: center; border-bottom: 2px solid #007cba; padding-bottom: 20px; margin-bottom: 30px; }}
                .summary {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 30px; }}
                .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }}
                .stat-card {{ background: white; padding: 15px; border-radius: 6px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .stat-number {{ font-size: 24px; font-weight: bold; margin-bottom: 5px; }}
                .stat-danger {{ color: #dc3545; }}
                .stat-warning {{ color: #ffc107; }}
                .stat-success {{ color: #28a745; }}
                .threat-section {{ margin-bottom: 30px; }}
                .threat-table {{ width: 100%; border-collapse: collapse; }}
                .threat-table th, .threat-table td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                .threat-table th {{ background: #007cba; color: white; }}
                .high-threat {{ background: #ffe6e6; }}
                .medium-threat {{ background: #fff3cd; }}
                .low-threat {{ background: ##d9ead3 }} 
                .footer {{ margin-top: 40px; text-align: center; color: #666; font-size: 0.9em; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Network Threat Intelligence Report</h1>
                <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>

            <div class="summary">
                <h2>Executive Summary</h2>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number">{escape_html(summary['total_ips_checked'])}</div>
                        <div>Total IPs Checked</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number stat-danger">{escape_html(summary['malicious_ips_found'])}</div>
                        <div>Malicious IPs Found</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number stat-danger">{escape_html(summary['high_threat_ips'])}</div>
                        <div>High Threat IPs</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number stat-warning">{escape_html(summary['medium_threat_ips'])}</div>
                        <div>Medium Threat IPs</div>
                    </div>
                     <div class="stat-card">
                        <div class="stat-number stat-success">{escape_html(summary['low_threat_ips'])}</div>
                        <div>Clean IPs</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{escape_html(f"{summary['threat_percentage']:.1f}%")}</div>
                        <div>Threat Percentage</div>
                    </div>
                </div>
            </div>

            {high_threats_html}
            {medium_threats_html}
            {low_threats_html}

            <div class="footer">
                <p>Report generated by Network Threat Analyzer | Confidential Security Document</p>
            </div>
        </body>
        </html>
                """

    # HTML Threat section
    def _create_threat_section_html(self, title: str, threats: List[Dict], css_class: str) -> str:
        if not threats:
            return f'<div class="threat-section"><h3>{title}</h3><p>No {title.lower()} found.</p></div>'
        rows = ''
        for threat in threats:
            rows += f"""
            <tr class="{css_class}">
                <td>{threat['ip']}</td>
                <td>{threat['threat_level']}</td>
                <td>{threat['abuse_score']}%</td>
                <td>{threat['total_reports']}</td>
                <td>{threat['isp']}</td>
                <td>{threat['country']}</td>
                <td>{'Yes' if threat['firehol_listed'] else 'No'}</td>
                <td>{threat.get('blocklist', '')}</td>
            </tr>
            """
        return f"""
                <div class="threat-section">
                    <h2>{title} ({len(threats)})</h2>
                    <table class="threat-table">
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>Threat Level</th>
                                <th>Abuse Score</th>
                                <th>Total Reports</th>
                                <th>ISP</th>
                                <th>Country</th>
                                <th>FireHOL Listed</th>
                                <th>Blocklist</th>
                            </tr>
                        </thead>
                        <tbody>
                            {rows}
                        </tbody>
                    </table>
                </div>
                """

    def generate_all_reports(self, results: Dict[str, Any], base_filename: Optional[str] = None) -> Dict[str, str]:
        if not base_filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            base_filename = f"threat_report_{timestamp}"

        reports = {}
        try:
            reports['html'] = self.generate_html_repot(results, f"{base_filename}.html")
            reports['json'] = self.generate_json_report(results, f"{base_filename}.json")
            reports['csv'] = self.generate_csv_report(results, f"{base_filename}.csv")

            try:
                reports['pdf'] = self.generate_pdf_report(results, f"{base_filename}.pdf")
            except ImportError as e:
                print(f"Warning: PDF generation skipped - {e}")
                reports['pdf'] = None
        except Exception as e:
            raise RuntimeError(f"Failed to generate all reports: {str(e)}")
        return reports
