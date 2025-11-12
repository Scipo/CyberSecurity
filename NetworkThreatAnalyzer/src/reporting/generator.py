""""
Reporting module support formats - CSV, PDF, HTML
"""

import json
import csv
import os

from datetime import datetime
from pathlib import Path

try:
    from weasyprint import HTML
    HAS_WEASYPRINT = True
except ImportError:
    HAS_WEASYPRINT = False


# Generate reports in CSV, PDF, HTML
class ReportGenerator:

    def __init__(self, output_dir='reports'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

    # Generate HTML report
    def generate_html_report(self, results, filename=None):
        if not filename:
            filename = f"threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

        filepath = self.output_dir / filename

        # Extract summary data
        summary = self._generate_summary(results)
        threat_data = self._extract_threat_data(results)

        html_content = self._create_html_template(summary, threat_data)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return str(filepath)

    # Generate JSON report
    def generate_json_report(self, results, filename=None):
        if not filename:
            filename = f"threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        filepath = self.output_dir / filename

        report_data = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'tool_version': '1.0.0',
                'report_type': 'threat_intelligence'
            },
            'summary': self._generate_summary(results),
            'detailed_results': results
        }

        with open(filepath, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)

        return str(filepath)

    # Generate CVS report
    def generate_csv_report(self, results, filename=None):

        if not filename:
            filename = f"threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

        filepath = self.output_dir / filename

        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # Write header
            writer.writerow([
                'IP Address', 'Is Malicious', 'Threat Level',
                'Abuse Score', 'Total Reports', 'ISP', 'Country',
                'FireHOL Listed', 'Blocklist', 'Last Reported'
            ])

            # Write data
            for ip, data in results.get('threat_results', {}).items():
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

        return str(filepath)

    # Generate PDF
    def generate_pdf_report(self, results, filename=None):
        if not HAS_WEASYPRINT:
            raise ImportError("WeasyPrint is required for PDF generation. Install with: pip install weasyprint")

        if not filename:
            filename = f"threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

        filepath = self.output_dir / filename

        # First generate HTML report
        html_file = self.generate_html_report(results, filename.replace('.pdf', '.html'))

        # Convert HTML to PDF
        HTML(html_file).write_pdf(filepath)

        # Remove temporary HTML file
        os.remove(html_file)

        return str(filepath)

    # Generate summery
    def _generate_summary(self, results):
        threat_results = results.get('threat_results', {})
        total_ips = len(threat_results)
        malicious_ips = sum(1 for r in threat_results.values() if r.get('is_malicious', False))
        high_threats = sum(1 for r in threat_results.values() if r.get('threat_level') == 'high')
        medium_threats = sum(1 for r in threat_results.values() if r.get('threat_level') == 'medium')

        # Calculate average abuse score for malicious IPs
        malicious_score = [
            r.get('details', {}).get('abuseipdb', {}).get('abuseConfidenceScore', 0)
            for r in threat_results.values()
            if r.get('is_malicious', False)
        ]

        avg_abuse_score = sum(malicious_score) / len(malicious_score) if malicious_score else 0
        return {
            'total_ips_checked': total_ips,
            'malicious_ips_found': malicious_ips,
            'high_threat_ips': high_threats,
            'medium_threat_ips': medium_threats,
            'clean_ips': total_ips - malicious_ips,
            'threat_percentage': (malicious_ips / total_ips * 100) if total_ips > 0 else 0,
            'average_abuse_score': round(avg_abuse_score, 2),
            'generated_at': datetime.now().isoformat()
        }

    # Extract and organized threat data
    def _extract_threat_data(self, results):
        threat_results = results.get('threat_results', {})

        high_threats = []
        medium_threats = []

        for ip, data in threat_results.items():
            if data.get('is_malicious', False):
                threat_info = {
                    'ip': ip,
                    'threat_level': data.get('threat_level'),
                    'abuse_score': data.get('details', {}).get('abuseipdb', {}).get('abuseConfidenceScore', 0),
                    'total_reports': data.get('details', {}).get('abuseipdb', {}).get('totalReports', 0),
                    'isp': data.get('details', {}).get('abuseipdb', {}).get('isp', 'Unknown'),
                    'country': data.get('details', {}).get('abuseipdb', {}).get('countryCode', 'Unknown'),
                    'firehol_listed': data.get('details', {}).get('firehol', {}).get('listed', False),
                    'blocklist': data.get('details', {}).get('firehol', {}).get('blocklist', '')
                }

                if data.get('threat_level') == 'high':
                    high_threats.append(threat_info)
                else:
                    medium_threats.append(threat_info)

        # Sort by abuse score (descending)
        high_threats.sort(key=lambda x: x['abuse_score'], reverse=True)
        medium_threats.sort(key=lambda x: x['abuse_score'], reverse=True)

        return {
            'high_threats': high_threats,
            'medium_threats': medium_threats
        }

    # HTML report template
    def _create_html_template(self, summary, threat_data):
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
                        <div class="stat-number">{summary['total_ips_checked']}</div>
                        <div>Total IPs Checked</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number stat-danger">{summary['malicious_ips_found']}</div>
                        <div>Malicious IPs Found</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number stat-danger">{summary['high_threat_ips']}</div>
                        <div>High Threat IPs</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number stat-warning">{summary['medium_threat_ips']}</div>
                        <div>Medium Threat IPs</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number stat-success">{summary['clean_ips']}</div>
                        <div>Clean IPs</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{summary['threat_percentage']:.1f}%</div>
                        <div>Threat Percentage</div>
                    </div>
                </div>
            </div>

            {self._create_threat_section_html('High Threats', threat_data['high_threats'], 'high-threat')}
            {self._create_threat_section_html('Medium Threats', threat_data['medium_threats'], 'medium-threat')}

            <div class="footer">
                <p>Report generated by Network Threat Analyzer | Confidential Security Document</p>
            </div>
        </body>
        </html>
                """

    # HTML Threat section
    def _create_threat_section_html(self, title, threats, css_class):
        if not threats:
            return f'<div class="threat-section"><h3>{title}</h3><p>No {title.lower()} found.</p></div>'

        rows = ''
        for threat in threats:
            rows += f"""
               <tr class="{css_class}">
                   <td>{threat['ip']}</td>
                   <td>{threat['abuse_score']}%</td>
                   <td>{threat['total_reports']}</td>
                   <td>{threat['isp']}</td>
                   <td>{threat['country']}</td>
                   <td>{'Yes' if threat['firehol_listed'] else 'No'}</td>
               </tr>
               """

        return f"""
           <div class="threat-section">
               <h3>{title} ({len(threats)})</h3>
               <table class="threat-table">
                   <thead>
                       <tr>
                           <th>IP Address</th>
                           <th>Abuse Score</th>
                           <th>Reports</th>
                           <th>ISP</th>
                           <th>Country</th>
                           <th>Blocklisted</th>
                       </tr>
                   </thead>
                   <tbody>
                       {rows}
                   </tbody>
               </table>
           </div>
           """

    # Create executive summary in Markdown format
    def _create_executive_summary_markdown(self, summary, threat_data):
        return f"""
        # Network Threat Intelligence Report
        **Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

        ## Executive Summary

        - **Total IPs Checked:** {summary['total_ips_checked']}
        - **Malicious IPs Found:** {summary['malicious_ips_found']}
        - **High Threat IPs:** {summary['high_threat_ips']}
        - **Medium Threat IPs:** {summary['medium_threat_ips']}
        - **Threat Percentage:** {summary['threat_percentage']:.1f}%

        ## Critical Findings

        ### High Threats ({len(threat_data['high_threats'])})
        {self._create_threat_list_markdown(threat_data['high_threats'])}

        ### Medium Threats ({len(threat_data['medium_threats'])})
        {self._create_threat_list_markdown(threat_data['medium_threats'])}

        ## Recommendations

        1. **Immediate Action Required:** Block high threat IPs in firewall
        2. **Investigation Needed:** Review network traffic from medium threat IPs
        3. **Monitoring:** Continue regular security scanning
        4. **Follow-up:** Schedule security review meeting

        ---
        *This report contains sensitive security information. Handle with appropriate confidentiality.*
                """

    # Markdown list of threats
    def _create_threat_list_markdown(self, threats):
        if not threats:
            return "No threats in this category.\n"

        threat_list = ""
        for threat in threats:
            threat_list += f"- **{threat['ip']}** - Score: {threat['abuse_score']}% - Reports: {threat['total_reports']} - ISP: {threat['isp']}\n"

        return threat_list
