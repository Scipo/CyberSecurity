import os
import sys
import json
import tempfile
import webbrowser
from datetime import datetime
from functools import wraps
from os.path import exists

from flask import Flask, render_template, request, jsonify, send_file, Response

from src.reporting.generator import ReportGenerator

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.network_scanner import NetworkScanner
from src.threat_intel import ThreatIntelligence
from src.utils import setup_logging
from src.config.settings import load_config, get_api_key
from src.state.statemanager import state_manager
from src.config.settings import should_use_cache

app = Flask(__name__)
app.config['SECRET_KEY'] = 'network-threat-analyzer-secret-key'

logger = setup_logging(False)

_request_counts = {}


def rate_limit(max_request: int = 10, window_seconds: int = 60):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            client_ip = request.remote_addr
            curr_time = datetime.now().timestamp()

            if client_ip not in _request_counts:
                _request_counts[client_ip] = []
            _request_counts[client_ip] = [
                ts for ts in _request_counts[client_ip]
                if curr_time - ts < window_seconds
            ]
            if len(_request_counts[client_ip]) >= max_request:
                return jsonify({
                    'success': False,
                    'error': 'Rate limit exceeded. Please try again later.'
                }), 429
            _request_counts[client_ip].append(curr_time)
            return f(*args, **kwargs)

        return wrapped

    return decorator


@app.route('/')
# Main dashboard page
def index():
    config = load_config()
    return render_template(
        'index.html',
        config=config,
        has_api_key=bool(get_api_key())
    )


@app.route('/api/scan', methods=['POST'])
@rate_limit(max_request=5, window_seconds=60)
def api_scan():
    try:
        api_key = get_api_key()
        scanner = NetworkScanner(logger)
        threat_intel = ThreatIntelligence(logger, api_key, use_cache=should_use_cache())

        network_data = scanner.get_network_info()
        if not network_data:
            logger.warning("No network data collected during scan")
            return jsonify({'success': False, 'error': 'No network data collected'})

        public_ips = scanner.extract_public_ips(network_data)
        if not public_ips:
            logger.info("No public IPs found in network data")
            return jsonify({'success': False, 'error': 'No public IPs found to analyze'})

        threat_results = threat_intel.check_ips(public_ips)

        # Prepare results
        scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        scan_results = {
            'id': scan_id,
            'network_data': network_data,
            'threat_results': threat_results,
            'scan_metadata': {
                'timestamp': datetime.now().isoformat(),
                'total_ips_scanned': len(public_ips),
                'public_ips_count': len(public_ips),
                'scanner_version': '1.0.0'
            }
        }

        state_manager.add_scan_results_to_history(scan_results)
        logger.info(f"Scan completed successfully: {scan_id}")

        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'results': scan_results
        })
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        return jsonify({'success': False, 'error': f'Scan failed: str(e)'}), 500


@app.route('/api/results/<scan_id>')
def get_results(scan_id):
    """Get specific scan results by ID."""
    try:
        scan_data = state_manager.get_scan_by_id(scan_id)

        if scan_data:
            return jsonify(scan_data)
        else:
            logger.warning(f"Scan not found: {scan_id}")
            return jsonify({'error': 'Scan not found'}), 404

    except Exception as e:
        logger.error(f"Failed to get results for {scan_id}: {e}", exc_info=True)
        return jsonify({'error': f'Failed to get results: {str(e)}'}), 500


@app.route('/api/history')
# Get scan history
def get_history():
    try:
        history = state_manager.get_scan_history()
        return jsonify(history)
    except Exception as e:
        logger.error(f"Failed to get history: {e}", exc_info=True)
        return jsonify({'error': f'Failed to get history: {str(e)}'}), 500


@app.route('/api/export/<scan_id>')
def export_results(scan_id):
    try:
        scan_data = state_manager.get_scan_by_id(scan_id)

        if not scan_data:
            logger.warning(f"Export failed - scan not found: {scan_id}")
            return jsonify({'error': 'Scan not found'}), 404

        # Create reports directory if it doesn't exist
        json_str = json.dumps(scan_data, indent=2, default=str)

        filename = f"threat_scan_{scan_id}.json"
        logger.info(f"Exporting scan results: {scan_id}")

        return Response(
            json_str,
            mimetype='application/json',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/json; charset=utf-8'
            }
        )
    except Exception as e:
        logger.error(f"Export failed for {scan_id}: {e}", exc_info=True)
        return jsonify({'error': f'Export failed: {str(e)}'}), 500


@app.route('/api/config', methods=['GET', 'POST'])
# Get update configuration
def handle_config():
    if request.method == 'GET':
        try:
            config = load_config()

            if config.get('ABUSEIPDB_API_KEY'):
                config['ABUSEIPDB_API_KEY'] = '***' + config['ABUSEIPDB_API_KEY'][-4:]
            return jsonify(config)
        except Exception as e:
            logger.error(f"Failed to load config:{e}", exc_info=True)
            return jsonify({'error': f'Failed to load config: {str(e)}'}), 500
    else:  # POST
        try:
            from src.config.settings import save_config
            new_config = request.json
            save_config(new_config)
            logger.info("Configuration updated successfully")
            return jsonify({'success': True})
        except Exception as e:
            logger.error(f"Failed to save config: {e}", exc_info=True)
            return jsonify({'success': False, 'error': f'Failed to save config: {str(e)}'}), 500


@app.route('/api/network_info')
# Get current network information without full scan
def get_network_info():
    try:
        scanner = NetworkScanner(setup_logging(False))
        network_data = scanner.get_network_info()
        public_ips = scanner.extract_public_ips(network_data)

        return jsonify(
            {
                'total_connections': len(network_data),
                'public_ips_count': len(public_ips),
                'sample_connections': dict(list(network_data.items())[:5])  # First 5
            }
        )
    except Exception as e:
        logger.error(f"Failed to get network info: {e}", exc_info=True)
        return jsonify({'error': f'Failed to get network info: {str(e)}'}), 500


@app.route('/api/test_api')
# Test AbuseIDDB API connection
def test_api():
    try:
        api_key = get_api_key()
        if not api_key:
            return jsonify({
                'success': False,
                'error': 'No API key configured'
            }), 400

        threat_intel = ThreatIntelligence(setup_logging(False), api_key)
        test_ip = "8.8.8.8"

        result = threat_intel._check_abuseipdb_sync(test_ip)

        if 'error' in result:
            logger.warning(f"API test failed: {result['error']}")
            return jsonify({'success': False, 'error': result['error']})
        else:
            logger.info("API test successful")
            return jsonify({'success': True, 'result': result})
    except Exception as e:
        logger.error(f"API test failed: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


# Generating reports web
@app.route('/api/generate_report', methods=['POST'])
def generate_report():
    """Generate reports in various formats using StateManager."""
    try:
        data = request.json
        scan_id = data.get('scan_id')
        formats = data.get('formats', ['html'])

        # Use StateManager to get scan results
        scan_data = state_manager.get_scan_by_id(scan_id)

        if not scan_data:
            return jsonify({'success': False, 'error': 'Scan not found'})

        generator = ReportGenerator()
        generated_reports = {}

        for fmt in formats:
            try:
                if fmt == 'html':
                    report_path = generator.generate_html_report(scan_data)
                    generated_reports['html'] = report_path
                elif fmt == 'json':
                    report_path = generator.generate_json_report(scan_data)
                    generated_reports['json'] = report_path
                elif fmt == 'csv':
                    report_path = generator.generate_csv_report(scan_data)
                    generated_reports['csv'] = report_path
                elif fmt == 'pdf':
                    try:
                        from weasyprint import HTML
                        report_path = generator.generate_pdf_report(scan_data)
                        generated_reports['pdf'] = report_path
                    except ImportError:
                        generated_reports[
                            'pdf'] = 'Error: PDF generation requires WeasyPrint. Install with: pip install weasyprint'
                elif fmt == 'all':
                    # Generate all supported formats
                    for fmt in ['html', 'json', 'csv', 'executive']:
                        try:
                            if fmt == 'html':
                                path = generator.generate_html_report(scan_data)
                            elif fmt == 'json':
                                path = generator.generate_json_report(scan_data)
                            elif fmt == 'csv':
                                path = generator.generate_csv_report(scan_data)
                            generated_reports[fmt] = path
                        except Exception as fmt_error:
                            generated_reports[fmt] = f'Error: {str(fmt_error)}'
                else:
                    generated_reports[fmt] = f'Error: Unsupported format: {fmt}'
            except Exception as e:
                generated_reports[fmt] = f'Error: {str(e)}'

        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'reports': generated_reports
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/reports/<scan_id>/<frm>')
def download_report(scan_id, frm):
    """Download a specific report using StateManager."""
    try:
        # Use StateManager to get scan results
        scan_data = state_manager.get_scan_by_id(scan_id)

        if not scan_data:
            return jsonify({'error': 'Scan not found'}), 404

        generator = ReportGenerator()

        # Generate report with scan ID in filename
        if frm == 'html':
            report_path = generator.generate_html_report(scan_data, f"threat_report_{scan_id}.html")
        elif frm == 'json':
            report_path = generator.generate_json_report(scan_data, f"threat_report_{scan_id}.json")
        elif frm == 'csv':
            report_path = generator.generate_csv_report(scan_data, f"threat_report_{scan_id}.csv")
        elif frm == 'pdf':
            try:
                from weasyprint import HTML
                report_path = generator.generate_pdf_report(scan_data, f"threat_report_{scan_id}.pdf")
            except ImportError:
                return jsonify(
                    {'error': 'PDF generation requires WeasyPrint. Install with: pip install weasyprint'}), 400
        elif frm == 'executive':
            report_path = generator.generate_executive_summary(scan_data, f"executive_summary_{scan_id}.md")
        else:
            return jsonify({'error': 'Unsupported format'}), 400

        # Determine MIME type
        mime_types = {
            'html': 'text/html',
            'json': 'application/json',
            'csv': 'text/csv',
            'pdf': 'application/pdf',
            'executive': 'text/markdown'
        }

        mime_type = mime_types.get(frm, 'application/octet-stream')

        return send_file(
            report_path,
            as_attachment=True,
            download_name=os.path.basename(report_path),
            mimetype=mime_type
        )

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports/<scan_id>/html/view')
def view_html_report(scan_id):
    try:
        # Use StateManager to get scan results
        scan_data = state_manager.get_scan_by_id(scan_id)

        if not scan_data:
            return jsonify({'error': 'Scan not found'}), 404

        generator = ReportGenerator()

        # Create temporary HTML file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
            temp_file_path = f.name

        # Generate HTML report to temporary file
        generator.generate_html_report(scan_data, temp_file_path)

        # Convert to absolute path for browser
        absolute_path = os.path.abspath(temp_file_path)

        # Open in browser
        webbrowser.open(f'file://{absolute_path}')

        return jsonify({
            'success': True,
            'message': 'Report opened in browser',
            'file_path': absolute_path
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/reports/<scan_id>/info')
def get_report_info(scan_id):

    try:
        # Use StateManager to get scan results
        scan_data = state_manager.get_scan_by_id(scan_id)

        if not scan_data:
            return jsonify({'error': 'Scan not found'}), 404

        # Get scan metadata
        metadata = scan_data.get('scan_metadata', {})
        threat_results = scan_data.get('threat_results', {})

        malicious_count = sum(1 for r in threat_results.values() if r.get('is_malicious', False))
        high_threat_count = sum(1 for r in threat_results.values() if r.get('threat_level') == 'high')

        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'scan_info': {
                'timestamp': metadata.get('timestamp'),
                'total_ips': metadata.get('total_ips_scanned', 0),
                'malicious_ips': malicious_count,
                'high_threats': high_threat_count
            },
            'available_formats': [
                {'id': 'html', 'name': 'HTML Report', 'mime': 'text/html'},
                {'id': 'json', 'name': 'JSON Data', 'mime': 'application/json'},
                {'id': 'csv', 'name': 'CSV Export', 'mime': 'text/csv'},
                {'id': 'pdf', 'name': 'PDF Document', 'mime': 'application/pdf'},
            ]
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Generate all reports
@app.route('/api/reports/<scan_id>/generate_all')
def generate_all_reports(scan_id):
    try:
        # Use StateManager to get scan results
        scan_data = state_manager.get_scan_by_id(scan_id)

        if not scan_data:
            return jsonify({'error': 'Scan not found'}), 404

        generator = ReportGenerator()
        generated_reports = {}

        formats_to_generate = ['html', 'json', 'csv', 'executive']

        for format in formats_to_generate:
            try:
                if format == 'html':
                    report_path = generator.generate_html_report(scan_data, f"threat_report_{scan_id}.html")
                elif format == 'json':
                    report_path = generator.generate_json_report(scan_data, f"threat_report_{scan_id}.json")
                elif format == 'csv':
                    report_path = generator.generate_csv_report(scan_data, f"threat_report_{scan_id}.csv")

                generated_reports[format] = {
                    'path': report_path,
                    'size': os.path.getsize(report_path) if os.path.exists(report_path) else 0,
                    'download_url': f'/api/reports/{scan_id}/{format}'
                }

            except Exception as e:
                generated_reports[format] = {
                    'error': str(e),
                    'path': None
                }

        # Try PDF separately (optional due to dependencies)
        try:
            from weasyprint import HTML
            pdf_path = generator.generate_pdf_report(scan_data, f"threat_report_{scan_id}.pdf")
            generated_reports['pdf'] = {
                'path': pdf_path,
                'size': os.path.getsize(pdf_path) if os.path.exists(pdf_path) else 0,
                'download_url': f'/api/reports/{scan_id}/pdf'
            }
        except ImportError:
            generated_reports['pdf'] = {
                'error': 'PDF generation requires WeasyPrint',
                'note': 'Install with: pip install weasyprint'
            }
        except Exception as e:
            generated_reports['pdf'] = {
                'error': str(e),
                'path': None
            }

        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'reports': generated_reports,
            'download_all_url': f'/api/reports/{scan_id}/download_bundle'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Download all reports as a zip bundle
@app.route('/api/reports/<scan_id>/download_bundle')
def download_report_bundle(scan_id):
    """Download all reports as a ZIP bundle."""
    try:
        import zipfile
        from io import BytesIO

        # Use StateManager to get scan results
        scan_data = state_manager.get_scan_by_id(scan_id)

        if not scan_data:
            return jsonify({'error': 'Scan not found'}), 404

        generator = ReportGenerator()

        # Create in-memory ZIP file
        memory_file = BytesIO()
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Generate and add each report format to ZIP
            formats = ['html', 'json', 'csv', 'executive']

            for format in formats:
                try:
                    if format == 'html':
                        report_path = generator.generate_html_report(scan_data, f"threat_report_{scan_id}.html")
                    elif format == 'json':
                        report_path = generator.generate_json_report(scan_data, f"threat_report_{scan_id}.json")
                    elif format == 'csv':
                        report_path = generator.generate_csv_report(scan_data, f"threat_report_{scan_id}.csv")


                    # Add file to ZIP
                    zf.write(report_path, os.path.basename(report_path))

                except Exception as e:
                    # Create error file for failed formats
                    error_content = f"Failed to generate {format} report: {str(e)}"
                    zf.writestr(f"ERROR_{format}.txt", error_content)

            # Try PDF if available
            try:
                from weasyprint import HTML
                pdf_path = generator.generate_pdf_report(scan_data, f"threat_report_{scan_id}.pdf")
                zf.write(pdf_path, os.path.basename(pdf_path))
            except ImportError:
                zf.writestr("NOTE_pdf.txt", "PDF requires WeasyPrint: pip install weasyprint")
            except Exception as e:
                zf.writestr("ERROR_pdf.txt", f"Failed to generate PDF: {str(e)}")

        memory_file.seek(0)

        return send_file(
            memory_file,
            as_attachment=True,
            download_name=f"threat_reports_{scan_id}.zip",
            mimetype='application/zip'
        )

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}", exc_info=True)
    return jsonify({'error': 'Internal server error'}), 500


# Run web interface
def run_web_interface(host='127.0.0.1', port=5000, debug=False):
    print(f"🚀 Starting Network Threat Analyzer Web Interface...")
    print(f"📡 Access at: http://{host}:{port}")
    print(f"🛑 Press Ctrl+C to stop")
    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == '__main__':
    run_web_interface()
