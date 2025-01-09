import os

from flask import Flask, jsonify, request
from werkzeug.utils import secure_filename

from module import VirusTotalScanner

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = 'upload'
ALLOWED_EXTENSIONS = {'zip', 'exe', 'pdf', 'doc', 'docx', 'xls', 'xlsx'}
MAX_CONTENT_LENGTH = 32 * 1024 * 1024  # 32MB max file size

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize scanner
scanner = VirusTotalScanner()


def allowed_file(filename):
    """Check if the file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def format_stats(stats):
    """Format scan statistics for better readability"""
    return {
        "malicious": stats.get('malicious', 0),
        "undetected": stats.get('undetected', 0),
        "suspicious": stats.get('suspicious', 0),
        "type_unsupported": stats.get('type-unsupported', 0),
        "failure": stats.get('failure', 0)
    }


@app.route('/scan', methods=['POST'])
def scan_file():
    """
    Endpoint to scan a file using VirusTotal
    Expects a file in the request with key 'file'
    """
    # Check if file was uploaded
    if 'file' not in request.files:
        return jsonify({
            'success': False,
            'error': 'No file provided'
        }), 400

    file = request.files['file']

    # Check if a file was selected
    if file.filename == '':
        return jsonify({
            'success': False,
            'error': 'No file selected'
        }), 400

    # Check if file type is allowed
    if not allowed_file(file.filename):
        return jsonify({
            'success': False,
            'error': 'File type not allowed'
        }), 400

    try:
        # Save the file
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        # Scan the file
        scan_result = scanner.scan_file(filepath)

        if not scan_result['success']:
            return jsonify({
                'success': False,
                'error': scan_result.get('error', 'Scan failed')
            }), 500

        # Wait for analysis (you might want to make this asynchronous in production)

        # Get analysis results
        analysis_result = scanner.get_analysis(scan_result['scan_id'])

        if not analysis_result['success']:
            return jsonify({
                'success': False,
                'error': analysis_result.get('error', 'Analysis failed')
            }), 500

        # Format the response
        response = {
            'success': True,
            'status': analysis_result['status'],
            'stats': format_stats(analysis_result['stats']),
            'malicious_detections': [
                {
                    'engine': engine,
                    'detection': details.get('result'),
                    'category': details.get('category'),
                    'engine_version': details.get('engine_version'),
                    'engine_update': details.get('engine_update')
                }
                for engine, details in analysis_result['results'].items()
                if details.get('category') == 'malicious'
            ]
        }

        return jsonify(response)

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        # Clean up - delete the uploaded file
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
        except:
            pass


if __name__ == '__main__':
    app.run(debug=True, port=5000)
