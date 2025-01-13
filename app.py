import hashlib
import os

import requests
from flask import Flask, jsonify, request
from werkzeug.utils import secure_filename

from module import VirusTotalScanner

app = Flask(__name__)

UPLOAD_FOLDER = 'upload'
ALLOWED_EXTENSIONS = {'zip'}
MAX_CONTENT_LENGTH = 32 * 1024 * 1024

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
scanner = VirusTotalScanner()


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_file_sha256(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


@app.route('/', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({
            'success': False,
            'error': 'No file provided'
        }), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({
            'success': False,
            'error': 'No file selected'
        }), 400
    if not allowed_file(file.filename):
        return jsonify({
            'success': False,
            'error': 'File type not allowed'
        }), 400

    try:
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        scan_result = scanner.scan_file(filepath)
        if not scan_result['success']:
            return jsonify({
                'success': False,
                'error': scan_result.get('error', 'Scan failed')
            }), 500
        analysis_result = scanner.get_analysis(scan_result['scan_id'])
        if not analysis_result['success']:
            return jsonify({
                'success': False,
                'error': analysis_result.get('error', 'Analysis failed')
            }), 500
        stats = analysis_result['stats']
        is_safe = stats.get('malicious', 0) == 0 and stats.get(
            'suspicious', 0) == 0
        response = {
            'status': is_safe,
            'sha256': scan_result['sha256']
        }

        return jsonify(response)

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
        except Exception as e:
            pass


@app.route('/delete/<file_hash>', methods=['DELETE'])
def delete_file(file_hash):
    try:
        # docs API: https://docs.virustotal.com/reference/get-a-private-file-report-copy
        url = f"https://www.virustotal.com/api/v3/private/files/{file_hash}"

        headers = {
            "x-apikey": os.getenv('VT_API_KEY')
        }
        response = requests.delete(url, headers=headers)
        if response.status_code == 200:
            return jsonify({
                "success": True,
            })
        else:
            return jsonify({
                "success": False,
                "error": f"Failed to delete file. Status code: {response.status_code}"
            }), response.status_code

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


if __name__ == '__main__':
    app.run(debug=True, port=5000)
