import os
import random
import uuid
import hashlib
import requests
import time
import tempfile
import threading
import json
from flask import Flask, request, jsonify, send_file, render_template, session, redirect, url_for
from flask_cors import CORS
from werkzeug.utils import secure_filename
import mimetypes
from datetime import datetime
import logging
import magic  # python-magic for MIME type detection

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes
app.secret_key = os.environ.get('SECRET_KEY', str(uuid.uuid4()))  # Needed for session

# Configuration
UPLOAD_FOLDER = 'file_pool'
QUARANTINE_FOLDER = 'quarantine'
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB max file size
ALLOWED_EXTENSIONS = {
    'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 
    'mp3', 'mp4', 'avi', 'mov', 'zip', 'rar', '7z', 'py', 
    'js', 'html', 'css', 'json', 'xml', 'csv', 'xlsx', 'pptx'
}

# Security Configuration
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
VIRUSTOTAL_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'
VIRUSTOTAL_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
SCAN_TIMEOUT = 300  # 5 minutes timeout for virus scan
MAX_SCAN_RETRIES = 30  # Maximum retries for scan results

# Dangerous file extensions that are always blocked
DANGEROUS_EXTENSIONS = {
    'exe', 'bat', 'cmd', 'com', 'pif', 'scr', 'vbs', 'js', 'jar', 
    'msi', 'dll', 'sys', 'drv', 'bin', 'deb', 'rpm', 'dmg', 'pkg',
    'app', 'sh', 'ps1', 'psm1', 'psd1', 'ps1xml', 'psc1', 'psc2'
}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Create upload and quarantine folders if they don't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)

# Setup logging
logging.basicConfig(
    filename='server.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
)

def calculate_file_hash(filepath):
    """Calculate SHA256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def is_dangerous_file(filename):
    """Check if file has dangerous extension"""
    if '.' not in filename:
        return False
    extension = filename.rsplit('.', 1)[1].lower()
    return extension in DANGEROUS_EXTENSIONS

def allowed_file(filename):
    """Check if file is allowed (safe extension and not dangerous)"""
    if is_dangerous_file(filename):
        return False
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def scan_file_with_virustotal(filepath):
    """Scan file with VirusTotal API"""
    if not VIRUSTOTAL_API_KEY:
        print("Warning: VirusTotal API key not configured. Skipping virus scan.")
        return {'clean': True, 'scan_performed': False, 'reason': 'No API key'}
    
    try:
        # Calculate file hash first to check if already scanned
        file_hash = calculate_file_hash(filepath)
        
        # Check if file was already scanned
        report_params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': file_hash}
        report_response = requests.get(VIRUSTOTAL_REPORT_URL, params=report_params, timeout=30)
        
        if report_response.status_code == 200:
            report_data = report_response.json()
            if report_data['response_code'] == 1:  # Report exists
                positives = report_data.get('positives', 0)
                total = report_data.get('total', 0)
                
                if positives > 0:
                    return {
                        'clean': False, 
                        'scan_performed': True,
                        'positives': positives,
                        'total': total,
                        'reason': f'Virus detected by {positives}/{total} engines'
                    }
                else:
                    return {
                        'clean': True, 
                        'scan_performed': True,
                        'positives': 0,
                        'total': total,
                        'reason': 'File is clean'
                    }
        
        # File not in database, submit for scanning
        with open(filepath, 'rb') as f:
            files = {'file': f}
            params = {'apikey': VIRUSTOTAL_API_KEY}
            scan_response = requests.post(VIRUSTOTAL_URL, files=files, params=params, timeout=60)
        
        if scan_response.status_code != 200:
            return {'clean': True, 'scan_performed': False, 'reason': 'Scan submission failed'}
        
        scan_data = scan_response.json()
        if scan_data['response_code'] != 1:
            return {'clean': True, 'scan_performed': False, 'reason': 'Scan not accepted'}
        
        # Wait for scan results
        resource = scan_data['resource']
        for attempt in range(MAX_SCAN_RETRIES):
            time.sleep(10)  # Wait 10 seconds between checks
            
            report_params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': resource}
            report_response = requests.get(VIRUSTOTAL_REPORT_URL, params=report_params, timeout=30)
            
            if report_response.status_code == 200:
                report_data = report_response.json()
                if report_data['response_code'] == 1:  # Scan complete
                    positives = report_data.get('positives', 0)
                    total = report_data.get('total', 0)
                    
                    if positives > 0:
                        return {
                            'clean': False, 
                            'scan_performed': True,
                            'positives': positives,
                            'total': total,
                            'reason': f'Virus detected by {positives}/{total} engines'
                        }
                    else:
                        return {
                            'clean': True, 
                            'scan_performed': True,
                            'positives': 0,
                            'total': total,
                            'reason': 'File is clean'
                        }
        
        # Timeout waiting for results
        return {'clean': False, 'scan_performed': False, 'reason': 'Scan timeout'}
        
    except Exception as e:
        print(f"VirusTotal scan error: {str(e)}")
        return {'clean': True, 'scan_performed': False, 'reason': f'Scan error: {str(e)}'}

def quarantine_file(filepath, reason):
    """Move file to quarantine folder"""
    filename = os.path.basename(filepath)
    quarantine_path = os.path.join(QUARANTINE_FOLDER, f"{int(time.time())}_{filename}")
    os.rename(filepath, quarantine_path)
    print(f"File quarantined: {filename} -> {quarantine_path} (Reason: {reason})")
    return quarantine_path

def get_file_info(filepath):
    """Get file information including size and type"""
    stat = os.stat(filepath)
    size = stat.st_size
    mime_type, _ = mimetypes.guess_type(filepath)
    return {
        'size': size,
        'mime_type': mime_type or 'application/octet-stream',
        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
    }

def get_location_from_ip(ip_address):
    """Get rough location data from IP address using ipapi.co"""
    try:
        # Skip location lookup for localhost/private IPs
        if ip_address in ['127.0.0.1', 'localhost'] or ip_address.startswith('192.168.') or ip_address.startswith('10.') or ip_address.startswith('172.'):
            return {
                'city': 'Local Network',
                'country': 'Local',
                'country_code': 'LN',
                'region': 'Private Network'
            }
        
        # Use ipapi.co free service (1000 requests/month)
        response = requests.get(f'https://ipapi.co/{ip_address}/json/', timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            
            # Extract relevant location info (no precise coordinates)
            location = {
                'city': data.get('city', 'Unknown'),
                'country': data.get('country_name', 'Unknown'),
                'country_code': data.get('country_code', 'XX'),
                'region': data.get('region', 'Unknown')
            }
            
            print(f"Location lookup for {ip_address}: {location['city']}, {location['country']}")
            return location
        else:
            print(f"Location lookup failed for {ip_address}: HTTP {response.status_code}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"Location lookup error for {ip_address}: {str(e)}")
        return None
    except Exception as e:
        print(f"Unexpected error in location lookup for {ip_address}: {str(e)}")
        return None

def get_client_ip():
    """Get the real client IP address, handling proxies"""
    # Check for forwarded headers (common in production behind proxies)
    if request.headers.get('X-Forwarded-For'):
        # X-Forwarded-For can contain multiple IPs, take the first one
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr

def is_suspicious_file(filepath):
    """Perform local security checks to determine if file is suspicious."""
    # Check for double extensions (e.g., .jpg.exe)
    filename = os.path.basename(filepath)
    parts = filename.lower().split('.')
    if len(parts) > 2 and parts[-1] not in DANGEROUS_EXTENSIONS and any(ext in DANGEROUS_EXTENSIONS for ext in parts[:-1]):
        return True
    # Check for executable MIME type
    try:
        mime = magic.from_file(filepath, mime=True)
        if mime in [
            'application/x-dosexec', 'application/x-msdownload', 'application/x-executable',
            'application/x-sh', 'application/x-bat', 'application/x-msi', 'application/x-object',
            'application/x-elf', 'application/x-mach-binary', 'application/x-pe', 'application/x-pie-executable',
            'application/x-msdos-program', 'application/x-shellscript', 'application/x-python-code',
            'application/x-ms-shortcut', 'application/x-ms-wim', 'application/x-cab-compressed',
            'application/x-apple-diskimage', 'application/x-iso9660-image', 'application/x-raw-disk-image',
            'application/x-diskcopy', 'application/x-virtualbox-vdi', 'application/x-virtualbox-vhd',
            'application/x-virtualbox-vmdk', 'application/x-msi', 'application/x-msinstaller',
        ]:
            return True
    except Exception as e:
        logging.warning(f"MIME check failed: {e}")
    # Check for scripts by content
    try:
        with open(filepath, 'rb') as f:
            head = f.read(2048)
            if b'#!/bin/bash' in head or b'#!/usr/bin/env python' in head or b'#!/bin/sh' in head:
                return True
    except Exception as e:
        logging.warning(f"Script head check failed: {e}")
    return False

@app.route('/')
def index():
    """Serve the main file sharing interface"""
    session['uploaded'] = False  # Reset upload status on new visit
    return render_template('index.html')

@app.route('/api/pool/stats')
def pool_stats():
    """Get statistics about the file pool"""
    try:
        all_files = os.listdir(UPLOAD_FOLDER)
        # Filter out metadata files
        files = [f for f in all_files if not f.endswith('.meta')]
        file_count = len(files)
        total_size = 0
        file_types = set()
        
        for filename in files:
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            if os.path.isfile(filepath):
                total_size += os.path.getsize(filepath)
                ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else 'unknown'
                file_types.add(ext)
        
        return jsonify({
            'file_count': file_count,
            'total_size': total_size,
            'unique_types': len(file_types),
            'file_types': list(file_types)
        })
    except Exception as e:
        logging.error(f"Pool stats error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Upload a file to the pool with security scanning"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Security check: dangerous file extensions
        if is_dangerous_file(file.filename):
            return jsonify({'error': 'File type is potentially dangerous and not allowed'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed'}), 400
        
        # Generate unique filename to avoid conflicts
        original_filename = secure_filename(file.filename)
        unique_id = str(uuid.uuid4())[:8]
        filename = f"{unique_id}_{original_filename}"
        
        # Save to temporary location first for scanning
        temp_filepath = os.path.join(UPLOAD_FOLDER, f"temp_{filename}")
        file.save(temp_filepath)
        
        # Local security check
        suspicious = is_suspicious_file(temp_filepath)
        scan_result = {'clean': True, 'scan_performed': False, 'reason': 'Locally checked'}
        if suspicious:
            scan_result = scan_file_with_virustotal(temp_filepath)
        
        if not scan_result['clean']:
            # File is infected, quarantine it
            quarantine_file(temp_filepath, scan_result['reason'])
            return jsonify({
                'error': f'File rejected: {scan_result["reason"]}',
                'scan_details': scan_result
            }), 400
        
        # File is clean, move to final location
        final_filepath = os.path.join(UPLOAD_FOLDER, filename)
        os.rename(temp_filepath, final_filepath)
        
        # Get file info
        file_info = get_file_info(final_filepath)
        
        # Get location data from uploader's IP
        client_ip = get_client_ip()
        location_data = get_location_from_ip(client_ip)
        
        # Store metadata including location
        metadata = {
            'filename': filename,
            'original_filename': original_filename,
            'size': file_info['size'],
            'mime_type': file_info['mime_type'],
            'upload_time': datetime.now().isoformat(),
            'uploader_ip': client_ip,
            'location': location_data,
            'security_scan': scan_result
        }
        
        # Save metadata to JSON file
        metadata_filepath = os.path.join(UPLOAD_FOLDER, f"{filename}.meta")
        with open(metadata_filepath, 'w') as f:
            json.dump(metadata, f, indent=2)
        # Mark user as having uploaded a file
        session['uploaded'] = True
        print(f"File uploaded: {original_filename} from {client_ip} ({location_data['city'] if location_data else 'Unknown'}, {location_data['country'] if location_data else 'Unknown'})")
        return jsonify({
            'success': True,
            'filename': filename,
            'original_filename': original_filename,
            'size': file_info['size'],
            'mime_type': file_info['mime_type'],
            'location': location_data,
            'security_scan': scan_result
        })
    
    except Exception as e:
        logging.error(f"Upload error: {str(e)}")
        temp_filepath = os.path.join(UPLOAD_FOLDER, f"temp_{filename}" if 'filename' in locals() else "temp_unknown")
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath)
        return jsonify({'error': str(e)}), 500

@app.route('/api/download')
def download_random_file():
    """Download a random file from the pool"""
    # Only allow download if user has uploaded
    if not session.get('uploaded', False):
        return jsonify({'error': 'You must upload a file before retrieving one.'}), 403
    
    try:
        files = [f for f in os.listdir(UPLOAD_FOLDER) 
                if os.path.isfile(os.path.join(UPLOAD_FOLDER, f))]
        
        if not files:
            return jsonify({'error': 'No files available in the pool'}), 404
        
        # Filter out files that are already being downloaded and metadata files
        available_files = [f for f in files if not f.endswith('.downloading') and not f.endswith('.meta')]
        
        if not available_files:
            return jsonify({'error': 'No files available in the pool'}), 404
        
        # Select random file
        random_file = random.choice(available_files)
        filepath = os.path.join(UPLOAD_FOLDER, random_file)
        
        # Load metadata if available
        metadata_filepath = os.path.join(UPLOAD_FOLDER, f"{random_file}.meta")
        metadata = None
        if os.path.exists(metadata_filepath):
            try:
                with open(metadata_filepath, 'r') as f:
                    metadata = json.load(f)
            except Exception as e:
                print(f"Error loading metadata for {random_file}: {e}")
                metadata = None
        
        # Extract original filename (remove unique ID prefix)
        if '_' in random_file:
            original_filename = '_'.join(random_file.split('_')[1:])
        else:
            original_filename = random_file
        
        # Read file content and remove from pool
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Remove file and metadata from pool immediately
        os.remove(filepath)
        if os.path.exists(metadata_filepath):
            os.remove(metadata_filepath)
        # Mark user as not uploaded (must upload again for next download)
        session['uploaded'] = False
        
        # Log download with location info
        location_info = "Unknown location"
        if metadata and metadata.get('location'):
            loc = metadata['location']
            location_info = f"{loc.get('city', 'Unknown')}, {loc.get('country', 'Unknown')}"
        
        print(f"File downloaded: {original_filename} (originally from {location_info})")
        
        # Create a temporary file for download
        import tempfile
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        temp_file.write(file_content)
        temp_file.close()
        
        def remove_temp_file():
            try:
                os.remove(temp_file.name)
            except:
                pass
        
        # Schedule cleanup after response
        from threading import Timer
        Timer(5.0, remove_temp_file).start()
        
        # Create response with location headers
        response = send_file(
            temp_file.name,
            as_attachment=True,
            download_name=original_filename,
            mimetype='application/octet-stream'
        )
        
        # Add location information to response headers
        if metadata and metadata.get('location'):
            loc = metadata['location']
            response.headers['X-File-Origin-City'] = loc.get('city', 'Unknown')
            response.headers['X-File-Origin-Country'] = loc.get('country', 'Unknown')
            response.headers['X-File-Origin-Region'] = loc.get('region', 'Unknown')
            response.headers['X-File-Upload-Time'] = metadata.get('upload_time', 'Unknown')
        
        return response
    
    except Exception as e:
        logging.error(f"Download error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/security/status')
def security_status():
    """Get security configuration status"""
    return jsonify({
        'virustotal_enabled': bool(VIRUSTOTAL_API_KEY),
        'dangerous_extensions_blocked': len(DANGEROUS_EXTENSIONS),
        'allowed_extensions': len(ALLOWED_EXTENSIONS),
        'quarantine_folder': QUARANTINE_FOLDER,
        'max_file_size_mb': MAX_FILE_SIZE // (1024 * 1024)
    })

@app.route('/api/quarantine/stats')
def quarantine_stats():
    """Get quarantine folder statistics"""
    try:
        quarantine_files = [f for f in os.listdir(QUARANTINE_FOLDER) 
                          if os.path.isfile(os.path.join(QUARANTINE_FOLDER, f))]
        
        total_size = sum(os.path.getsize(os.path.join(QUARANTINE_FOLDER, f)) 
                        for f in quarantine_files)
        
        return jsonify({
            'quarantined_files': len(quarantine_files),
            'total_size': total_size
        })
    except Exception as e:
        logging.error(f"Quarantine stats error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/file/info')
def get_random_file_info():
    # Only allow preview if user has uploaded
    if not session.get('uploaded', False):
        return jsonify({'error': 'You must upload a file before retrieving one.'}), 403
    
    """Get information about a random file including location data"""
    try:
        files = [f for f in os.listdir(UPLOAD_FOLDER) 
                if os.path.isfile(os.path.join(UPLOAD_FOLDER, f)) and not f.endswith('.meta')]
        
        if not files:
            return jsonify({'error': 'No files available in the pool'}), 404
        
        # Select random file
        random_file = random.choice(files)
        
        # Load metadata if available
        metadata_filepath = os.path.join(UPLOAD_FOLDER, f"{random_file}.meta")
        metadata = None
        if os.path.exists(metadata_filepath):
            try:
                with open(metadata_filepath, 'r') as f:
                    metadata = json.load(f)
            except Exception as e:
                print(f"Error loading metadata for {random_file}: {e}")
        
        # Extract original filename
        if '_' in random_file:
            original_filename = '_'.join(random_file.split('_')[1:])
        else:
            original_filename = random_file
        
        # Get file info
        filepath = os.path.join(UPLOAD_FOLDER, random_file)
        file_info = get_file_info(filepath)
        
        response_data = {
            'filename': original_filename,
            'size': file_info['size'],
            'mime_type': file_info['mime_type'],
            'upload_time': metadata.get('upload_time') if metadata else None,
            'location': metadata.get('location') if metadata else None
        };
        
        return jsonify(response_data);
    
    except Exception as e:
        logging.error(f"File info error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.errorhandler(400)
def bad_request(error):
    response = jsonify({'error': 'Bad request', 'message': str(error)})
    response.status_code = 400
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

@app.errorhandler(404)
def not_found(error):
    response = jsonify({'error': 'Not found', 'message': str(error)})
    response.status_code = 404
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

@app.errorhandler(500)
def internal_error(error):
    response = jsonify({'error': 'Internal server error', 'message': str(error)})
    response.status_code = 500
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

if __name__ == '__main__':
    print("Starting Random File Exchange Server...")
    print(f"Upload folder: {os.path.abspath(UPLOAD_FOLDER)}")
    print("Server will be available at: http://0.0.0.0:8080")
    print("Local access: http://localhost:8080")
    app.run(host='0.0.0.0', port=8080, debug=False)
