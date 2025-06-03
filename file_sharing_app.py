import os
import random
import uuid
import hashlib
import requests
import time
import tempfile
import threading
from flask import Flask, request, jsonify, send_file, render_template_string
from flask_cors import CORS
from werkzeug.utils import secure_filename
import mimetypes
from datetime import datetime

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

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

@app.route('/')
def index():
    """Serve the main file sharing interface"""
    html_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Random File Exchange</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .upload-area {
            border: 2px dashed #cbd5e0;
            transition: all 0.3s ease;
        }
        .upload-area.dragover {
            border-color: #4299e1;
            background-color: #ebf8ff;
        }
        .file-info {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
    </style>
</head>
<body class="bg-gray-100 min-h-screen">
    <div class="container mx-auto px-4 py-8">
        <div class="max-w-4xl mx-auto">
            <!-- Header -->
            <div class="text-center mb-8">
                <h1 class="text-4xl font-bold text-gray-800 mb-4">Random File Exchange</h1>
                <p class="text-lg text-gray-600">Upload a file, get a random file back!</p>
            </div>

            <!-- Pool Statistics -->
            <div class="bg-white rounded-lg shadow-md p-6 mb-8">
                <h2 class="text-2xl font-semibold mb-4">Pool Statistics</h2>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div class="text-center">
                        <div class="text-3xl font-bold text-blue-600" id="fileCount">-</div>
                        <div class="text-gray-600">Files in Pool</div>
                    </div>
                    <div class="text-center">
                        <div class="text-3xl font-bold text-green-600" id="totalSize">-</div>
                        <div class="text-gray-600">Total Size</div>
                    </div>
                    <div class="text-center">
                        <div class="text-3xl font-bold text-purple-600" id="fileTypes">-</div>
                        <div class="text-gray-600">File Types</div>
                    </div>
                </div>
            </div>

            <!-- Security Status -->
            <div class="bg-white rounded-lg shadow-md p-6 mb-8">
                <h2 class="text-2xl font-semibold mb-4">🔒 Security Status</h2>
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                    <div class="text-center">
                        <div class="text-2xl font-bold" id="virusScanStatus">-</div>
                        <div class="text-gray-600 text-sm">Virus Scanning</div>
                    </div>
                    <div class="text-center">
                        <div class="text-2xl font-bold text-red-600" id="blockedExtensions">-</div>
                        <div class="text-gray-600 text-sm">Blocked Extensions</div>
                    </div>
                    <div class="text-center">
                        <div class="text-2xl font-bold text-orange-600" id="quarantinedFiles">-</div>
                        <div class="text-gray-600 text-sm">Quarantined Files</div>
                    </div>
                    <div class="text-center">
                        <div class="text-2xl font-bold text-blue-600" id="maxFileSize">-</div>
                        <div class="text-gray-600 text-sm">Max File Size (MB)</div>
                    </div>
                </div>
            </div>

            <!-- Upload Section -->
            <div class="bg-white rounded-lg shadow-md p-6 mb-8">
                <h2 class="text-2xl font-semibold mb-4">Upload a File</h2>
                <div class="upload-area rounded-lg p-8 text-center" id="uploadArea">
                    <div class="mb-4">
                        <svg class="mx-auto h-12 w-12 text-gray-400" stroke="currentColor" fill="none" viewBox="0 0 48 48">
                            <path d="M28 8H12a4 4 0 00-4 4v20m32-12v8m0 0v8a4 4 0 01-4 4H12a4 4 0 01-4-4v-4m32-4l-3.172-3.172a4 4 0 00-5.656 0L28 28M8 32l9.172-9.172a4 4 0 015.656 0L28 28m0 0l4 4m4-24h8m-4-4v8m-12 4h.02" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
                        </svg>
                    </div>
                    <p class="text-lg text-gray-600 mb-2">Drag and drop a file here, or click to select</p>
                    <p class="text-sm text-gray-500">Max file size: 50MB</p>
                    <input type="file" id="fileInput" class="hidden" accept=".txt,.pdf,.png,.jpg,.jpeg,.gif,.doc,.docx,.mp3,.mp4,.avi,.mov,.zip,.rar,.7z,.py,.js,.html,.css,.json,.xml,.csv,.xlsx,.pptx">
                </div>
                <div class="mt-4">
                    <button id="uploadBtn" class="w-full bg-blue-600 text-white py-3 px-6 rounded-lg font-semibold hover:bg-blue-700 transition duration-200 disabled:opacity-50 disabled:cursor-not-allowed" disabled>
                        Upload File
                    </button>
                </div>
            </div>

            <!-- Download Section -->
            <div class="bg-white rounded-lg shadow-md p-6">
                <h2 class="text-2xl font-semibold mb-4">Get a Random File</h2>
                <p class="text-gray-600 mb-4">Click the button below to download a random file from the pool.</p>
                <button id="downloadBtn" class="w-full bg-green-600 text-white py-3 px-6 rounded-lg font-semibold hover:bg-green-700 transition duration-200 disabled:opacity-50 disabled:cursor-not-allowed">
                    Download Random File
                </button>
            </div>

            <!-- Status Messages -->
            <div id="statusMessage" class="mt-4 p-4 rounded-lg hidden"></div>
        </div>
    </div>

    <script>
        let selectedFile = null;

        // DOM elements
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        const uploadBtn = document.getElementById('uploadBtn');
        const downloadBtn = document.getElementById('downloadBtn');
        const statusMessage = document.getElementById('statusMessage');

        // Load pool statistics
        function loadPoolStats() {
            fetch('/api/pool/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('fileCount').textContent = data.file_count;
                    document.getElementById('totalSize').textContent = formatFileSize(data.total_size);
                    document.getElementById('fileTypes').textContent = data.unique_types;
                    
                    // Enable/disable download button based on pool status
                    downloadBtn.disabled = data.file_count === 0;
                })
                .catch(error => {
                    console.error('Error loading pool stats:', error);
                });
        }

        // Load security status
        function loadSecurityStatus() {
            // Load security configuration
            fetch('/api/security/status')
                .then(response => response.json())
                .then(data => {
                    const virusStatus = document.getElementById('virusScanStatus');
                    if (data.virustotal_enabled) {
                        virusStatus.textContent = '✅ Enabled';
                        virusStatus.className = 'text-2xl font-bold text-green-600';
                    } else {
                        virusStatus.textContent = '⚠️ Disabled';
                        virusStatus.className = 'text-2xl font-bold text-yellow-600';
                    }
                    
                    document.getElementById('blockedExtensions').textContent = data.dangerous_extensions_blocked;
                    document.getElementById('maxFileSize').textContent = data.max_file_size_mb;
                })
                .catch(error => {
                    console.error('Error loading security status:', error);
                });

            // Load quarantine statistics
            fetch('/api/quarantine/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('quarantinedFiles').textContent = data.quarantined_files;
                })
                .catch(error => {
                    console.error('Error loading quarantine stats:', error);
                });
        }

        // Format file size
        function formatFileSize(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        // Show status message
        function showStatus(message, type = 'info') {
            statusMessage.textContent = message;
            statusMessage.className = `mt-4 p-4 rounded-lg ${type === 'error' ? 'bg-red-100 text-red-700' : type === 'success' ? 'bg-green-100 text-green-700' : 'bg-blue-100 text-blue-700'}`;
            statusMessage.classList.remove('hidden');
            setTimeout(() => {
                statusMessage.classList.add('hidden');
            }, 5000);
        }

        // File upload handling
        uploadArea.addEventListener('click', () => fileInput.click());
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });
        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('dragover');
        });
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                handleFileSelect(files[0]);
            }
        });

        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                handleFileSelect(e.target.files[0]);
            }
        });

        function handleFileSelect(file) {
            selectedFile = file;
            uploadBtn.disabled = false;
            uploadArea.innerHTML = `
                <div class="mb-4">
                    <svg class="mx-auto h-12 w-12 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                    </svg>
                </div>
                <p class="text-lg text-gray-800 font-semibold">${file.name}</p>
                <p class="text-sm text-gray-500">${formatFileSize(file.size)}</p>
            `;
        }

        // Upload file
        uploadBtn.addEventListener('click', () => {
            if (!selectedFile) return;

            const formData = new FormData();
            formData.append('file', selectedFile);

            uploadBtn.disabled = true;
            uploadBtn.textContent = 'Uploading...';

            fetch('/api/upload', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showStatus('File uploaded successfully!', 'success');
                    selectedFile = null;
                    uploadBtn.textContent = 'Upload File';
                    uploadBtn.disabled = true;
                    uploadArea.innerHTML = `
                        <div class="mb-4">
                            <svg class="mx-auto h-12 w-12 text-gray-400" stroke="currentColor" fill="none" viewBox="0 0 48 48">
                                <path d="M28 8H12a4 4 0 00-4 4v20m32-12v8m0 0v8a4 4 0 01-4 4H12a4 4 0 01-4-4v-4m32-4l-3.172-3.172a4 4 0 00-5.656 0L28 28M8 32l9.172-9.172a4 4 0 015.656 0L28 28m0 0l4 4m4-24h8m-4-4v8m-12 4h.02" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
                            </svg>
                        </div>
                        <p class="text-lg text-gray-600 mb-2">Drag and drop a file here, or click to select</p>
                        <p class="text-sm text-gray-500">Max file size: 50MB</p>
                    `;
                    loadPoolStats();
                    loadSecurityStatus();
                } else {
                    showStatus(data.error || 'Upload failed', 'error');
                    uploadBtn.disabled = false;
                    uploadBtn.textContent = 'Upload File';
                }
            })
            .catch(error => {
                console.error('Upload error:', error);
                showStatus('Upload failed: ' + error.message, 'error');
                uploadBtn.disabled = false;
                uploadBtn.textContent = 'Upload File';
            });
        });

        // Download random file
        downloadBtn.addEventListener('click', () => {
            downloadBtn.disabled = true;
            downloadBtn.textContent = 'Downloading...';

            fetch('/api/download')
            .then(response => {
                if (response.ok) {
                    const contentDisposition = response.headers.get('Content-Disposition');
                    const filename = contentDisposition ? 
                        contentDisposition.split('filename=')[1].replace(/"/g, '') : 
                        'downloaded_file';
                    
                    return response.blob().then(blob => {
                        const url = window.URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.style.display = 'none';
                        a.href = url;
                        a.download = filename;
                        document.body.appendChild(a);
                        a.click();
                        window.URL.revokeObjectURL(url);
                        document.body.removeChild(a);
                        
                        showStatus('File downloaded successfully!', 'success');
                        loadPoolStats();
                    });
                } else {
                    return response.json().then(data => {
                        throw new Error(data.error || 'Download failed');
                    });
                }
            })
            .catch(error => {
                console.error('Download error:', error);
                showStatus('Download failed: ' + error.message, 'error');
            })
            .finally(() => {
                downloadBtn.disabled = false;
                downloadBtn.textContent = 'Download Random File';
                loadPoolStats();
            });
        });

        // Load initial stats
        loadPoolStats();
        loadSecurityStatus();
    </script>
</body>
</html>
    '''
    return render_template_string(html_template)

@app.route('/api/pool/stats')
def pool_stats():
    """Get statistics about the file pool"""
    try:
        files = os.listdir(UPLOAD_FOLDER)
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
        
        # Security scan with VirusTotal
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
        
        file_info = get_file_info(final_filepath)
        
        return jsonify({
            'success': True,
            'filename': filename,
            'original_filename': original_filename,
            'size': file_info['size'],
            'mime_type': file_info['mime_type'],
            'security_scan': scan_result
        })
    
    except Exception as e:
        # Clean up temp file if it exists
        temp_filepath = os.path.join(UPLOAD_FOLDER, f"temp_{filename}" if 'filename' in locals() else "temp_unknown")
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath)
        return jsonify({'error': str(e)}), 500

@app.route('/api/download')
def download_random_file():
    """Download a random file from the pool"""
    try:
        files = [f for f in os.listdir(UPLOAD_FOLDER) 
                if os.path.isfile(os.path.join(UPLOAD_FOLDER, f))]
        
        if not files:
            return jsonify({'error': 'No files available in the pool'}), 404
        
        # Filter out files that are already being downloaded
        available_files = [f for f in files if not f.endswith('.downloading')]
        
        if not available_files:
            return jsonify({'error': 'No files available in the pool'}), 404
        
        # Select random file
        random_file = random.choice(available_files)
        filepath = os.path.join(UPLOAD_FOLDER, random_file)
        
        # Extract original filename (remove unique ID prefix)
        if '_' in random_file:
            original_filename = '_'.join(random_file.split('_')[1:])
        else:
            original_filename = random_file
        
        # Read file content and remove from pool
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Remove file from pool immediately
        os.remove(filepath)
        
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
        
        return send_file(
            temp_file.name,
            as_attachment=True,
            download_name=original_filename,
            mimetype='application/octet-stream'
        )
    
    except Exception as e:
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
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("Starting Random File Exchange Server...")
    print(f"Upload folder: {os.path.abspath(UPLOAD_FOLDER)}")
    print("Server will be available at: http://0.0.0.0:8080")
    print("Local access: http://localhost:8080")
    app.run(host='0.0.0.0', port=8080, debug=False)