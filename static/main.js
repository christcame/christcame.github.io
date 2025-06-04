// JavaScript for Random File Exchange
let selectedFile = null;

// DOM elements
const uploadArea = document.getElementById('uploadArea');
const fileInput = document.getElementById('fileInput');
const uploadBtn = document.getElementById('uploadBtn');
const previewBtn = document.getElementById('previewBtn');
const confirmDownloadBtn = document.getElementById('confirmDownloadBtn');
const getAnotherBtn = document.getElementById('getAnotherBtn');
const filePreview = document.getElementById('filePreview');
const statusMessage = document.getElementById('statusMessage');

let currentFileInfo = null;

// Add better error handling and user feedback
function handleFileSelect(file) {
    if (!file) {
        showStatus('No file selected.', 'error');
        return;
    }
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

// Format date for display
function formatDate(isoString) {
    if (!isoString) return 'Unknown';
    const date = new Date(isoString);
    return date.toLocaleString();
}

// Preview random file
previewBtn.addEventListener('click', () => {
    previewBtn.disabled = true;
    previewBtn.textContent = 'Loading...';
    fetch('/api/file/info')
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            showStatus(data.error, 'error');
            previewBtn.disabled = false;
            previewBtn.textContent = 'Preview Random File';
            return;
        }
        currentFileInfo = data;
        document.getElementById('previewFilename').textContent = data.filename;
        document.getElementById('previewSize').textContent = formatFileSize(data.size);
        document.getElementById('previewType').textContent = data.mime_type || 'Unknown';
        document.getElementById('previewUploadTime').textContent = formatDate(data.upload_time);
        const locationDetails = document.getElementById('locationDetails');
        if (data.location) {
            const loc = data.location;
            locationDetails.innerHTML = `
                <div class="font-medium">${loc.city}, ${loc.region}</div>
                <div class="text-sm">${loc.country} (${loc.country_code})</div>
            `;
        } else {
            locationDetails.innerHTML = '<div class="text-sm">Location information not available</div>';
        }
        filePreview.style.display = 'block';
        previewBtn.style.display = 'none';
        showStatus('File preview loaded!', 'success');
    })
    .catch(error => {
        showStatus('Preview failed: ' + error.message, 'error');
    })
    .finally(() => {
        previewBtn.disabled = false;
        previewBtn.textContent = 'Preview Random File';
    });
});

// Download the previewed file
confirmDownloadBtn.addEventListener('click', () => {
    if (!currentFileInfo) return;
    confirmDownloadBtn.disabled = true;
    confirmDownloadBtn.textContent = 'Downloading...';
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
                filePreview.style.display = 'none';
                previewBtn.style.display = 'block';
                currentFileInfo = null;
                loadPoolStats();
            });
        } else {
            return response.json().then(data => {
                showStatus(data.error || 'Download failed', 'error');
            });
        }
    })
    .catch(error => {
        showStatus('Download failed: ' + error.message, 'error');
    })
    .finally(() => {
        confirmDownloadBtn.disabled = false;
        confirmDownloadBtn.textContent = 'Download This File';
    });
});

// Get another file
getAnotherBtn.addEventListener('click', () => {
    filePreview.style.display = 'none';
    previewBtn.style.display = 'block';
    currentFileInfo = null;
    previewBtn.click();
});

// Add catch for all fetches to show user-friendly error
function safeFetch(url, options) {
    return fetch(url, options).then(async response => {
        if (!response.ok) {
            let data;
            try { data = await response.json(); } catch { data = {}; }
            throw new Error(data.error || response.statusText);
        }
        return response.json();
    });
}

// Use safeFetch for stats and preview
function loadPoolStats() {
    safeFetch('/api/pool/stats')
        .then(data => {
            document.getElementById('fileCount').textContent = data.file_count;
            document.getElementById('totalSize').textContent = formatFileSize(data.total_size);
            document.getElementById('fileTypes').textContent = data.unique_types;
        })
        .catch(error => {
            showStatus('Error loading pool stats: ' + error.message, 'error');
        });
}

function loadSecurityStatus() {
    safeFetch('/api/security/status')
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
            showStatus('Error loading security status: ' + error.message, 'error');
        });
    safeFetch('/api/quarantine/stats')
        .then(data => {
            document.getElementById('quarantinedFiles').textContent = data.quarantined_files;
        })
        .catch(error => {
            showStatus('Error loading quarantine stats: ' + error.message, 'error');
        });
}

// Load initial stats
loadPoolStats();
loadSecurityStatus();

// On load, disable preview/download if not allowed
safeFetch('/api/file/info').then(data => {
    if (data.error) {
        previewBtn.disabled = true;
        previewBtn.textContent = 'Upload First!';
    }
}).catch(() => {
    previewBtn.disabled = true;
    previewBtn.textContent = 'Upload First!';
});
