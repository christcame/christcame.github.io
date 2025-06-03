# Security Features Documentation

## Overview

The Random File Exchange application includes comprehensive security measures to protect users from malicious files and ensure safe file sharing.

## Security Features

### 1. Dangerous File Extension Blocking

The application blocks 26 potentially dangerous file extensions:

**Executable Files:**
- `.exe`, `.bat`, `.cmd`, `.com`, `.scr`, `.pif`

**Script Files:**
- `.vbs`, `.js`, `.jar`, `.ps1`, `.sh`, `.py` (when dangerous)

**System Files:**
- `.dll`, `.sys`, `.msi`, `.reg`

**Archive with Executables:**
- `.cab`, `.deb`, `.rpm`

**Other Dangerous Types:**
- `.iso`, `.img`, `.dmg`, `.app`, `.ipa`, `.apk`, `.lnk`, `.url`

### 2. VirusTotal Integration

**API Integration:**
- Supports VirusTotal API v2 for virus scanning
- Requires `VIRUSTOTAL_API_KEY` environment variable
- Scans files using SHA-256 hash lookup
- Falls back to file upload if hash not found

**Scan Results:**
- Files marked as infected are automatically quarantined
- Clean files are allowed into the pool
- Scan results included in upload response

### 3. Quarantine System

**Automatic Quarantine:**
- Infected files moved to `quarantine/` folder
- Original filename preserved with timestamp
- Quarantined files excluded from random downloads

**Quarantine Statistics:**
- Real-time count of quarantined files
- Total size of quarantined content
- Accessible via `/api/quarantine/stats`

### 4. File Size Limits

- Maximum file size: 50MB
- Prevents resource exhaustion attacks
- Configurable via `MAX_FILE_SIZE` constant

### 5. Security Monitoring

**Security Status Endpoint:** `/api/security/status`
```json
{
  "virustotal_enabled": true/false,
  "dangerous_extensions_blocked": 26,
  "allowed_extensions": 24,
  "quarantine_folder": "quarantine",
  "max_file_size_mb": 50
}
```

**Quarantine Stats Endpoint:** `/api/quarantine/stats`
```json
{
  "quarantined_files": 0,
  "total_size": 0
}
```

## Configuration

### Environment Variables

```bash
# Optional: VirusTotal API key for virus scanning
export VIRUSTOTAL_API_KEY="your_api_key_here"
```

### File Structure

```
uploads/          # Safe files available for download
quarantine/       # Quarantined infected files
server.log        # Application logs
```

## Security Workflow

### Upload Process

1. **File Extension Check**
   - Reject dangerous extensions immediately
   - Return error: "File type is potentially dangerous and not allowed"

2. **File Size Validation**
   - Reject files exceeding 50MB limit
   - Return error with size information

3. **Virus Scanning** (if VirusTotal API available)
   - Calculate SHA-256 hash
   - Query VirusTotal for existing scan results
   - Upload file for scanning if hash not found
   - Wait for scan completion (up to 60 seconds)

4. **Quarantine Decision**
   - Files with positive virus detections → quarantine
   - Clean files → move to uploads folder
   - Scan failures → allow with warning

5. **Response Generation**
   - Include security scan results
   - Provide file metadata
   - Update pool statistics

### Download Process

- Only files in `uploads/` folder are available
- Quarantined files are never served
- Random selection from safe files only

## Security Indicators

### Web Interface

The security status section displays:

- **Virus Scanning Status:**
  - ✅ Enabled (green) - VirusTotal API configured
  - ⚠️ Disabled (yellow) - No API key provided

- **Blocked Extensions:** Count of dangerous file types blocked
- **Quarantined Files:** Number of infected files in quarantine
- **Max File Size:** Upload size limit in MB

### API Responses

Upload responses include security information:

```json
{
  "success": true,
  "filename": "abc123_document.pdf",
  "security_scan": {
    "scan_performed": true,
    "clean": true,
    "reason": "No threats detected"
  }
}
```

## Best Practices

### For Administrators

1. **Configure VirusTotal API:**
   - Obtain free API key from VirusTotal
   - Set `VIRUSTOTAL_API_KEY` environment variable
   - Monitor scan quotas and usage

2. **Monitor Quarantine:**
   - Regularly check quarantine folder
   - Review quarantined files for false positives
   - Clean up old quarantined files as needed

3. **Log Monitoring:**
   - Check `server.log` for security events
   - Monitor for repeated dangerous file uploads
   - Watch for API quota exhaustion

### For Users

1. **File Selection:**
   - Use common, safe file formats
   - Avoid executable and script files
   - Scan files locally before upload

2. **Size Considerations:**
   - Keep files under 50MB limit
   - Compress large files when appropriate

## Troubleshooting

### Common Issues

**"File type is potentially dangerous"**
- File extension is in blocked list
- Use alternative format or contact administrator

**"Virus scan failed"**
- VirusTotal API quota exceeded
- Network connectivity issues
- File may still be uploaded with warning

**Upload timeout**
- File too large for virus scanning
- Reduce file size or try again later

### Security Logs

Check `server.log` for detailed security events:
- Dangerous file upload attempts
- Virus scan results
- Quarantine actions
- API errors

## Security Limitations

1. **File Content Analysis:**
   - Only extension-based filtering for dangerous files
   - Relies on VirusTotal for malware detection
   - No deep content inspection

2. **API Dependencies:**
   - VirusTotal API rate limits
   - Network connectivity requirements
   - Potential for false positives/negatives

3. **Storage Security:**
   - Files stored in plain text
   - No encryption at rest
   - Quarantine files remain accessible to admin

## Future Enhancements

- File content-based analysis
- Custom virus scanning engines
- Encrypted file storage
- User authentication and file ownership
- Advanced threat detection
- Automated quarantine cleanup