# Random File Exchange

A secure file sharing application where users can upload a file and receive a random file from the pool in return.

## Features

### Core Functionality
- **Random File Exchange**: Upload any file, get a random file back
- **Pool Statistics**: Real-time view of files in the pool
- **Drag & Drop Interface**: Easy file upload with modern UI
- **Multiple File Types**: Support for 24+ safe file formats

### Security Features
- **🔒 VirusTotal Integration**: Automatic virus scanning of uploaded files
- **🚫 Dangerous File Blocking**: Blocks 26 dangerous file extensions
- **🏥 Quarantine System**: Infected files automatically quarantined
- **📊 Security Monitoring**: Real-time security status dashboard
- **📏 File Size Limits**: 50MB maximum file size
- **🛡️ Safe Downloads**: Only clean files available for download

## Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/christcame/christcame.github.io.git
cd christcame.github.io
git checkout file-sharing-site
```

### 2. Install Dependencies
```bash
pip install flask flask-cors requests
```

### 3. Optional: Configure VirusTotal (Recommended)
```bash
# Get a free API key from https://www.virustotal.com/gui/join-us
export VIRUSTOTAL_API_KEY="your_api_key_here"
```

### 4. Run the Application
```bash
python file_sharing_app.py
```

### 5. Access the Application
Open your browser to: `http://localhost:8080`

## Security Configuration

### VirusTotal API Setup
1. Visit [VirusTotal](https://www.virustotal.com/gui/join-us)
2. Create a free account
3. Get your API key from the API section
4. Set the environment variable:
   ```bash
   export VIRUSTOTAL_API_KEY="your_api_key_here"
   ```

### Security Status
- **✅ Enabled**: VirusTotal API configured and working
- **⚠️ Disabled**: No API key provided (files still checked for dangerous extensions)

## API Endpoints

### File Operations
- `POST /api/upload` - Upload a file
- `GET /api/download` - Download a random file
- `GET /api/pool/stats` - Get pool statistics

### Security Monitoring
- `GET /api/security/status` - Get security configuration
- `GET /api/quarantine/stats` - Get quarantine statistics

## File Types

### ✅ Allowed Extensions
`.txt`, `.pdf`, `.png`, `.jpg`, `.jpeg`, `.gif`, `.doc`, `.docx`, `.mp3`, `.mp4`, `.avi`, `.mov`, `.zip`, `.rar`, `.7z`, `.py`, `.js`, `.html`, `.css`, `.json`, `.xml`, `.csv`, `.xlsx`, `.pptx`

### ❌ Blocked Extensions (Dangerous)
`.exe`, `.bat`, `.cmd`, `.com`, `.scr`, `.pif`, `.vbs`, `.js`, `.jar`, `.ps1`, `.sh`, `.dll`, `.sys`, `.msi`, `.reg`, `.cab`, `.deb`, `.rpm`, `.iso`, `.img`, `.dmg`, `.app`, `.ipa`, `.apk`, `.lnk`, `.url`

## Directory Structure

```
├── file_sharing_app.py    # Main application
├── uploads/               # Safe files available for download
├── quarantine/           # Quarantined infected files
├── server.log            # Application logs
├── SECURITY.md           # Detailed security documentation
└── README.md             # This file
```

## Security Features Detail

### Virus Scanning Process
1. File uploaded and temporarily stored
2. SHA-256 hash calculated
3. VirusTotal API queried for existing scan results
4. If no results found, file uploaded to VirusTotal
5. Scan results evaluated (up to 60 second timeout)
6. Clean files moved to uploads/, infected files quarantined

### Quarantine System
- Infected files automatically moved to `quarantine/` folder
- Original filename preserved with timestamp
- Quarantined files never served to users
- Statistics available via API

### File Extension Filtering
- 26 dangerous extensions blocked at upload
- Immediate rejection with clear error message
- No processing of dangerous file types

## Usage Examples

### Upload a File
```bash
curl -X POST -F "file=@document.pdf" http://localhost:8080/api/upload
```

### Download Random File
```bash
curl -O -J http://localhost:8080/api/download
```

### Check Security Status
```bash
curl http://localhost:8080/api/security/status
```

## Troubleshooting

### Common Issues

**"File type is potentially dangerous"**
- Your file extension is blocked for security
- Use a different format or contact administrator

**"Virus scan failed"**
- VirusTotal API quota exceeded or network issue
- File may still be uploaded with warning

**Upload timeout**
- File too large or slow virus scan
- Try smaller file or wait and retry

### Logs
Check `server.log` for detailed information about:
- Security events
- Virus scan results
- Error messages
- API interactions

## Development

### Running in Development Mode
```bash
# Enable debug mode
export FLASK_ENV=development
python file_sharing_app.py
```

### Testing Security Features
```bash
# Test dangerous file blocking
curl -X POST -F "file=@test.exe" http://localhost:8080/api/upload

# Test virus scanning (requires VirusTotal API)
curl -X POST -F "file=@document.pdf" http://localhost:8080/api/upload
```

## Production Deployment

### Security Considerations
1. **Always configure VirusTotal API** for production
2. **Monitor quarantine folder** regularly
3. **Set up log rotation** for server.log
4. **Use HTTPS** in production
5. **Configure firewall** appropriately
6. **Regular security updates**

### Environment Variables
```bash
export VIRUSTOTAL_API_KEY="your_production_api_key"
export FLASK_ENV=production
```

### Reverse Proxy Configuration
For production, use nginx or Apache as reverse proxy:
```nginx
location / {
    proxy_pass http://localhost:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test security features
5. Submit a pull request

## License

This project is open source. See the repository for license details.

## Security

For security issues, please see [SECURITY.md](SECURITY.md) for detailed information about the security features and best practices.

## Support

- Check the logs in `server.log`
- Review [SECURITY.md](SECURITY.md) for security-related questions
- Open an issue on GitHub for bugs or feature requests
