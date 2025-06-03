# Random File Exchange

A simple file sharing site where users can upload a random file and receive a random file from the pool in return.

## Features

- **Random File Exchange**: Upload any file and get a random file back from the pool
- **Drag & Drop Interface**: Easy-to-use web interface with drag-and-drop upload
- **Pool Statistics**: Real-time statistics showing file count, total size, and file types
- **File Type Support**: Supports text files, PDFs, images, documents, media files, archives, and code files
- **Size Limit**: Maximum file size of 50MB
- **Automatic Cleanup**: Files are automatically removed from the pool when downloaded

## How It Works

1. **Upload**: Users upload a file through the web interface
2. **Pool**: The file is added to a shared pool with a unique identifier
3. **Download**: Users can download a random file from the pool
4. **Exchange**: Each download removes the file from the pool, ensuring fair exchange

## Technical Details

- **Backend**: Flask web application with REST API
- **Frontend**: Embedded HTML/CSS/JavaScript interface
- **Storage**: Local file system with unique file naming
- **Security**: File type validation and size limits
- **CORS**: Cross-origin support for API access

## API Endpoints

- `GET /` - Web interface
- `GET /api/pool/stats` - Get pool statistics
- `POST /api/upload` - Upload a file
- `GET /api/download` - Download a random file

## Running the Application

```bash
python file_sharing_app.py
```

The server will start on port 8080 and be accessible at `http://localhost:8080`.

## Requirements

- Python 3.6+
- Flask
- Flask-CORS

Install dependencies:
```bash
pip install flask flask-cors
```

## File Structure

```
file_sharing_app.py     # Main application
file_pool/              # Directory for uploaded files (auto-created)
test_*.txt              # Sample test files
.gitignore              # Git ignore rules
```

## Security Considerations

- File type validation prevents executable uploads
- Size limits prevent abuse
- Unique file naming prevents conflicts
- No permanent storage of user data
- Local file system only (not suitable for production without modifications)

## Future Enhancements

- User authentication
- File encryption
- Database storage
- File expiration
- Download history
- File categories
- Production deployment configuration