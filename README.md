# IntelliVault - Secure File Chunking with Database Management

A secure file chunking and encryption system with comprehensive database tracking and management capabilities.

## Features

- **File Chunking**: Split large files into manageable chunks
- **AES-256-GCM Encryption**: Military-grade encryption for each chunk
- **Database Management**: Complete file tracking and metadata storage
- **Master Password Authentication**: Single password system with SHA-256 hashing
- **File Organization**: Tagging and search capabilities
- **Cross-platform**: Works on Windows, macOS, and Linux
- **Simple Functions**: Easy-to-use function-based interface

## Installation

1. **Clone the repository**:
   ```bash
   git clone <your-repo-url>
   cd "Qualcom intellivault"
   ```

2. **Create virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Quick Start

### 1. Basic File Operations

```python
from Security.IntelliVaultFunctions import *

# Set master password and authenticate
set_master_password("your_master_password")
authenticate_user("your_master_password")

# Add file to database
add_file_metadata("document.pdf", {"tags": ["work", "confidential"]})

# Split file into chunks
split_result = split_file("document.pdf", "chunks", tags=["work", "confidential"])

# Reconstruct file from chunks
reconstruct_file(split_result['file_id'], "reconstructed.pdf", "chunks")

# Logout
logout_user()
```

### 2. Test the System

```bash
python test_functions.py
```

## Detailed Usage

### Core Functions

**Authentication**:
```python
# Set master password
set_master_password("your_password")

# Authenticate
auth_result = authenticate_user("your_password")

# Check authentication status
if is_user_authenticated():
    print("User is authenticated")

# Logout
logout_user()
```

**File Management**:
```python
# Add file to database
add_result = add_file_metadata("file.pdf", {
    "tags": ["work", "confidential"],
    "category": "document"
})

# Split file into chunks
split_result = split_file(
    "file.pdf", 
    "chunks", 
    tags=["work", "confidential"],
    use_encryption=True
)

# Reconstruct file
reconstruct_result = reconstruct_file(
    split_result['file_id'],
    "reconstructed.pdf",
    "chunks"
)
```

**File Operations**:
```python
# List all files
files = list_files()

# Search files
pdf_files = search_files(file_type=".pdf")
encrypted_files = search_files(is_encrypted=True)

# Get file details
details = get_file_details(file_id)

# Add tags
add_file_tag(file_id, "priority", "high")

# Delete file
delete_file(file_id)
```

### Command Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--input` | `-i` | Input file to split |
| `--output-dir` | `-o` | Output directory for chunks |
| `--reconstruct` | `-r` | Reconstruct file from chunks |
| `--passphrase` | `-p` | Passphrase for encryption |
| `--username` | `-u` | Username for keystroke auth |
| `--keystroke-auth` | `-k` | Require keystroke authentication |
| `--register-user` | | Register new user |
| `--list-users` | | List registered users |
| `--chunk-size` | `-c` | Chunk size in bytes |
| `--target-chunks` | `-t` | Target number of chunks |

## How Keystroke Dynamics Works

### Data Collection
The system measures three types of timing patterns:

1. **Hold Time**: Time between key press and release
2. **Keydown-Keydown Time**: Time between pressing consecutive keys
3. **Keyup-Keydown Time**: Time between releasing one key and pressing the next

### Machine Learning
- Uses multiple algorithms (Random Forest, SVM, Logistic Regression, KNN)
- Automatically selects the best performing model
- Cross-validation ensures robust performance
- Confidence scoring for authentication decisions

### Security Benefits
- **Unique Biometric**: Each person has unique typing patterns
- **Continuous Authentication**: Can be used for ongoing verification
- **Non-intrusive**: No special hardware required
- **Multi-factor**: Combines with traditional passwords

## File Formats Supported

The chunker works with **any file type**:
- Documents: PDF, DOCX, XLSX, PPTX
- Media: MP4, AVI, MOV, JPG, PNG, GIF
- Archives: ZIP, RAR, 7Z, TAR
- Executables: EXE, APP, BIN
- Any binary file

## Security Features

### Encryption
- **AES-256-GCM**: Military-grade encryption
- **Scrypt KDF**: Password-based key derivation
- **Unique Nonces**: Each chunk encrypted with different nonce
- **Integrity Verification**: SHA-256 checksums

### Keystroke Authentication
- **Biometric Verification**: Unique typing patterns
- **Confidence Scoring**: Measures authentication certainty
- **Model Persistence**: Trained models saved for reuse
- **Real-time Collection**: Captures actual keystroke timing

### File Integrity
- **SHA-256 Verification**: Ensures file integrity after reconstruction
- **Chunk Validation**: Verifies each chunk during reconstruction
- **Manifest Tracking**: Complete metadata for file reconstruction

## Example Workflows

### 1. Secure Document Storage

```bash
# Register user
python Security/SecureChunker.py --register-user --username john

# Split sensitive document with dual authentication
python Security/SecureChunker.py --input "confidential.pdf" --username john --keystroke-auth --passphrase "secret123"

# Later, reconstruct with authentication
python Security/SecureChunker.py --reconstruct "restored.pdf" --username john --keystroke-auth --passphrase "secret123"
```

### 2. Large File Distribution

```bash
# Split large video file into chunks
python Security/SecureChunker.py --input "movie.mp4" --target-chunks 1000 --passphrase "video_password"

# Distribute chunks across multiple locations
# Reconstruct when needed
python Security/SecureChunker.py --reconstruct "movie_restored.mp4" --passphrase "video_password"
```

### 3. Backup and Recovery

```bash
# Create encrypted backup chunks
python Security/SecureChunker.py --input "database.sql" --username admin --keystroke-auth --passphrase "backup_key"

# Restore from backup
python Security/SecureChunker.py --reconstruct "database_restored.sql" --username admin --keystroke-auth --passphrase "backup_key"
```

## Troubleshooting

### Keystroke Collection Issues

If real-time keystroke collection fails:
```bash
# Install pynput for real-time collection
pip install pynput

# Or use simulation mode
python Security/KeystrokeCollector.py
```

### Authentication Failures

- Ensure you're using the same username used during registration
- Type your passphrase naturally - don't try to match previous samples exactly
- Collect more training samples if authentication is inconsistent

### File Reconstruction Issues

- Verify all chunk files are present
- Check that the manifest.json file exists
- Ensure you're using the correct passphrase and username

## Technical Details

### Chunk Format
Each encrypted chunk contains:
- Magic header: `CRPTv1\0`
- Header length (4 bytes)
- JSON header with encryption parameters
- Encrypted data

### Manifest Format
```json
{
  "version": 1,
  "original_filename": "file.pdf",
  "original_size": 1048576,
  "original_sha256": "abc123...",
  "chunk_size": 1048576,
  "encrypted": true,
  "encryption_info": {...},
  "keystroke_auth_required": true,
  "username": "alice",
  "chunks": [...]
}
```

### Keystroke Features
- Hold time statistics (mean, std, min, max)
- Keydown-keydown timing statistics
- Keyup-keydown timing statistics
- Sequence length

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is based on the keystroke dynamics methodology from [nikhilagr/User-Authentication-using-keystroke-dynamics](https://github.com/nikhilagr/User-Authentication-using-keystroke-dynamics).

## References

- [Keystroke Dynamics Research](https://www.nikhildagrawal.com/keystroke.html)
- [IEEE Paper on Keystroke Dynamics](https://ieeexplore.ieee.org/abstract/document/5270346)
- [Original GitHub Repository](https://github.com/nikhilagr/User-Authentication-using-keystroke-dynamics)
