# IntelliVault Database System

A comprehensive database system for tracking files, chunks, users, and metadata in the IntelliVault secure file chunking system.

## Database Schema

### Tables Overview

1. **`users`** - User accounts and keystroke model information
2. **`files`** - File metadata and tracking information
3. **`chunks`** - Individual file chunk information
4. **`file_tags`** - Custom tags for file organization
5. **`access_logs`** - Audit trail of file access attempts

### Detailed Schema

#### Users Table
```sql
CREATE TABLE users (
    user_id TEXT PRIMARY KEY,           -- UUID for user
    username TEXT UNIQUE NOT NULL,      -- Username
    created_at TIMESTAMP,               -- Account creation time
    last_login TIMESTAMP,               -- Last login time
    keystroke_model_path TEXT,          -- Path to keystroke model
    is_active BOOLEAN DEFAULT 1         -- Account status
);
```

#### Files Table
```sql
CREATE TABLE files (
    file_id TEXT PRIMARY KEY,           -- UUID for file
    user_id TEXT NOT NULL,              -- Owner user ID
    original_filename TEXT NOT NULL,    -- Original filename
    original_path TEXT NOT NULL,        -- Original file path
    file_size INTEGER NOT NULL,         -- File size in bytes
    file_hash TEXT NOT NULL,            -- SHA-256 hash
    file_type TEXT,                     -- File extension
    created_at TIMESTAMP,               -- File registration time
    modified_at TIMESTAMP,              -- Last modification time
    is_chunked BOOLEAN DEFAULT 0,       -- Whether file is chunked
    is_encrypted BOOLEAN DEFAULT 0,     -- Whether file is encrypted
    encryption_algorithm TEXT,          -- Encryption algorithm used
    keystroke_auth_required BOOLEAN DEFAULT 0, -- Keystroke auth required
    FOREIGN KEY (user_id) REFERENCES users (user_id)
);
```

#### Chunks Table
```sql
CREATE TABLE chunks (
    chunk_id TEXT PRIMARY KEY,          -- UUID for chunk
    file_id TEXT NOT NULL,              -- Parent file ID
    chunk_index INTEGER NOT NULL,       -- Chunk order index
    chunk_filename TEXT NOT NULL,       -- Chunk filename
    chunk_path TEXT NOT NULL,           -- Chunk file path
    chunk_size INTEGER NOT NULL,        -- Chunk size in bytes
    chunk_hash TEXT,                    -- Chunk hash (optional)
    is_encrypted BOOLEAN DEFAULT 0,     -- Whether chunk is encrypted
    encryption_nonce TEXT,              -- Encryption nonce (if encrypted)
    created_at TIMESTAMP,               -- Chunk creation time
    FOREIGN KEY (file_id) REFERENCES files (file_id)
);
```

#### File Tags Table
```sql
CREATE TABLE file_tags (
    tag_id TEXT PRIMARY KEY,            -- UUID for tag
    file_id TEXT NOT NULL,              -- Parent file ID
    tag_name TEXT NOT NULL,             -- Tag name
    tag_value TEXT,                     -- Tag value (optional)
    created_at TIMESTAMP,               -- Tag creation time
    FOREIGN KEY (file_id) REFERENCES files (file_id)
);
```

#### Access Logs Table
```sql
CREATE TABLE access_logs (
    log_id TEXT PRIMARY KEY,            -- UUID for log entry
    file_id TEXT NOT NULL,              -- File being accessed
    user_id TEXT NOT NULL,              -- User accessing file
    action TEXT NOT NULL,               -- Action performed
    success BOOLEAN NOT NULL,           -- Whether action succeeded
    ip_address TEXT,                    -- Client IP address
    user_agent TEXT,                    -- Client user agent
    timestamp TIMESTAMP,                -- Access time
    details TEXT,                       -- Additional details
    FOREIGN KEY (file_id) REFERENCES files (file_id),
    FOREIGN KEY (user_id) REFERENCES users (user_id)
);
```

## Usage Examples

### 1. Basic File Operations

#### Register a User
```python
from Security.DatabaseChunker import DatabaseChunker

chunker = DatabaseChunker()
chunker.register_user("alice")
```

#### Split a File with Database Tracking
```python
success = chunker.split_file(
    input_file="document.pdf",
    out_dir="chunks",
    username="alice",
    passphrase="secret123",
    require_keystroke_auth=True,
    tags=["work", "confidential"]
)
```

#### Reconstruct a File
```python
success = chunker.join_chunks(
    in_dir="chunks",
    output_file="reconstructed.pdf",
    username="alice",
    passphrase="secret123",
    require_keystroke_auth=True
)
```

### 2. File Management

#### List User Files
```python
files = chunker.list_user_files("alice")
for file in files:
    print(f"{file['original_filename']} - {file['file_size']} bytes")
```

#### Search Files
```python
# Search by filename
results = chunker.search_files("alice", query="document")

# Search by file type
results = chunker.search_files("alice", file_type=".pdf")

# Search encrypted files
results = chunker.search_files("alice", is_encrypted=True)
```

#### Get File Details
```python
details = chunker.get_file_details("alice", file_id)
print(f"File: {details['original_filename']}")
print(f"Chunks: {len(details['chunks'])}")
print(f"Tags: {[tag['tag_name'] for tag in details['tags']]}")
```

### 3. Database Management

#### Database Statistics
```python
from Security.DatabaseManager import DatabaseManager

manager = DatabaseManager()
stats = manager.get_database_stats()
print(f"Total files: {stats['total_files']}")
print(f"Total storage: {stats['total_storage_mb']} MB")
```

#### Backup and Restore
```python
# Backup database
manager.backup_database("backup.db")

# Restore database
manager.restore_database("backup.db")
```

#### Export/Import Data
```python
# Export all data to JSON
manager.export_data("export.json")

# Import data from JSON
manager.import_data("export.json")
```

## Command Line Interface

### Database Chunker Commands

#### Register User
```bash
python Security/DatabaseChunker.py --register-user --username alice
```

#### Split File
```bash
python Security/DatabaseChunker.py \
    --input "document.pdf" \
    --username alice \
    --passphrase "secret123" \
    --keystroke-auth \
    --tags "work" "confidential"
```

#### List Files
```bash
python Security/DatabaseChunker.py --list-files --username alice
```

#### Search Files
```bash
python Security/DatabaseChunker.py --search "document" --username alice
```

#### Get File Details
```bash
python Security/DatabaseChunker.py --file-details FILE_ID --username alice
```

### Database Manager Commands

#### Show Statistics
```bash
python Security/DatabaseManager.py --stats
```

#### Backup Database
```bash
python Security/DatabaseManager.py --backup backup.db
```

#### Export Data
```bash
python Security/DatabaseManager.py --export data.json
```

#### Cleanup Orphaned Data
```bash
python Security/DatabaseManager.py --cleanup
```

#### Optimize Database
```bash
python Security/DatabaseManager.py --optimize
```

## Key Features

### 1. **Complete File Tracking**
- Original file location and metadata
- File hash for integrity verification
- Chunk information and locations
- Encryption status and algorithms

### 2. **User Management**
- User registration and authentication
- Keystroke model integration
- Access control and permissions

### 3. **Audit Trail**
- Complete access logging
- Success/failure tracking
- IP address and user agent logging
- Detailed action descriptions

### 4. **File Organization**
- Custom tagging system
- Search and filtering capabilities
- File categorization
- Metadata management

### 5. **Database Maintenance**
- Automatic cleanup of orphaned data
- Database optimization
- Backup and restore functionality
- Data export/import

## Security Features

### 1. **Access Control**
- User-based file ownership
- Keystroke authentication integration
- Access attempt logging

### 2. **Data Integrity**
- File hash verification
- Chunk integrity checking
- Database constraint enforcement

### 3. **Audit Compliance**
- Complete access logging
- User action tracking
- Security event monitoring

## Performance Considerations

### 1. **Indexing**
- Optimized indexes on frequently queried columns
- Composite indexes for complex queries
- Foreign key relationships for data integrity

### 2. **Query Optimization**
- Efficient SQL queries
- Proper use of indexes
- Query result caching where appropriate

### 3. **Storage Management**
- Automatic cleanup of orphaned data
- Database vacuum and optimization
- Efficient data types and storage

## Migration and Backup

### 1. **Database Backup**
```python
manager = DatabaseManager()
manager.backup_database("backup_2024.db")
```

### 2. **Data Export**
```python
manager.export_data("full_export.json")
```

### 3. **Data Import**
```python
manager.import_data("full_export.json")
```

### 4. **Database Reset**
```python
manager.reset_database()  # WARNING: Deletes all data!
```

## Troubleshooting

### Common Issues

1. **Database Locked**: Ensure no other processes are using the database
2. **Foreign Key Violations**: Check that referenced records exist
3. **Disk Space**: Monitor database size and clean up if needed
4. **Performance**: Run database optimization regularly

### Maintenance Tasks

1. **Regular Cleanup**: Remove orphaned data
2. **Database Optimization**: Run VACUUM and ANALYZE
3. **Backup Verification**: Test backup and restore procedures
4. **Log Rotation**: Archive old access logs if needed

## Integration with IntelliVault

The database system seamlessly integrates with:
- **SecureChunker**: File chunking and encryption
- **KeystrokeAuth**: Biometric authentication
- **Crypter**: File encryption/decryption
- **DatabaseChunker**: Combined functionality

This provides a complete solution for secure file management with full tracking, auditing, and organization capabilities.

