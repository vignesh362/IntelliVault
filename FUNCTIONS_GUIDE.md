# IntelliVault Functions Guide

## Overview

IntelliVault Functions provides a simple, function-based interface for secure file chunking, encryption, and management. It uses a master password authentication system with SHA-256 hashing.

## Quick Start

```python
from Security.IntelliVaultFunctions import *

# 1. Set master password and authenticate
set_master_password("your_master_password")
auth_result = authenticate_user("your_master_password")

if auth_result['success']:
    print("Authenticated successfully!")
    
    # 2. Add file to database
    add_result = add_file_metadata("path/to/file.pdf", {
        "tags": ["work", "confidential"],
        "category": "document"
    })
    
    # 3. Split file into chunks
    split_result = split_file(
        file_path="path/to/file.pdf",
        output_dir="chunks",
        tags=["work", "confidential"],
        use_encryption=True
    )
    
    # 4. Reconstruct file from chunks
    reconstruct_result = reconstruct_file(
        file_id=split_result['file_id'],
        output_path="reconstructed_file.pdf",
        chunk_directory="chunks"
    )
    
    # 5. Logout
    logout_user()
```

## Available Functions

### Authentication Functions

#### `set_master_password(password: str) -> bool`
Set the master password for the session.

**Parameters:**
- `password`: Master password string

**Returns:**
- `bool`: True if password set successfully

#### `authenticate_user(password: str) -> Dict[str, Any]`
Authenticate user with master password.

**Parameters:**
- `password`: Master password string

**Returns:**
```python
{
    'success': bool,
    'message': str,
    'user_id': str  # if successful
}
```

#### `logout_user() -> Dict[str, Any]`
Logout current user.

**Returns:**
```python
{
    'success': bool,
    'message': str
}
```

#### `is_user_authenticated() -> bool`
Check if user is currently authenticated.

**Returns:**
- `bool`: True if authenticated

### File Management Functions

#### `add_file_metadata(file_path: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]`
Add file to database with metadata.

**Parameters:**
- `file_path`: Path to the file
- `metadata`: Optional metadata dictionary

**Returns:**
```python
{
    'success': bool,
    'message': str,
    'file_id': str,  # if successful
    'is_duplicate': bool
}
```

#### `split_file(file_path: str, output_dir: str = "chunks", chunk_size: int = None, tags: List[str] = None, use_encryption: bool = True) -> Dict[str, Any]`
Split file into encrypted chunks.

**Parameters:**
- `file_path`: Path to the file to split
- `output_dir`: Directory to store chunks (default: "chunks")
- `chunk_size`: Size of each chunk in bytes (auto-calculated if None)
- `tags`: List of tags to add to the file
- `use_encryption`: Whether to encrypt chunks (default: True)

**Returns:**
```python
{
    'success': bool,
    'message': str,
    'file_id': str,  # if successful
    'chunks': List[Dict],  # chunk information
    'total_chunks': int,
    'output_directory': str
}
```

#### `reconstruct_file(file_id: str, output_path: str, chunk_directory: str = None) -> Dict[str, Any]`
Reconstruct file from chunks.

**Parameters:**
- `file_id`: ID of the file to reconstruct
- `output_path`: Path where reconstructed file will be saved
- `chunk_directory`: Directory containing chunks (auto-detected if None)

**Returns:**
```python
{
    'success': bool,
    'message': str,
    'output_path': str,  # if successful
    'file_size': int,
    'original_filename': str
}
```

#### `list_files(limit: int = 100, offset: int = 0) -> Dict[str, Any]`
Get list of files for current user.

**Parameters:**
- `limit`: Maximum number of files to return
- `offset`: Number of files to skip

**Returns:**
```python
{
    'success': bool,
    'message': str,
    'files': List[Dict],  # file information
    'total_count': int
}
```

#### `get_file_details(file_id: str) -> Dict[str, Any]`
Get detailed information about a file.

**Parameters:**
- `file_id`: ID of the file

**Returns:**
```python
{
    'success': bool,
    'message': str,
    'file_details': Dict  # detailed file information
}
```

#### `search_files(query: str = None, file_type: str = None, is_chunked: bool = None, is_encrypted: bool = None) -> Dict[str, Any]`
Search files with various filters.

**Parameters:**
- `query`: Search query for filename or path
- `file_type`: File type filter (e.g., ".pdf")
- `is_chunked`: Filter by chunked status
- `is_encrypted`: Filter by encrypted status

**Returns:**
```python
{
    'success': bool,
    'message': str,
    'files': List[Dict],  # matching files
    'total_count': int
}
```

#### `add_file_tag(file_id: str, tag_name: str, tag_value: str = None) -> Dict[str, Any]`
Add a tag to a file.

**Parameters:**
- `file_id`: ID of the file
- `tag_name`: Name of the tag
- `tag_value`: Optional value for the tag

**Returns:**
```python
{
    'success': bool,
    'message': str,
    'tag_id': str  # if successful
}
```

#### `delete_file(file_id: str) -> Dict[str, Any]`
Delete a file and all its chunks.

**Parameters:**
- `file_id`: ID of the file to delete

**Returns:**
```python
{
    'success': bool,
    'message': str
}
```

#### `get_database_stats() -> Dict[str, Any]`
Get database statistics.

**Returns:**
```python
{
    'success': bool,
    'message': str,
    'stats': Dict  # database statistics
}
```

### Utility Functions

#### `quick_setup(master_password: str, db_path: str = "intellivault.db") -> bool`
Quick setup with master password.

**Parameters:**
- `master_password`: Master password
- `db_path`: Path to database file

**Returns:**
- `bool`: True if setup successful

## Usage Examples

### Basic File Operations

```python
from Security.IntelliVaultFunctions import *

# Setup
set_master_password("my_secure_password")
authenticate_user("my_secure_password")

# Add file
add_result = add_file_metadata("document.pdf", {
    "tags": ["work", "important"],
    "category": "document"
})

# Split file
split_result = split_file(
    "document.pdf",
    "chunks",
    tags=["work", "important"]
)

# List files
files = list_files()
for file in files['files']:
    print(f"File: {file['filename']} - {file['file_size']} bytes")

# Reconstruct file
reconstruct_file(
    split_result['file_id'],
    "reconstructed_document.pdf",
    "chunks"
)

# Logout
logout_user()
```

### File Search and Management

```python
# Search for PDF files
pdf_files = search_files(file_type=".pdf")

# Search for encrypted files
encrypted_files = search_files(is_encrypted=True)

# Search by filename
search_results = search_files(query="document")

# Add tags to file
add_file_tag(file_id, "priority", "high")
add_file_tag(file_id, "department", "finance")

# Get file details
details = get_file_details(file_id)
print(f"File has {len(details['file_details']['chunks'])} chunks")
print(f"Tags: {[tag['tag_name'] for tag in details['file_details']['tags']]}")
```

### Database Statistics

```python
# Get database statistics
stats = get_database_stats()
if stats['success']:
    print(f"Total files: {stats['stats']['total_files']}")
    print(f"Total storage: {stats['stats']['total_storage_mb']} MB")
    print(f"Chunked files: {stats['stats']['chunked_files']}")
    print(f"Encrypted files: {stats['stats']['encrypted_files']}")
```

## Error Handling

All functions return a dictionary with a `success` field indicating whether the operation was successful:

```python
result = split_file("file.pdf", "chunks")

if result['success']:
    print(f"Success: {result['message']}")
    print(f"File ID: {result['file_id']}")
    print(f"Chunks created: {result['total_chunks']}")
else:
    print(f"Error: {result['message']}")
```

## Security Features

1. **Master Password Authentication**: Single password for all operations
2. **SHA-256 Hashing**: Passwords are hashed before storage/comparison
3. **File Encryption**: AES-256-GCM encryption for file chunks
4. **Access Logging**: Complete audit trail of all operations
5. **User Isolation**: Each user only sees their own files

## File Structure

When you split a file, the following structure is created:

```
chunks/
├── chunk_00001.part
├── chunk_00002.part
├── chunk_00003.part
└── manifest.json
```

The `manifest.json` contains metadata about the original file and chunk information.

## Best Practices

1. **Always authenticate** before performing operations
2. **Check return values** for success/failure
3. **Use meaningful tags** for file organization
4. **Regular cleanup** of unused files
5. **Backup database** regularly
6. **Use strong master passwords**

## Integration with Frontend

These functions can be easily integrated with any frontend framework:

- **Web Applications**: Call functions from JavaScript/Python backend
- **Desktop Applications**: Use functions directly in Python applications
- **Mobile Applications**: Integrate with mobile app backends
- **Command Line Tools**: Use functions in CLI scripts

The functions provide a clean, consistent interface that's easy to integrate with any frontend technology.
