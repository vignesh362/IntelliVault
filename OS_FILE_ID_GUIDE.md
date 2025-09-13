# OS-Based File ID System

## Overview

IntelliVault now supports OS-based file IDs in addition to UUID-based IDs. This allows you to use operating system file identifiers instead of random UUIDs.

## How OS File IDs Work

The system automatically detects your operating system and uses the appropriate method:

### **Windows**
- **Source**: File index + device + size
- **Format**: `os_<16-char-hash>`
- **Example**: `os_9i8h7g6f5e4d3c2b`
- **Uniqueness**: Unique per volume

### **Unix/Linux/macOS**
- **Source**: File inode number + device ID
- **Format**: `os_<16-char-hash>`
- **Example**: `os_31137a4b71c6045f`
- **Uniqueness**: Unique per filesystem

## Usage

### **Enable OS-based File IDs (Default)**
```python
from Security.IntelliVaultFunctions import *

# Set master password and authenticate
set_master_password("your_password")
authenticate_user("your_password")

# Add file with OS-based ID (default)
add_result = add_file_metadata("document.pdf", use_os_id=True)
print(f"OS-based File ID: {add_result['file_id']}")
# Output: os_31137a4b71c6045f
```

### **Use UUID-based File IDs**
```python
# Add file with UUID-based ID
add_result = add_file_metadata("document.pdf", use_os_id=False)
print(f"UUID-based File ID: {add_result['file_id']}")
# Output: 3ebce28b-1b8e-4f8c-be6e-e457ca84012a
```

## Benefits of OS-based File IDs

### **1. Deterministic**
- Same file always gets same ID
- Consistent across sessions
- No random generation

### **2. File System Integration**
- Based on actual file system metadata
- Reflects file system structure
- Natural file identification

### **3. Shorter**
- 16 characters vs 36 characters
- More compact storage
- Easier to work with

### **4. Meaningful**
- Based on file system properties
- Can be traced back to file system
- Not just random numbers

## Comparison

| Feature | OS-based ID | UUID-based ID |
|---------|-------------|---------------|
| **Length** | 16 chars | 36 chars |
| **Format** | `os_<hash>` | `uuid4` |
| **Deterministic** | ✅ Yes | ❌ No |
| **Cross-platform** | ✅ Yes | ✅ Yes |
| **Uniqueness** | Per filesystem | Global |
| **Consistency** | ✅ Same file = same ID | ❌ Random each time |

## Examples

### **Same File, Multiple Registrations**
```python
# First registration
add_result1 = add_file_metadata("file.pdf", use_os_id=True)
print(f"First ID: {add_result1['file_id']}")

# Second registration (same file)
add_result2 = add_file_metadata("file.pdf", use_os_id=True)
print(f"Second ID: {add_result2['file_id']}")

# IDs will be identical!
# Output: os_31137a4b71c6045f
# Output: os_31137a4b71c6045f
```

### **Different Files, Different IDs**
```python
# File 1
add_result1 = add_file_metadata("file1.pdf", use_os_id=True)
print(f"File 1 ID: {add_result1['file_id']}")

# File 2
add_result2 = add_file_metadata("file2.pdf", use_os_id=True)
print(f"File 2 ID: {add_result2['file_id']}")

# IDs will be different
# Output: os_31137a4b71c6045f
# Output: os_315e357d26b79c97
```

## Technical Details

### **ID Generation Process**
1. **Get file stats**: `os.stat(file_path)`
2. **Extract system info**: inode, device, size
3. **Create identifier**: `system_inode_device`
4. **Hash identifier**: SHA-256 hash
5. **Format result**: `os_<first-16-chars>`

### **Fallback Mechanism**
If OS-based ID generation fails:
- Falls back to UUID4
- Logs the error
- Continues operation

### **Cross-platform Support**
- **Windows**: Uses file index + device + size
- **Unix/Linux/macOS**: Uses inode + device
- **Other systems**: Falls back to UUID

## Testing

Run the test script to see OS-based file IDs in action:

```bash
python test_os_file_ids.py
```

This will:
- Show OS-based vs UUID-based IDs
- Demonstrate ID consistency
- Test with multiple files
- Display system information

## When to Use Each Type

### **Use OS-based IDs when:**
- You want deterministic file identification
- File paths are stable
- You need shorter IDs
- You want file system integration
- You're working with the same files repeatedly

### **Use UUID-based IDs when:**
- You need global uniqueness
- Files might be moved/copied
- You want completely random IDs
- You're working across different systems
- You need maximum compatibility

## Migration

You can switch between ID types at any time:

```python
# Start with OS-based IDs
add_file_metadata("file.pdf", use_os_id=True)

# Later switch to UUID-based IDs
add_file_metadata("file.pdf", use_os_id=False)
```

Both types work seamlessly with all IntelliVault functions.

## Best Practices

1. **Choose one type** for consistency in your application
2. **Use OS-based IDs** for local file management
3. **Use UUID-based IDs** for distributed systems
4. **Test both types** to see which works better for your use case
5. **Document your choice** for team members

The OS-based file ID system provides a more natural and deterministic way to identify files while maintaining all the security and functionality of IntelliVault.
