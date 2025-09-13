#!/usr/bin/env python3
"""
Test OS-based File ID generation
"""

import os
import sys
from pathlib import Path

# Add Security directory to path
sys.path.append(str(Path(__file__).parent / "Security"))

from IntelliVaultFunctions import *

def test_os_file_ids():
    """Test OS-based file ID generation"""
    print("Testing OS-based File IDs")
    print("=" * 40)
    
    # Test file
    test_file = "Test Files/vov.pdf"
    if not os.path.exists(test_file):
        print(f"Test file {test_file} not found")
        return
    
    # Setup
    set_master_password("test123")
    authenticate_user("test123")
    
    print(f"\n1. Testing with file: {test_file}")
    
    # Test OS-based file ID
    print("\n2. Adding file with OS-based ID...")
    add_result_os = add_file_metadata(test_file, {"tags": ["os_test"]}, use_os_id=True)
    print(f"   OS-based ID: {add_result_os['file_id']}")
    print(f"   Result: {add_result_os['message']}")
    
    # Test UUID-based file ID
    print("\n3. Adding file with UUID-based ID...")
    add_result_uuid = add_file_metadata(test_file, {"tags": ["uuid_test"]}, use_os_id=False)
    print(f"   UUID-based ID: {add_result_uuid['file_id']}")
    print(f"   Result: {add_result_uuid['message']}")
    
    # Show the difference
    print(f"\n4. ID Comparison:")
    print(f"   OS-based ID:  {add_result_os['file_id']}")
    print(f"   UUID-based ID: {add_result_uuid['file_id']}")
    print(f"   Length difference: {len(add_result_os['file_id'])} vs {len(add_result_uuid['file_id'])}")
    
    # Test file details
    if add_result_os['success']:
        print(f"\n5. File details for OS-based ID:")
        details = get_file_details(add_result_os['file_id'])
        if details['success']:
            file_info = details['file_details']
            print(f"   Filename: {file_info['filename']}")
            print(f"   File ID: {file_info['file_id']}")
            print(f"   File Hash: {file_info['file_hash']}")
            print(f"   File Size: {file_info['file_size']} bytes")
    
    # Test that same file gets same OS-based ID
    print(f"\n6. Testing ID consistency...")
    add_result_os2 = add_file_metadata(test_file, {"tags": ["consistency_test"]}, use_os_id=True)
    print(f"   First OS ID:  {add_result_os['file_id']}")
    print(f"   Second OS ID: {add_result_os2['file_id']}")
    print(f"   IDs match: {add_result_os['file_id'] == add_result_os2['file_id']}")
    
    # Show system info
    print(f"\n7. System Information:")
    import platform
    print(f"   OS: {platform.system()}")
    print(f"   Platform: {platform.platform()}")
    
    # Test with different files
    print(f"\n8. Testing with different files...")
    if os.path.exists("Test Files"):
        for file in os.listdir("Test Files"):
            if file.endswith(('.pdf', '.txt', '.doc')):
                file_path = os.path.join("Test Files", file)
                add_result = add_file_metadata(file_path, {"tags": ["multi_file_test"]}, use_os_id=True)
                print(f"   {file}: {add_result['file_id']}")
    
    # List all files
    print(f"\n9. All files in database:")
    files_result = list_files()
    for file in files_result['files']:
        print(f"   {file['filename']}: {file['file_id']}")
    
    # Logout
    logout_user()
    
    print(f"\n" + "=" * 40)
    print("OS File ID test completed!")

if __name__ == "__main__":
    test_os_file_ids()
