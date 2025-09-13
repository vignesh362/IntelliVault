#!/usr/bin/env python3
"""
Simple test script for IntelliVault Functions
"""

import os
import sys
from pathlib import Path

# Add Security directory to path
sys.path.append(str(Path(__file__).parent / "Security"))

from IntelliVaultFunctions import *

def test_intellivault_functions():
    """Test the IntelliVault functions"""
    print("Testing IntelliVault Functions")
    print("=" * 40)
    
    # Test authentication
    print("\n1. Testing authentication...")
    set_master_password("test123")
    auth_result = authenticate_user("test123")
    print(f"   Authentication: {auth_result['message']}")
    
    if not auth_result['success']:
        print("   ✗ Authentication failed, stopping test")
        return
    
    # Test file operations if test file exists
    test_file = "Test Files/vov.pdf"
    if os.path.exists(test_file):
        print(f"\n2. Testing with file: {test_file}")
        
        # Add file metadata
        print("   Adding file metadata...")
        add_result = add_file_metadata(test_file, {"tags": ["test"], "category": "demo"})
        print(f"   Result: {add_result['message']}")
        
        if add_result['success']:
            file_id = add_result['file_id']
            
            # Split file
            print("   Splitting file...")
            split_result = split_file(test_file, "test_chunks", tags=["test"])
            print(f"   Result: {split_result['message']}")
            
            if split_result['success']:
                print(f"   Created {split_result['total_chunks']} chunks")
                
                # Reconstruct file
                print("   Reconstructing file...")
                reconstruct_result = reconstruct_file(
                    file_id, 
                    "test_output/reconstructed.pdf", 
                    "test_chunks"
                )
                print(f"   Result: {reconstruct_result['message']}")
                
                if reconstruct_result['success']:
                    print(f"   Output: {reconstruct_result['output_path']}")
                    print(f"   Size: {reconstruct_result['file_size']} bytes")
    
    # Test file listing
    print("\n3. Testing file listing...")
    files_result = list_files()
    print(f"   Found {files_result['total_count']} files")
    
    # Test search
    print("\n4. Testing file search...")
    search_result = search_files(file_type=".pdf")
    print(f"   Found {search_result['total_count']} PDF files")
    
    # Test stats
    print("\n5. Testing database stats...")
    stats_result = get_database_stats()
    if stats_result['success']:
        stats = stats_result['stats']
        print(f"   Total files: {stats['total_files']}")
        print(f"   Total storage: {stats['total_storage_mb']} MB")
    
    # Test logout
    print("\n6. Testing logout...")
    logout_result = logout_user()
    print(f"   Logout: {logout_result['message']}")
    
    print("\n" + "=" * 40)
    print("✓ All tests completed!")

if __name__ == "__main__":
    test_intellivault_functions()
