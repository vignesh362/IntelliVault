#!/usr/bin/env python3
"""
IntelliVault Functions
Simple functions for frontend integration with master password authentication
"""

import hashlib
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
import uuid
from datetime import datetime

# Add Security directory to path
sys.path.append(str(Path(__file__).parent))

from Database import IntelliVaultDB
from DatabaseChunker import DatabaseChunker
from KeystrokeAuth import KeystrokeAuthenticator

class IntelliVaultManager:
    """Main manager class for IntelliVault operations"""
    
    def __init__(self, db_path: str = "intellivault.db"):
        self.db = IntelliVaultDB(db_path)
        self.keystroke_auth = KeystrokeAuthenticator()
        self.chunker = DatabaseChunker(db_path, self.keystroke_auth)
        self.master_password_hash = None
        self.current_user = None
        self.authenticated = False
    
    def set_master_password(self, password: str) -> bool:
        """Set the master password (SHA-256 hashed)"""
        try:
            self.master_password_hash = hashlib.sha256(password.encode()).hexdigest()
            return True
        except Exception as e:
            print(f"Error setting master password: {e}")
            return False
    
    def verify_master_password(self, password: str) -> bool:
        """Verify the master password"""
        if not self.master_password_hash:
            return False
        
        input_hash = hashlib.sha256(password.encode()).hexdigest()
        return input_hash == self.master_password_hash
    
    def authenticate(self, password: str) -> Dict[str, Any]:
        """Authenticate user with master password"""
        if not self.verify_master_password(password):
            return {
                'success': False,
                'message': 'Invalid master password'
            }
        
        # Create or get master user
        master_user = self.db.get_user("master_user")
        if not master_user:
            user_id = self.db.create_user("master_user")
            master_user = self.db.get_user("master_user")
        
        self.current_user = master_user
        self.authenticated = True
        
        return {
            'success': True,
            'message': 'Authentication successful',
            'user_id': master_user['user_id']
        }
    
    def logout(self) -> Dict[str, Any]:
        """Logout user"""
        self.current_user = None
        self.authenticated = False
        return {
            'success': True,
            'message': 'Logged out successfully'
        }
    
    def is_authenticated(self) -> bool:
        """Check if user is authenticated"""
        return self.authenticated

# Global manager instance
_manager = None

def initialize_intellivault(db_path: str = "intellivault.db") -> IntelliVaultManager:
    """Initialize IntelliVault manager"""
    global _manager
    _manager = IntelliVaultManager(db_path)
    return _manager

def get_manager() -> IntelliVaultManager:
    """Get the global manager instance"""
    global _manager
    if _manager is None:
        _manager = IntelliVaultManager()
    return _manager

# Authentication Functions
def set_master_password(password: str) -> bool:
    """Set master password for the session"""
    manager = get_manager()
    return manager.set_master_password(password)

def authenticate_user(password: str) -> Dict[str, Any]:
    """Authenticate user with master password"""
    manager = get_manager()
    return manager.authenticate(password)

def logout_user() -> Dict[str, Any]:
    """Logout current user"""
    manager = get_manager()
    return manager.logout()

def is_user_authenticated() -> bool:
    """Check if user is authenticated"""
    manager = get_manager()
    return manager.is_authenticated()

# File Management Functions
def add_file_metadata(file_path: str, metadata: Dict[str, Any] = None, use_os_id: bool = True) -> Dict[str, Any]:
    """Add file to database with metadata"""
    manager = get_manager()
    
    if not manager.is_authenticated():
        return {
            'success': False,
            'message': 'User not authenticated'
        }
    
    try:
        # Check if file exists
        if not os.path.exists(file_path):
            return {
                'success': False,
                'message': 'File does not exist'
            }
        
        # Check if file already exists in database using OS-based ID
        existing_file = manager.db.get_file_by_os_id(file_path)
        if existing_file:
            return {
                'success': True,
                'message': 'File already exists in database',
                'file_id': existing_file['file_id'],
                'is_duplicate': True
            }
        
        # Register file
        file_metadata = metadata or {}
        file_metadata.update({
            'is_chunked': False,
            'is_encrypted': False,
            'keystroke_auth_required': False
        })
        
        file_id = manager.db.register_file(manager.current_user['user_id'], file_path, file_metadata, use_os_id)
        
        # Add custom tags if provided
        if 'tags' in metadata:
            for tag in metadata['tags']:
                manager.db.add_file_tag(file_id, tag)
        
        return {
            'success': True,
            'message': 'File added successfully',
            'file_id': file_id,
            'is_duplicate': False
        }
        
    except Exception as e:
        return {
            'success': False,
            'message': f'Error adding file: {str(e)}'
        }

def split_file(file_path: str, output_dir: str = "chunks", chunk_size: int = None, 
               tags: List[str] = None, use_encryption: bool = True) -> Dict[str, Any]:
    """Split file into chunks with optional encryption"""
    manager = get_manager()
    
    if not manager.is_authenticated():
        return {
            'success': False,
            'message': 'User not authenticated'
        }
    
    try:
        # Check if file exists
        if not os.path.exists(file_path):
            return {
                'success': False,
                'message': 'File does not exist'
            }
        
        # Calculate chunk size if not provided
        if not chunk_size:
            chunk_size = manager.chunker.choose_chunk_size_for_file(file_path)
        
        # Use master password for encryption if enabled
        passphrase = None
        if use_encryption and manager.master_password_hash:
            # Derive encryption key from master password
            passphrase = "master_key"  # In production, derive proper key from master password
        
        # Split the file
        success = manager.chunker.split_file(
            input_file=file_path,
            out_dir=output_dir,
            username=manager.current_user['username'],
            chunk_size=chunk_size,
            passphrase=passphrase,
            require_keystroke_auth=False,
            tags=tags
        )
        
        if success:
            # Get file info from database using OS-based ID
            file_info = manager.db.get_file_by_os_id(file_path)
            
            if file_info:
                chunks = manager.db.get_file_chunks(file_info['file_id'])
                return {
                    'success': True,
                    'message': 'File split successfully',
                    'file_id': file_info['file_id'],
                    'chunks': [{
                        'chunk_id': chunk['chunk_id'],
                        'filename': chunk['chunk_filename'],
                        'path': chunk['chunk_path'],
                        'size': chunk['chunk_size'],
                        'index': chunk['chunk_index']
                    } for chunk in chunks],
                    'total_chunks': len(chunks),
                    'output_directory': output_dir
                }
            else:
                return {
                    'success': True,
                    'message': 'File split but database info not found',
                    'file_id': None,
                    'chunks': [],
                    'total_chunks': 0,
                    'output_directory': output_dir
                }
        else:
            return {
                'success': False,
                'message': 'File splitting failed'
            }
            
    except Exception as e:
        return {
            'success': False,
            'message': f'Error splitting file: {str(e)}'
        }

def reconstruct_file(file_id: str, output_path: str, chunk_directory: str = None) -> Dict[str, Any]:
    """Reconstruct file from chunks"""
    manager = get_manager()
    
    if not manager.is_authenticated():
        return {
            'success': False,
            'message': 'User not authenticated'
        }
    
    try:
        # Get file info
        file_info = manager.db.get_file(file_id)
        if not file_info or file_info['user_id'] != manager.current_user['user_id']:
            return {
                'success': False,
                'message': 'File not found or access denied'
            }
        
        # Get chunks
        chunks = manager.db.get_file_chunks(file_id)
        if not chunks:
            return {
                'success': False,
                'message': 'No chunks found for this file'
            }
        
        # Determine chunk directory
        if not chunk_directory:
            chunk_directory = os.path.dirname(chunks[0]['chunk_path'])
        
        # Use master password for decryption if file is encrypted
        passphrase = None
        if file_info['is_encrypted'] and manager.master_password_hash:
            passphrase = "master_key"  # In production, derive proper key from master password
        
        # Reconstruct the file
        success = manager.chunker.join_chunks(
            in_dir=chunk_directory,
            output_file=output_path,
            username=manager.current_user['username'],
            passphrase=passphrase,
            require_keystroke_auth=False
        )
        
        if success:
            # Verify file was created
            if os.path.exists(output_path):
                file_size = os.path.getsize(output_path)
                return {
                    'success': True,
                    'message': 'File reconstructed successfully',
                    'output_path': output_path,
                    'file_size': file_size,
                    'original_filename': file_info['original_filename']
                }
            else:
                return {
                    'success': False,
                    'message': 'File reconstruction completed but output file not found'
                }
        else:
            return {
                'success': False,
                'message': 'File reconstruction failed'
            }
            
    except Exception as e:
        return {
            'success': False,
            'message': f'Error reconstructing file: {str(e)}'
        }

def list_files(limit: int = 100, offset: int = 0) -> Dict[str, Any]:
    """Get list of files for current user"""
    manager = get_manager()
    
    if not manager.is_authenticated():
        return {
            'success': False,
            'message': 'User not authenticated',
            'files': []
        }
    
    try:
        files = manager.db.get_user_files(manager.current_user['user_id'], limit, offset)
        
        # Format file information
        formatted_files = []
        for file in files:
            formatted_files.append({
                'file_id': file['file_id'],
                'filename': file['original_filename'],
                'original_path': file['original_path'],
                'file_size': file['file_size'],
                'file_type': file['file_type'],
                'is_chunked': bool(file['is_chunked']),
                'is_encrypted': bool(file['is_encrypted']),
                'created_at': file['created_at'],
                'modified_at': file['modified_at']
            })
        
        return {
            'success': True,
            'message': 'Files retrieved successfully',
            'files': formatted_files,
            'total_count': len(formatted_files)
        }
        
    except Exception as e:
        return {
            'success': False,
            'message': f'Error retrieving files: {str(e)}',
            'files': []
        }

def get_file_details(file_id: str) -> Dict[str, Any]:
    """Get detailed information about a file"""
    manager = get_manager()
    
    if not manager.is_authenticated():
        return {
            'success': False,
            'message': 'User not authenticated',
            'file_details': None
        }
    
    try:
        file_info = manager.db.get_file(file_id)
        if not file_info or file_info['user_id'] != manager.current_user['user_id']:
            return {
                'success': False,
                'message': 'File not found or access denied',
                'file_details': None
            }
        
        # Get chunks
        chunks = manager.db.get_file_chunks(file_id)
        
        # Get tags
        tags = manager.db.get_file_tags(file_id)
        
        # Get recent access logs
        access_logs = manager.db.get_access_logs(file_id, limit=10)
        
        file_details = {
            'file_id': file_info['file_id'],
            'filename': file_info['original_filename'],
            'original_path': file_info['original_path'],
            'file_size': file_info['file_size'],
            'file_hash': file_info['file_hash'],
            'file_type': file_info['file_type'],
            'is_chunked': bool(file_info['is_chunked']),
            'is_encrypted': bool(file_info['is_encrypted']),
            'encryption_algorithm': file_info['encryption_algorithm'],
            'created_at': file_info['created_at'],
            'modified_at': file_info['modified_at'],
            'chunks': [{
                'chunk_id': chunk['chunk_id'],
                'filename': chunk['chunk_filename'],
                'path': chunk['chunk_path'],
                'size': chunk['chunk_size'],
                'index': chunk['chunk_index'],
                'is_encrypted': bool(chunk['is_encrypted'])
            } for chunk in chunks],
            'tags': [{
                'tag_name': tag['tag_name'],
                'tag_value': tag['tag_value']
            } for tag in tags],
            'recent_access': [{
                'action': log['action'],
                'success': bool(log['success']),
                'timestamp': log['timestamp'],
                'details': log['details']
            } for log in access_logs]
        }
        
        return {
            'success': True,
            'message': 'File details retrieved successfully',
            'file_details': file_details
        }
        
    except Exception as e:
        return {
            'success': False,
            'message': f'Error retrieving file details: {str(e)}',
            'file_details': None
        }

def search_files(query: str = None, file_type: str = None, 
                is_chunked: bool = None, is_encrypted: bool = None) -> Dict[str, Any]:
    """Search files with various filters"""
    manager = get_manager()
    
    if not manager.is_authenticated():
        return {
            'success': False,
            'message': 'User not authenticated',
            'files': []
        }
    
    try:
        files = manager.db.search_files(
            manager.current_user['user_id'], query, file_type, is_chunked, is_encrypted
        )
        
        # Format search results
        formatted_files = []
        for file in files:
            formatted_files.append({
                'file_id': file['file_id'],
                'filename': file['original_filename'],
                'original_path': file['original_path'],
                'file_size': file['file_size'],
                'file_type': file['file_type'],
                'is_chunked': bool(file['is_chunked']),
                'is_encrypted': bool(file['is_encrypted']),
                'created_at': file['created_at']
            })
        
        return {
            'success': True,
            'message': f'Found {len(formatted_files)} files',
            'files': formatted_files,
            'total_count': len(formatted_files)
        }
        
    except Exception as e:
        return {
            'success': False,
            'message': f'Error searching files: {str(e)}',
            'files': []
        }

def add_file_tag(file_id: str, tag_name: str, tag_value: str = None) -> Dict[str, Any]:
    """Add a tag to a file"""
    manager = get_manager()
    
    if not manager.is_authenticated():
        return {
            'success': False,
            'message': 'User not authenticated'
        }
    
    try:
        # Verify file belongs to user
        file_info = manager.db.get_file(file_id)
        if not file_info or file_info['user_id'] != manager.current_user['user_id']:
            return {
                'success': False,
                'message': 'File not found or access denied'
            }
        
        # Add tag
        tag_id = manager.db.add_file_tag(file_id, tag_name, tag_value)
        
        return {
            'success': True,
            'message': 'Tag added successfully',
            'tag_id': tag_id
        }
        
    except Exception as e:
        return {
            'success': False,
            'message': f'Error adding tag: {str(e)}'
        }

def delete_file(file_id: str) -> Dict[str, Any]:
    """Delete a file and all its chunks"""
    manager = get_manager()
    
    if not manager.is_authenticated():
        return {
            'success': False,
            'message': 'User not authenticated'
        }
    
    try:
        # Verify file belongs to user
        file_info = manager.db.get_file(file_id)
        if not file_info or file_info['user_id'] != manager.current_user['user_id']:
            return {
                'success': False,
                'message': 'File not found or access denied'
            }
        
        # Delete file from database (this will also delete chunks and tags)
        success = manager.db.delete_file(file_id)
        
        if success:
            return {
                'success': True,
                'message': 'File deleted successfully'
            }
        else:
            return {
                'success': False,
                'message': 'Failed to delete file'
            }
            
    except Exception as e:
        return {
            'success': False,
            'message': f'Error deleting file: {str(e)}'
        }

def get_database_stats() -> Dict[str, Any]:
    """Get database statistics"""
    manager = get_manager()
    
    if not manager.is_authenticated():
        return {
            'success': False,
            'message': 'User not authenticated',
            'stats': None
        }
    
    try:
        stats = manager.db.get_database_stats()
        return {
            'success': True,
            'message': 'Statistics retrieved successfully',
            'stats': stats
        }
    except Exception as e:
        return {
            'success': False,
            'message': f'Error retrieving statistics: {str(e)}',
            'stats': None
        }

# Convenience function for quick setup
def quick_setup(master_password: str, db_path: str = "intellivault.db") -> bool:
    """Quick setup with master password"""
    try:
        manager = initialize_intellivault(db_path)
        manager.set_master_password(master_password)
        auth_result = manager.authenticate(master_password)
        return auth_result['success']
    except Exception as e:
        print(f"Quick setup failed: {e}")
        return False

def main():
    """Example usage of IntelliVault functions"""
    print("IntelliVault Functions Example")
    print("=" * 40)
    
    # Quick setup
    print("\n1. Setting up IntelliVault...")
    if quick_setup("test123"):
        print("   ✓ Setup successful")
        
        # Add file metadata
        print("\n2. Adding file metadata...")
        if os.path.exists("Test Files/vov.pdf"):
            add_result = add_file_metadata(
                "Test Files/vov.pdf",
                {"tags": ["test", "demo"], "category": "document"}
            )
            print(f"   Add file: {add_result['message']}")
            
            if add_result['success']:
                file_id = add_result['file_id']
                
                # Split file
                print("\n3. Splitting file...")
                split_result = split_file(
                    "Test Files/vov.pdf",
                    "Functions_Test_Chunks",
                    tags=["functions_test"]
                )
                print(f"   Split: {split_result['message']}")
                
                if split_result['success']:
                    print(f"   Created {split_result['total_chunks']} chunks")
                    
                    # Reconstruct file
                    print("\n4. Reconstructing file...")
                    reconstruct_result = reconstruct_file(
                        file_id,
                        "Functions_Test_Output/reconstructed.pdf",
                        "Functions_Test_Chunks"
                    )
                    print(f"   Reconstruct: {reconstruct_result['message']}")
                    
                    if reconstruct_result['success']:
                        print(f"   Output: {reconstruct_result['output_path']}")
                        print(f"   Size: {reconstruct_result['file_size']} bytes")
        
        # List files
        print("\n5. Listing files...")
        files_result = list_files()
        print(f"   List files: {files_result['message']}")
        print(f"   Found {files_result['total_count']} files")
        
        # Get stats
        print("\n6. Getting statistics...")
        stats_result = get_database_stats()
        if stats_result['success']:
            stats = stats_result['stats']
            print(f"   Total files: {stats['total_files']}")
            print(f"   Total storage: {stats['total_storage_mb']} MB")
        
        # Logout
        print("\n7. Logging out...")
        logout_result = logout_user()
        print(f"   Logout: {logout_result['message']}")
    else:
        print("   ✗ Setup failed")
    
    print("\n" + "=" * 40)
    print("Functions example completed!")

if __name__ == "__main__":
    main()
