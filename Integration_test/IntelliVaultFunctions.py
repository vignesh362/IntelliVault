#!/usr/bin/env python3
"""
IntelliVault API - Streamlined Functions for Frontend Integration
Simplified interface for easy frontend connectivity with consistent error handling

STREAMLINED API USAGE:
=====================

1. Initialize the API:
   from IntelliVaultFunctions import initialize_intellivault, login, logout, add_file, split_file, etc.
   api = initialize_intellivault("your_database.db")

2. Authentication:
   result = login("your_master_password")
   if result['success']:
       print("Logged in successfully")
   else:
       print(f"Login failed: {result['message']}")

3. File Operations:
   # Add file to vault
   result = add_file("/path/to/file.pdf", tags=["important", "work"])
   
   # Split file into encrypted chunks
   result = split_file("/path/to/file.pdf", "output_chunks", encrypt=True)
   
   # Reconstruct file from chunks
   result = reconstruct_file("file_id", "/path/to/output.pdf")
   
   # List all files
   result = list_files()
   
   # Search files
   result = search_files(query="important", file_type="pdf")
   
   # Get file details
   result = get_file_info("file_id")
   
   # Delete file
   result = delete_file("file_id")

4. All functions return standardized responses:
   {
       'success': bool,
       'message': str,
       'data': dict,  # Contains actual data if success=True
       'error': str,  # Error code if success=False
       'timestamp': str
   }

5. Logout when done:
   result = logout()

EXAMPLE FRONTEND INTEGRATION:
============================

# Simple web API wrapper
from flask import Flask, request, jsonify
from IntelliVaultFunctions import *

app = Flask(__name__)

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    result = login(data['password'])
    return jsonify(result)

@app.route('/api/files', methods=['GET'])
def api_list_files():
    result = list_files()
    return jsonify(result)

@app.route('/api/files', methods=['POST'])
def api_add_file():
    data = request.json
    result = add_file(data['file_path'], data.get('tags', []))
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)

KEY FEATURES:
=============
- Consistent response format for all functions
- Built-in authentication validation
- Input validation and error handling
- Easy to integrate with any frontend framework
- Backward compatibility with legacy functions
- Comprehensive error codes for frontend handling
"""

import hashlib
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import uuid
from datetime import datetime
import json

# Add Security directory to path
sys.path.append(str(Path(__file__).parent))

from Database import IntelliVaultDB
from DatabaseChunker import DatabaseChunker
from KeystrokeAuth import KeystrokeAuthenticator

class IntelliVaultAPI:
    """
    Streamlined API for frontend integration
    Provides simple, consistent interface with proper error handling
    """
    
    def __init__(self, db_path: str = "intellivault.db"):
        self.db = IntelliVaultDB(db_path)
        self.keystroke_auth = KeystrokeAuthenticator()
        self.chunker = DatabaseChunker(db_path, self.keystroke_auth)
        self.master_password_hash = None
        self.current_user = None
        self.authenticated = False
    
    def _validate_auth(self) -> Dict[str, Any]:
        """Validate authentication status"""
        if not self.authenticated:
            return {
                'success': False,
                'error': 'AUTHENTICATION_REQUIRED',
                'message': 'User must be authenticated to perform this action'
            }
        return {'success': True}
    
    def _validate_input(self, **kwargs) -> Dict[str, Any]:
        """Validate input parameters"""
        for key, value in kwargs.items():
            if value is None:
                return {
                    'success': False,
                    'error': 'INVALID_INPUT',
                    'message': f'Parameter {key} is required'
                }
        return {'success': True}
    
    def _create_response(self, success: bool, message: str, data: Any = None, error: str = None) -> Dict[str, Any]:
        """Create standardized response format"""
        response = {
            'success': success,
            'message': message,
            'timestamp': datetime.now().isoformat()
        }
        
        if data is not None:
            response['data'] = data
        
        if error:
            response['error'] = error
            
        return response
    
    # Authentication Methods
    def login(self, password: str) -> Dict[str, Any]:
        """Login with master password"""
        validation = self._validate_input(password=password)
        if not validation['success']:
            return self._create_response(False, validation['message'], error=validation['error'])
        
        try:
            # Set master password
            self.master_password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            # Create or get master user
            master_user = self.db.get_user("master_user")
            if not master_user:
                user_id = self.db.create_user("master_user")
                master_user = self.db.get_user("master_user")
            
            self.current_user = master_user
            self.authenticated = True
            
            return self._create_response(
                True, 
                "Login successful", 
                {'user_id': master_user['user_id'], 'username': master_user['username']}
            )
        except Exception as e:
            return self._create_response(False, f"Login failed: {str(e)}", error="LOGIN_ERROR")
    
    def logout(self) -> Dict[str, Any]:
        """Logout current user"""
        self.current_user = None
        self.authenticated = False
        self.master_password_hash = None
        return self._create_response(True, "Logout successful")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current authentication status"""
        return self._create_response(
            True, 
            "Status retrieved", 
            {
                'authenticated': self.authenticated,
                'user': self.current_user['username'] if self.current_user else None
            }
        )
    
    # File Management Methods
    def add_file(self, file_path: str, tags: List[str] = None, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """Add file to vault"""
        auth_check = self._validate_auth()
        if not auth_check['success']:
            return self._create_response(False, auth_check['message'], error=auth_check['error'])
        
        validation = self._validate_input(file_path=file_path)
        if not validation['success']:
            return self._create_response(False, validation['message'], error=validation['error'])
        
        try:
            if not os.path.exists(file_path):
                return self._create_response(False, "File does not exist", error="FILE_NOT_FOUND")
            
            # Check if file already exists
            existing_file = self.db.get_file_by_os_id(file_path)
            if existing_file:
                return self._create_response(
                    True, 
                    "File already exists in vault", 
                    {'file_id': existing_file['file_id'], 'is_duplicate': True}
                )
            
            # Prepare metadata
            file_metadata = metadata or {}
            file_metadata.update({
                'is_chunked': False,
                'is_encrypted': False,
                'keystroke_auth_required': False
            })
            
            # Register file
            file_id = self.db.register_file(self.current_user['user_id'], file_path, file_metadata, True)
            
            # Add tags if provided
            if tags:
                for tag in tags:
                    self.db.add_file_tag(file_id, tag)
            
            return self._create_response(
                True, 
                "File added successfully", 
                {'file_id': file_id, 'is_duplicate': False}
            )
        except Exception as e:
            return self._create_response(False, f"Failed to add file: {str(e)}", error="ADD_FILE_ERROR")
    
    def split_file(self, file_path: str, output_dir: str = "chunks", chunk_size: int = None, 
                   tags: List[str] = None, encrypt: bool = True) -> Dict[str, Any]:
        """Split file into encrypted chunks"""
        auth_check = self._validate_auth()
        if not auth_check['success']:
            return self._create_response(False, auth_check['message'], error=auth_check['error'])
        
        validation = self._validate_input(file_path=file_path)
        if not validation['success']:
            return self._create_response(False, validation['message'], error=validation['error'])
        
        try:
            if not os.path.exists(file_path):
                return self._create_response(False, "File does not exist", error="FILE_NOT_FOUND")
            
            # Calculate chunk size if not provided
            if not chunk_size:
                chunk_size = self.chunker.choose_chunk_size_for_file(file_path)
            
            # Use master password for encryption
            passphrase = None
            if encrypt and self.master_password_hash:
                passphrase = "master_key"  # In production, derive proper key from master password
            
            # Split the file
            success = self.chunker.split_file(
                input_file=file_path,
                out_dir=output_dir,
                username=self.current_user['username'],
                chunk_size=chunk_size,
                passphrase=passphrase,
                require_keystroke_auth=False,
                tags=tags
            )
            
            if success:
                # Get file info
                file_info = self.db.get_file_by_os_id(file_path)
                if file_info:
                    chunks = self.db.get_file_chunks(file_info['file_id'])
                    return self._create_response(
                        True, 
                        "File split successfully", 
                        {
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
                    )
            
            return self._create_response(False, "File splitting failed", error="SPLIT_ERROR")
        except Exception as e:
            return self._create_response(False, f"Failed to split file: {str(e)}", error="SPLIT_ERROR")
    
    def reconstruct_file(self, file_id: str, output_path: str, chunk_directory: str = None) -> Dict[str, Any]:
        """Reconstruct file from chunks"""
        auth_check = self._validate_auth()
        if not auth_check['success']:
            return self._create_response(False, auth_check['message'], error=auth_check['error'])
        
        validation = self._validate_input(file_id=file_id, output_path=output_path)
        if not validation['success']:
            return self._create_response(False, validation['message'], error=validation['error'])
        
        try:
            # Get file info
            file_info = self.db.get_file(file_id)
            if not file_info or file_info['user_id'] != self.current_user['user_id']:
                return self._create_response(False, "File not found or access denied", error="ACCESS_DENIED")
            
            # Get chunks
            chunks = self.db.get_file_chunks(file_id)
            if not chunks:
                return self._create_response(False, "No chunks found for this file", error="NO_CHUNKS")
            
            # Determine chunk directory
            if not chunk_directory:
                chunk_directory = os.path.dirname(chunks[0]['chunk_path'])
            
            # Use master password for decryption if file is encrypted
            passphrase = None
            if file_info['is_encrypted'] and self.master_password_hash:
                passphrase = "master_key"  # In production, derive proper key from master password
            
            # Reconstruct the file
            success = self.chunker.join_chunks(
                in_dir=chunk_directory,
                output_file=output_path,
                username=self.current_user['username'],
                passphrase=passphrase,
                require_keystroke_auth=False
            )
            
            if success and os.path.exists(output_path):
                file_size = os.path.getsize(output_path)
                return self._create_response(
                    True, 
                    "File reconstructed successfully", 
                    {
                        'output_path': output_path,
                        'file_size': file_size,
                        'original_filename': file_info['original_filename']
                    }
                )
            
            return self._create_response(False, "File reconstruction failed", error="RECONSTRUCT_ERROR")
        except Exception as e:
            return self._create_response(False, f"Failed to reconstruct file: {str(e)}", error="RECONSTRUCT_ERROR")
    
    def list_files(self, limit: int = 100, offset: int = 0) -> Dict[str, Any]:
        """Get list of files in vault"""
        auth_check = self._validate_auth()
        if not auth_check['success']:
            return self._create_response(False, auth_check['message'], error=auth_check['error'])
        
        try:
            files = self.db.get_user_files(self.current_user['user_id'], limit, offset)
            
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
            
            return self._create_response(
                True, 
                f"Retrieved {len(formatted_files)} files", 
                {'files': formatted_files, 'total_count': len(formatted_files)}
            )
        except Exception as e:
            return self._create_response(False, f"Failed to list files: {str(e)}", error="LIST_ERROR")
    
    def get_file_info(self, file_id: str) -> Dict[str, Any]:
        """Get detailed information about a file"""
        auth_check = self._validate_auth()
        if not auth_check['success']:
            return self._create_response(False, auth_check['message'], error=auth_check['error'])
        
        validation = self._validate_input(file_id=file_id)
        if not validation['success']:
            return self._create_response(False, validation['message'], error=validation['error'])
        
        try:
            file_info = self.db.get_file(file_id)
            if not file_info or file_info['user_id'] != self.current_user['user_id']:
                return self._create_response(False, "File not found or access denied", error="ACCESS_DENIED")
            
            # Get chunks and tags
            chunks = self.db.get_file_chunks(file_id)
            tags = self.db.get_file_tags(file_id)
            access_logs = self.db.get_access_logs(file_id, limit=10)
            
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
                'tags': [{'tag_name': tag['tag_name'], 'tag_value': tag['tag_value']} for tag in tags],
                'recent_access': [{
                    'action': log['action'],
                    'success': bool(log['success']),
                    'timestamp': log['timestamp'],
                    'details': log['details']
                } for log in access_logs]
            }
            
            return self._create_response(True, "File information retrieved", {'file': file_details})
        except Exception as e:
            return self._create_response(False, f"Failed to get file info: {str(e)}", error="GET_INFO_ERROR")
    
    def search_files(self, query: str = None, file_type: str = None, 
                    is_chunked: bool = None, is_encrypted: bool = None) -> Dict[str, Any]:
        """Search files with filters"""
        auth_check = self._validate_auth()
        if not auth_check['success']:
            return self._create_response(False, auth_check['message'], error=auth_check['error'])
        
        try:
            files = self.db.search_files(
                self.current_user['user_id'], query, file_type, is_chunked, is_encrypted
            )
            
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
            
            return self._create_response(
                True, 
                f"Found {len(formatted_files)} files", 
                {'files': formatted_files, 'total_count': len(formatted_files)}
            )
        except Exception as e:
            return self._create_response(False, f"Search failed: {str(e)}", error="SEARCH_ERROR")
    
    def delete_file(self, file_id: str) -> Dict[str, Any]:
        """Delete a file and all its chunks"""
        auth_check = self._validate_auth()
        if not auth_check['success']:
            return self._create_response(False, auth_check['message'], error=auth_check['error'])
        
        validation = self._validate_input(file_id=file_id)
        if not validation['success']:
            return self._create_response(False, validation['message'], error=validation['error'])
        
        try:
            # Verify file belongs to user
            file_info = self.db.get_file(file_id)
            if not file_info or file_info['user_id'] != self.current_user['user_id']:
                return self._create_response(False, "File not found or access denied", error="ACCESS_DENIED")
            
            # Delete file from database
            success = self.db.delete_file(file_id)
            
            if success:
                return self._create_response(True, "File deleted successfully")
            else:
                return self._create_response(False, "Failed to delete file", error="DELETE_ERROR")
        except Exception as e:
            return self._create_response(False, f"Failed to delete file: {str(e)}", error="DELETE_ERROR")
    
    def add_tag(self, file_id: str, tag_name: str, tag_value: str = None) -> Dict[str, Any]:
        """Add a tag to a file"""
        auth_check = self._validate_auth()
        if not auth_check['success']:
            return self._create_response(False, auth_check['message'], error=auth_check['error'])
        
        validation = self._validate_input(file_id=file_id, tag_name=tag_name)
        if not validation['success']:
            return self._create_response(False, validation['message'], error=validation['error'])
        
        try:
            # Verify file belongs to user
            file_info = self.db.get_file(file_id)
            if not file_info or file_info['user_id'] != self.current_user['user_id']:
                return self._create_response(False, "File not found or access denied", error="ACCESS_DENIED")
            
            # Add tag
            tag_id = self.db.add_file_tag(file_id, tag_name, tag_value)
            
            return self._create_response(True, "Tag added successfully", {'tag_id': tag_id})
        except Exception as e:
            return self._create_response(False, f"Failed to add tag: {str(e)}", error="TAG_ERROR")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get vault statistics"""
        auth_check = self._validate_auth()
        if not auth_check['success']:
            return self._create_response(False, auth_check['message'], error=auth_check['error'])
        
        try:
            stats = self.db.get_database_stats()
            return self._create_response(True, "Statistics retrieved", {'stats': stats})
        except Exception as e:
            return self._create_response(False, f"Failed to get stats: {str(e)}", error="STATS_ERROR")

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

# Global instances
_api = None
_manager = None

def initialize_intellivault(db_path: str = "intellivault.db") -> IntelliVaultAPI:
    """Initialize IntelliVault API"""
    global _api
    _api = IntelliVaultAPI(db_path)
    return _api

def get_api() -> IntelliVaultAPI:
    """Get the global API instance"""
    global _api
    if _api is None:
        _api = IntelliVaultAPI()
    return _api

# Legacy support
def get_manager() -> IntelliVaultManager:
    """Get the global manager instance (legacy support)"""
    global _manager
    if _manager is None:
        _manager = IntelliVaultManager()
    return _manager

# Streamlined API Functions - Easy Frontend Integration
def login(password: str) -> Dict[str, Any]:
    """Login with master password - Returns standardized response"""
    api = get_api()
    return api.login(password)

def logout() -> Dict[str, Any]:
    """Logout current user - Returns standardized response"""
    api = get_api()
    return api.logout()

def get_status() -> Dict[str, Any]:
    """Get current authentication status - Returns standardized response"""
    api = get_api()
    return api.get_status()

# File Management Functions
def add_file(file_path: str, tags: List[str] = None, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
    """Add file to vault - Returns standardized response"""
    api = get_api()
    return api.add_file(file_path, tags, metadata)

def split_file(file_path: str, output_dir: str = "chunks", chunk_size: int = None, 
               tags: List[str] = None, encrypt: bool = True) -> Dict[str, Any]:
    """Split file into encrypted chunks - Returns standardized response"""
    api = get_api()
    return api.split_file(file_path, output_dir, chunk_size, tags, encrypt)

def reconstruct_file(file_id: str, output_path: str, chunk_directory: str = None) -> Dict[str, Any]:
    """Reconstruct file from chunks - Returns standardized response"""
    api = get_api()
    return api.reconstruct_file(file_id, output_path, chunk_directory)

def list_files(limit: int = 100, offset: int = 0) -> Dict[str, Any]:
    """Get list of files in vault - Returns standardized response"""
    api = get_api()
    return api.list_files(limit, offset)

def get_file_info(file_id: str) -> Dict[str, Any]:
    """Get detailed file information - Returns standardized response"""
    api = get_api()
    return api.get_file_info(file_id)

def search_files(query: str = None, file_type: str = None, 
                is_chunked: bool = None, is_encrypted: bool = None) -> Dict[str, Any]:
    """Search files with filters - Returns standardized response"""
    api = get_api()
    return api.search_files(query, file_type, is_chunked, is_encrypted)

def delete_file(file_id: str) -> Dict[str, Any]:
    """Delete file and all chunks - Returns standardized response"""
    api = get_api()
    return api.delete_file(file_id)

def add_tag(file_id: str, tag_name: str, tag_value: str = None) -> Dict[str, Any]:
    """Add tag to file - Returns standardized response"""
    api = get_api()
    return api.add_tag(file_id, tag_name, tag_value)

def get_stats() -> Dict[str, Any]:
    """Get vault statistics - Returns standardized response"""
    api = get_api()
    return api.get_stats()

# Legacy Functions (for backward compatibility)
def set_master_password(password: str) -> bool:
    """Set master password for the session (legacy)"""
    manager = get_manager()
    return manager.set_master_password(password)

def authenticate_user(password: str) -> Dict[str, Any]:
    """Authenticate user with master password (legacy)"""
    manager = get_manager()
    return manager.authenticate(password)

def logout_user() -> Dict[str, Any]:
    """Logout current user (legacy)"""
    manager = get_manager()
    return manager.logout()

def is_user_authenticated() -> bool:
    """Check if user is authenticated (legacy)"""
    manager = get_manager()
    return manager.is_authenticated()

# Legacy File Management Functions (for backward compatibility)
def add_file_metadata(file_path: str, metadata: Dict[str, Any] = None, use_os_id: bool = True) -> Dict[str, Any]:
    """Add file to database with metadata (legacy)"""
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

# Legacy split_file function (for backward compatibility)
def split_file_legacy(file_path: str, output_dir: str = "chunks", chunk_size: int = None, 
               tags: List[str] = None, use_encryption: bool = True) -> Dict[str, Any]:
    """Split file into chunks with optional encryption (legacy)"""
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

# Legacy reconstruct_file function (for backward compatibility)
def reconstruct_file_legacy(file_id: str, output_path: str, chunk_directory: str = None) -> Dict[str, Any]:
    """Reconstruct file from chunks (legacy)"""
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

# Legacy list_files function (for backward compatibility)
def list_files_legacy(limit: int = 100, offset: int = 0) -> Dict[str, Any]:
    """Get list of files for current user (legacy)"""
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

# Legacy get_file_details function (for backward compatibility)
def get_file_details_legacy(file_id: str) -> Dict[str, Any]:
    """Get detailed information about a file (legacy)"""
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

# Legacy search_files function (for backward compatibility)
def search_files_legacy(query: str = None, file_type: str = None, 
                is_chunked: bool = None, is_encrypted: bool = None) -> Dict[str, Any]:
    """Search files with various filters (legacy)"""
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

# Legacy add_file_tag function (for backward compatibility)
def add_file_tag_legacy(file_id: str, tag_name: str, tag_value: str = None) -> Dict[str, Any]:
    """Add a tag to a file (legacy)"""
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

# Legacy delete_file function (for backward compatibility)
def delete_file_legacy(file_id: str) -> Dict[str, Any]:
    """Delete a file and all its chunks (legacy)"""
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

# Legacy get_database_stats function (for backward compatibility)
def get_database_stats_legacy() -> Dict[str, Any]:
    """Get database statistics (legacy)"""
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
        api = initialize_intellivault(db_path)
        login_result = api.login(master_password)
        return login_result['success']
    except Exception as e:
        print(f"Quick setup failed: {e}")
        return False

def demo_streamlined_api():
    """Demonstrate the streamlined API for frontend integration"""
    print("IntelliVault Streamlined API Demo")
    print("=" * 50)
    
    # Initialize API
    print("\n1. Initializing API...")
    api = initialize_intellivault("demo_intellivault.db")
    print("   ✓ API initialized")
    
    # Login
    print("\n2. Logging in...")
    login_result = login("demo123")
    print(f"   Login: {login_result['message']}")
    if not login_result['success']:
        print("   ✗ Login failed")
        return
    
    # Check status
    print("\n3. Checking status...")
    status_result = get_status()
    print(f"   Status: {status_result['data']}")
    
    # Add file if it exists
    print("\n4. Adding file...")
    if os.path.exists("Test Files/vov.pdf"):
        add_result = add_file("Test Files/vov.pdf", tags=["demo", "test"])
        print(f"   Add file: {add_result['message']}")
        
        if add_result['success'] and not add_result['data']['is_duplicate']:
            file_id = add_result['data']['file_id']
            
            # Split file
            print("\n5. Splitting file...")
            split_result = split_file("Test Files/vov.pdf", "Demo_Chunks", tags=["demo_split"])
            print(f"   Split: {split_result['message']}")
            
            if split_result['success']:
                print(f"   Created {split_result['data']['total_chunks']} chunks")
                
                # Reconstruct file
                print("\n6. Reconstructing file...")
                reconstruct_result = reconstruct_file(
                    file_id,
                    "Demo_Output/reconstructed.pdf",
                    "Demo_Chunks"
                )
                print(f"   Reconstruct: {reconstruct_result['message']}")
                
                if reconstruct_result['success']:
                    print(f"   Output: {reconstruct_result['data']['output_path']}")
                    print(f"   Size: {reconstruct_result['data']['file_size']} bytes")
    
    # List files
    print("\n7. Listing files...")
    files_result = list_files()
    print(f"   List files: {files_result['message']}")
    if files_result['success']:
        print(f"   Found {files_result['data']['total_count']} files")
        for file in files_result['data']['files'][:3]:  # Show first 3 files
            print(f"     - {file['filename']} ({file['file_size']} bytes)")
    
    # Search files
    print("\n8. Searching files...")
    search_result = search_files(query="demo")
    print(f"   Search: {search_result['message']}")
    if search_result['success']:
        print(f"   Found {search_result['data']['total_count']} matching files")
    
    # Get stats
    print("\n9. Getting statistics...")
    stats_result = get_stats()
    print(f"   Stats: {stats_result['message']}")
    if stats_result['success']:
        stats = stats_result['data']['stats']
        print(f"   Total files: {stats['total_files']}")
        print(f"   Total storage: {stats['total_storage_mb']} MB")
    
    # Logout
    print("\n10. Logging out...")
    logout_result = logout()
    print(f"   Logout: {logout_result['message']}")
    
    print("\n" + "=" * 50)
    print("Streamlined API demo completed!")

def main():
    """Main function - demonstrates both legacy and streamlined APIs"""
    print("IntelliVault API Examples")
    print("=" * 50)
    
    # Run streamlined API demo
    demo_streamlined_api()
    
    print("\n" + "=" * 50)
    print("All examples completed!")

if __name__ == "__main__":
    main()
