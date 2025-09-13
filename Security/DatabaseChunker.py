#!/usr/bin/env python3
"""
Database-Integrated Secure Chunker
Combines file chunking, encryption, keystroke auth, and database tracking
"""

import argparse
import json
import pathlib
import sys
import hashlib
import os
import math
import getpass
from typing import Optional, Tuple, Dict, List
from Crypter import derive_key, MAGIC, KEY_SIZE, NONCE_SIZE, SALT_SIZE
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
from KeystrokeAuth import KeystrokeAuthenticator
from Database import IntelliVaultDB
from SecureChunker import SecureChunker

DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024  # 4 MiB

class DatabaseChunker:
    """Enhanced chunker with full database integration"""
    
    def __init__(self, db_path: str = "intellivault.db", keystroke_auth: Optional[KeystrokeAuthenticator] = None):
        self.db = IntelliVaultDB(db_path)
        self.keystroke_auth = keystroke_auth or KeystrokeAuthenticator()
        self.secure_chunker = SecureChunker(self.keystroke_auth)
        
    def register_user(self, username: str) -> bool:
        """Register a new user with keystroke dynamics and database"""
        print(f"Registering user: {username}")
        
        # Register with keystroke auth
        if not self.keystroke_auth.register_user(username):
            return False
            
        # Get keystroke model path
        keystroke_model_path = f"keystroke_data/{username}_model.joblib"
        
        # Create user in database
        try:
            user_id = self.db.create_user(username, keystroke_model_path)
            print(f"✓ User {username} registered successfully! (ID: {user_id})")
            return True
        except Exception as e:
            print(f"✗ Database registration failed: {e}")
            return False
    
    def split_file(self, input_file: str, out_dir: str, username: str, 
                   chunk_size: int = DEFAULT_CHUNK_SIZE, passphrase: str = None, 
                   require_keystroke_auth: bool = False, tags: List[str] = None) -> bool:
        """
        Split file with full database tracking
        """
        # Get user from database
        user = self.db.get_user(username)
        if not user:
            print(f"Error: User {username} not found. Please register first.")
            return False
            
        user_id = user['user_id']
        
        # Check if file already exists using OS-based ID
        existing_file = self.db.get_file_by_os_id(input_file)
        if existing_file:
            print(f"File already exists in database (ID: {existing_file['file_id']})")
            response = input("Do you want to create a new entry? (y/N): ")
            if response.lower() != 'y':
                return False
        
        # Register file in database
        file_metadata = {
            'is_chunked': True,
            'is_encrypted': passphrase is not None,
            'encryption_algorithm': 'AES-256-GCM' if passphrase else None,
            'keystroke_auth_required': require_keystroke_auth
        }
        
        file_id = self.db.register_file(user_id, input_file, file_metadata)
        print(f"File registered in database (ID: {file_id})")
        
        # Log access attempt
        self.db.log_access(file_id, user_id, "file_split_attempt", True, 
                          details=f"Starting file split: {input_file}")
        
        try:
            # Perform the actual file splitting
            success = self.secure_chunker.split_file(
                input_file, out_dir, chunk_size, passphrase, 
                username, require_keystroke_auth
            )
            
            if success:
                # Get chunk information from output directory
                chunks_info = self._get_chunk_info(out_dir, file_id)
                
                # Add chunks to database
                chunk_ids = self.db.add_chunks(file_id, chunks_info)
                print(f"✓ Added {len(chunk_ids)} chunks to database")
                
                # Add tags if provided
                if tags:
                    for tag in tags:
                        self.db.add_file_tag(file_id, tag)
                    print(f"✓ Added {len(tags)} tags to file")
                
                # Log successful split
                self.db.log_access(file_id, user_id, "file_split_success", True,
                                  details=f"File split into {len(chunks_info)} chunks")
                
                print(f"✓ File successfully split and tracked in database!")
                return True
            else:
                # Log failed split
                self.db.log_access(file_id, user_id, "file_split_failed", False,
                                  details="File splitting operation failed")
                return False
                
        except Exception as e:
            # Log error
            self.db.log_access(file_id, user_id, "file_split_error", False,
                              details=f"Error: {str(e)}")
            print(f"✗ Error during file splitting: {e}")
            return False
    
    def join_chunks(self, in_dir: str, output_file: str, username: str,
                   passphrase: str = None, require_keystroke_auth: bool = False) -> bool:
        """
        Join chunks with database tracking
        """
        # Get user from database
        user = self.db.get_user(username)
        if not user:
            print(f"Error: User {username} not found.")
            return False
            
        user_id = user['user_id']
        
        # Find file by output directory (assuming it matches chunk directory)
        # This is a simplified approach - in practice, you might want to store chunk directory in DB
        manifest_path = pathlib.Path(in_dir) / "manifest.json"
        if not manifest_path.exists():
            print(f"Error: No manifest found in {in_dir}")
            return False
            
        # Read manifest to get file info
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
        
        # Try to find file in database by original filename
        files = self.db.search_files(user_id, query=manifest.get('original_filename', ''))
        if not files:
            print(f"Error: File not found in database for user {username}")
            return False
            
        file_id = files[0]['file_id']  # Take first match
        
        # Log access attempt
        self.db.log_access(file_id, user_id, "file_join_attempt", True,
                          details=f"Starting file reconstruction: {output_file}")
        
        try:
            # Perform the actual file joining
            success = self.secure_chunker.join_chunks(
                in_dir, output_file, passphrase, username, require_keystroke_auth
            )
            
            if success:
                # Log successful join
                self.db.log_access(file_id, user_id, "file_join_success", True,
                                  details=f"File successfully reconstructed: {output_file}")
                print(f"✓ File successfully reconstructed and logged!")
                return True
            else:
                # Log failed join
                self.db.log_access(file_id, user_id, "file_join_failed", False,
                                  details="File reconstruction failed")
                return False
                
        except Exception as e:
            # Log error
            self.db.log_access(file_id, user_id, "file_join_error", False,
                              details=f"Error: {str(e)}")
            print(f"✗ Error during file reconstruction: {e}")
            return False
    
    def _get_chunk_info(self, chunk_dir: str, file_id: str) -> List[Dict]:
        """Extract chunk information from directory"""
        chunk_dir_path = pathlib.Path(chunk_dir)
        chunks_info = []
        
        # Read manifest for chunk information
        manifest_path = chunk_dir_path / "manifest.json"
        if manifest_path.exists():
            with open(manifest_path, 'r') as f:
                manifest = json.load(f)
            
            for i, chunk_data in enumerate(manifest.get('chunks', [])):
                chunk_path = chunk_dir_path / chunk_data['name']
                chunk_info = {
                    'index': i,
                    'filename': chunk_data['name'],
                    'path': str(chunk_path),
                    'size': chunk_data['size'],
                    'hash': None,  # Could calculate if needed
                    'is_encrypted': manifest.get('encrypted', False),
                    'nonce': None  # Could extract from encrypted chunk if needed
                }
                chunks_info.append(chunk_info)
        
        return chunks_info
    
    def list_user_files(self, username: str, limit: int = 50) -> List[Dict]:
        """List all files for a user"""
        user = self.db.get_user(username)
        if not user:
            print(f"Error: User {username} not found.")
            return []
            
        files = self.db.get_user_files(user['user_id'], limit)
        return files
    
    def search_files(self, username: str, query: str = None, file_type: str = None,
                    is_chunked: bool = None, is_encrypted: bool = None) -> List[Dict]:
        """Search files with filters"""
        user = self.db.get_user(username)
        if not user:
            print(f"Error: User {username} not found.")
            return []
            
        files = self.db.search_files(
            user['user_id'], query, file_type, is_chunked, is_encrypted
        )
        return files
    
    def get_file_details(self, username: str, file_id: str) -> Dict:
        """Get detailed file information including chunks"""
        user = self.db.get_user(username)
        if not user:
            return {}
            
        file_info = self.db.get_file(file_id)
        if not file_info or file_info['user_id'] != user['user_id']:
            return {}
            
        # Get chunks
        chunks = self.db.get_file_chunks(file_id)
        file_info['chunks'] = chunks
        
        # Get tags
        tags = self.db.get_file_tags(file_id)
        file_info['tags'] = tags
        
        # Get recent access logs
        access_logs = self.db.get_access_logs(file_id, limit=10)
        file_info['recent_access'] = access_logs
        
        return file_info
    
    def add_file_tag(self, username: str, file_id: str, tag_name: str, tag_value: str = None) -> bool:
        """Add a tag to a file"""
        user = self.db.get_user(username)
        if not user:
            return False
            
        file_info = self.db.get_file(file_id)
        if not file_info or file_info['user_id'] != user['user_id']:
            return False
            
        try:
            self.db.add_file_tag(file_id, tag_name, tag_value)
            return True
        except:
            return False
    
    def get_database_stats(self) -> Dict:
        """Get database statistics"""
        return self.db.get_database_stats()
    
    def choose_chunk_size_for_file(self, path: str, target_chunks: int = 300) -> int:
        """Calculate optimal chunk size for a file"""
        return self.secure_chunker.choose_chunk_size_for_file(path, target_chunks)

def main():
    """Main function with enhanced command-line interface"""
    parser = argparse.ArgumentParser(description="Database-integrated secure file chunker")
    parser.add_argument("--input", "-i", help="Input file to split")
    parser.add_argument("--output-dir", "-o", default="Test Chunks", help="Output directory for chunks")
    parser.add_argument("--reconstruct", "-r", help="Reconstruct file from chunks")
    parser.add_argument("--username", "-u", required=True, help="Username")
    parser.add_argument("--passphrase", "-p", help="Passphrase for encryption/decryption")
    parser.add_argument("--keystroke-auth", "-k", action="store_true", help="Require keystroke authentication")
    parser.add_argument("--register-user", action="store_true", help="Register new user")
    parser.add_argument("--list-files", action="store_true", help="List user files")
    parser.add_argument("--file-details", help="Get detailed file information (file_id)")
    parser.add_argument("--search", help="Search files")
    parser.add_argument("--add-tag", nargs=2, metavar=("FILE_ID", "TAG"), help="Add tag to file")
    parser.add_argument("--stats", action="store_true", help="Show database statistics")
    parser.add_argument("--chunk-size", "-c", type=int, help="Chunk size in bytes")
    parser.add_argument("--target-chunks", "-t", type=int, default=300, help="Target number of chunks")
    parser.add_argument("--tags", nargs="*", help="Tags to add to file")
    
    args = parser.parse_args()
    
    # Initialize database chunker
    chunker = DatabaseChunker()
    
    try:
        if args.register_user:
            # Register new user
            success = chunker.register_user(args.username)
            if success:
                print(f"✓ User {args.username} registered successfully!")
            else:
                print(f"✗ Failed to register user {args.username}")
            return
                
        if args.list_files:
            # List user files
            files = chunker.list_user_files(args.username)
            if files:
                print(f"\nFiles for {args.username}:")
                for file in files:
                    print(f"  ID: {file['file_id']}")
                    print(f"  Name: {file['original_filename']}")
                    print(f"  Size: {file['file_size']} bytes")
                    print(f"  Chunked: {file['is_chunked']}")
                    print(f"  Encrypted: {file['is_encrypted']}")
                    print(f"  Created: {file['created_at']}")
                    print("  ---")
            else:
                print(f"No files found for {args.username}")
            return
                
        if args.file_details:
            # Get file details
            details = chunker.get_file_details(args.username, args.file_details)
            if details:
                print(f"\nFile Details:")
                print(f"  ID: {details['file_id']}")
                print(f"  Name: {details['original_filename']}")
                print(f"  Path: {details['original_path']}")
                print(f"  Size: {details['file_size']} bytes")
                print(f"  Hash: {details['file_hash']}")
                print(f"  Chunked: {details['is_chunked']}")
                print(f"  Encrypted: {details['is_encrypted']}")
                print(f"  Chunks: {len(details.get('chunks', []))}")
                print(f"  Tags: {[tag['tag_name'] for tag in details.get('tags', [])]}")
            else:
                print("File not found or access denied")
            return
                
        if args.search:
            # Search files
            files = chunker.search_files(args.username, query=args.search)
            if files:
                print(f"\nSearch results for '{args.search}':")
                for file in files:
                    print(f"  {file['original_filename']} ({file['file_size']} bytes)")
            else:
                print(f"No files found matching '{args.search}'")
            return
                
        if args.add_tag:
            # Add tag to file
            file_id, tag_name = args.add_tag
            success = chunker.add_file_tag(args.username, file_id, tag_name)
            if success:
                print(f"✓ Tag '{tag_name}' added to file {file_id}")
            else:
                print(f"✗ Failed to add tag to file")
            return
                
        if args.stats:
            # Show database statistics
            stats = chunker.get_database_stats()
            print(f"\nDatabase Statistics:")
            print(f"  Total Users: {stats['total_users']}")
            print(f"  Total Files: {stats['total_files']}")
            print(f"  Chunked Files: {stats['chunked_files']}")
            print(f"  Encrypted Files: {stats['encrypted_files']}")
            print(f"  Total Storage: {stats['total_storage_mb']} MB")
            return
            
        if args.reconstruct:
            # Reconstruct mode
            if not args.passphrase:
                args.passphrase = input("Enter passphrase for decryption (or press Enter for no encryption): ").strip()
                if not args.passphrase:
                    args.passphrase = None
            
            print(f"Reconstructing file from {args.output_dir}...")
            success = chunker.join_chunks(
                args.output_dir, 
                args.reconstruct, 
                args.username,
                args.passphrase,
                args.keystroke_auth
            )
            if success:
                print(f"File successfully reconstructed as {args.reconstruct}!")
            else:
                print("File reconstruction failed!")
        else:
            # Split mode
            if not args.input:
                print("Error: Input file required for splitting")
                return
                
            if not args.chunk_size:
                fileSize = chunker.choose_chunk_size_for_file(args.input, target_chunks=args.target_chunks)
            else:
                fileSize = args.chunk_size
            
            if not args.passphrase:
                args.passphrase = input("Enter passphrase for encryption (or press Enter for no encryption): ").strip()
                if not args.passphrase:
                    args.passphrase = None
                    print("Splitting file without encryption...")
                else:
                    print("Splitting file with encryption...")
            
            success = chunker.split_file(
                args.input, 
                args.output_dir, 
                args.username,
                fileSize, 
                args.passphrase,
                args.keystroke_auth,
                args.tags
            )
            if success:
                print(f"File split into chunks in {args.output_dir}")
            else:
                print("File splitting failed!")
        
    except Exception as ex:
        print(f"Error: {ex}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()
