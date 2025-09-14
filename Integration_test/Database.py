#!/usr/bin/env python3
"""
IntelliVault Database Module
Manages file metadata, chunk information, and user data
"""

import sqlite3
import json
import hashlib
import os
import stat
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import uuid
import platform

class IntelliVaultDB:
    """Database manager for IntelliVault file tracking"""
    
    def __init__(self, db_path: str = "intellivault.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database with required tables"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    keystroke_model_path TEXT,
                    is_active BOOLEAN DEFAULT 1
                )
            ''')
            
            # Files table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS files (
                    file_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    original_filename TEXT NOT NULL,
                    original_path TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    file_hash TEXT NOT NULL,
                    file_type TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_chunked BOOLEAN DEFAULT 0,
                    is_encrypted BOOLEAN DEFAULT 0,
                    encryption_algorithm TEXT,
                    keystroke_auth_required BOOLEAN DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users (user_id)
                )
            ''')
            
            # Chunks table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS chunks (
                    chunk_id TEXT PRIMARY KEY,
                    file_id TEXT NOT NULL,
                    chunk_index INTEGER NOT NULL,
                    chunk_filename TEXT NOT NULL,
                    chunk_path TEXT NOT NULL,
                    chunk_size INTEGER NOT NULL,
                    chunk_hash TEXT,
                    is_encrypted BOOLEAN DEFAULT 0,
                    encryption_nonce TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (file_id) REFERENCES files (file_id)
                )
            ''')
            
            # File tags table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_tags (
                    tag_id TEXT PRIMARY KEY,
                    file_id TEXT NOT NULL,
                    tag_name TEXT NOT NULL,
                    tag_value TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (file_id) REFERENCES files (file_id)
                )
            ''')
            
            # Access logs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS access_logs (
                    log_id TEXT PRIMARY KEY,
                    file_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    success BOOLEAN NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    details TEXT,
                    FOREIGN KEY (file_id) REFERENCES files (file_id),
                    FOREIGN KEY (user_id) REFERENCES users (user_id)
                )
            ''')
            
            # Create indexes for better performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_files_user_id ON files (user_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_files_hash ON files (file_hash)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_chunks_file_id ON chunks (file_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_chunks_index ON chunks (file_id, chunk_index)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_tags_file_id ON file_tags (file_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_access_logs_file_id ON access_logs (file_id)')
            
            conn.commit()
    
    def generate_file_hash(self, file_path: str) -> str:
        """Generate SHA-256 hash of a file"""
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    def generate_os_file_id(self, file_path: str) -> str:
        """Generate OS-based file ID"""
        try:
            file_stat = os.stat(file_path)
            system = platform.system().lower()
            
            if system == "windows":
                # Windows: Use file index + device + size
                file_id = f"win_{file_stat.st_ino}_{file_stat.st_dev}_{file_stat.st_size}"
            else:
                # Unix/Linux/macOS: Use inode number + device
                file_id = f"unix_{file_stat.st_ino}_{file_stat.st_dev}"
            
            # Create a hash to make it shorter and more consistent
            file_id_hash = hashlib.sha256(file_id.encode()).hexdigest()[:16]
            return f"os_{file_id_hash}"
            
        except (OSError, AttributeError):
            # Fallback to UUID if OS method fails
            return str(uuid.uuid4())
    
    def generate_file_id(self, file_path: str, use_os_id: bool = True) -> str:
        """Generate file ID using OS or UUID method"""
        if use_os_id:
            return self.generate_os_file_id(file_path)
        else:
            return str(uuid.uuid4())
    
    def create_user(self, username: str, keystroke_model_path: str = None) -> str:
        """Create a new user"""
        user_id = str(uuid.uuid4())
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (user_id, username, keystroke_model_path)
                VALUES (?, ?, ?)
            ''', (user_id, username, keystroke_model_path))
            conn.commit()
        
        return user_id
    
    def get_user(self, username: str) -> Optional[Dict]:
        """Get user information by username"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def register_file(self, user_id: str, file_path: str, file_metadata: Dict = None, use_os_id: bool = True) -> str:
        """Register a new file in the database"""
        file_path = Path(file_path)
        file_id = self.generate_file_id(str(file_path), use_os_id)
        
        # Get file information
        file_size = file_path.stat().st_size
        file_hash = self.generate_file_hash(str(file_path))
        file_type = file_path.suffix.lower()
        
        # Extract metadata
        metadata = file_metadata or {}
        is_chunked = metadata.get('is_chunked', False)
        is_encrypted = metadata.get('is_encrypted', False)
        encryption_algorithm = metadata.get('encryption_algorithm')
        keystroke_auth_required = metadata.get('keystroke_auth_required', False)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO files (
                    file_id, user_id, original_filename, original_path,
                    file_size, file_hash, file_type, is_chunked, is_encrypted,
                    encryption_algorithm, keystroke_auth_required
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                file_id, user_id, file_path.name, str(file_path),
                file_size, file_hash, file_type, is_chunked, is_encrypted,
                encryption_algorithm, keystroke_auth_required
            ))
            conn.commit()
        
        return file_id
    
    def add_chunks(self, file_id: str, chunks_info: List[Dict]) -> List[str]:
        """Add chunk information for a file"""
        chunk_ids = []
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            for chunk_info in chunks_info:
                chunk_id = str(uuid.uuid4())
                chunk_ids.append(chunk_id)
                
                cursor.execute('''
                    INSERT INTO chunks (
                        chunk_id, file_id, chunk_index, chunk_filename,
                        chunk_path, chunk_size, chunk_hash, is_encrypted,
                        encryption_nonce
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    chunk_id, file_id, chunk_info['index'], chunk_info['filename'],
                    chunk_info['path'], chunk_info['size'], chunk_info.get('hash'),
                    chunk_info.get('is_encrypted', False), chunk_info.get('nonce')
                ))
            
            # Update file as chunked
            cursor.execute('''
                UPDATE files SET is_chunked = 1, modified_at = CURRENT_TIMESTAMP
                WHERE file_id = ?
            ''', (file_id,))
            
            conn.commit()
        
        return chunk_ids
    
    def get_file(self, file_id: str) -> Optional[Dict]:
        """Get file information by file_id"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM files WHERE file_id = ?', (file_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_file_by_hash(self, file_hash: str) -> Optional[Dict]:
        """Get file information by file hash"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM files WHERE file_hash = ?', (file_hash,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_file_by_os_id(self, file_path: str) -> Optional[Dict]:
        """Get file by OS-based ID"""
        os_file_id = self.generate_os_file_id(file_path)
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM files WHERE file_id = ?', (os_file_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_file_chunks(self, file_id: str) -> List[Dict]:
        """Get all chunks for a file"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM chunks 
                WHERE file_id = ? 
                ORDER BY chunk_index
            ''', (file_id,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    
    def get_user_files(self, user_id: str, limit: int = 100, offset: int = 0) -> List[Dict]:
        """Get all files for a user"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM files 
                WHERE user_id = ? 
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            ''', (user_id, limit, offset))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    
    def search_files(self, user_id: str, query: str = None, file_type: str = None, 
                    is_chunked: bool = None, is_encrypted: bool = None) -> List[Dict]:
        """Search files with various filters"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            where_conditions = ["user_id = ?"]
            params = [user_id]
            
            if query:
                where_conditions.append("(original_filename LIKE ? OR original_path LIKE ?)")
                params.extend([f"%{query}%", f"%{query}%"])
            
            if file_type:
                where_conditions.append("file_type = ?")
                params.append(file_type)
            
            if is_chunked is not None:
                where_conditions.append("is_chunked = ?")
                params.append(is_chunked)
            
            if is_encrypted is not None:
                where_conditions.append("is_encrypted = ?")
                params.append(is_encrypted)
            
            sql = f'''
                SELECT * FROM files 
                WHERE {' AND '.join(where_conditions)}
                ORDER BY created_at DESC
            '''
            
            cursor.execute(sql, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    
    def add_file_tag(self, file_id: str, tag_name: str, tag_value: str = None) -> str:
        """Add a tag to a file"""
        tag_id = str(uuid.uuid4())
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO file_tags (tag_id, file_id, tag_name, tag_value)
                VALUES (?, ?, ?, ?)
            ''', (tag_id, file_id, tag_name, tag_value))
            conn.commit()
        
        return tag_id
    
    def get_file_tags(self, file_id: str) -> List[Dict]:
        """Get all tags for a file"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM file_tags 
                WHERE file_id = ? 
                ORDER BY created_at
            ''', (file_id,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    
    def log_access(self, file_id: str, user_id: str, action: str, 
                   success: bool, ip_address: str = None, 
                   user_agent: str = None, details: str = None) -> str:
        """Log file access attempt"""
        log_id = str(uuid.uuid4())
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO access_logs (
                    log_id, file_id, user_id, action, success,
                    ip_address, user_agent, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (log_id, file_id, user_id, action, success, 
                  ip_address, user_agent, details))
            conn.commit()
        
        return log_id
    
    def get_access_logs(self, file_id: str = None, user_id: str = None, 
                       limit: int = 100) -> List[Dict]:
        """Get access logs with optional filters"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            where_conditions = []
            params = []
            
            if file_id:
                where_conditions.append("file_id = ?")
                params.append(file_id)
            
            if user_id:
                where_conditions.append("user_id = ?")
                params.append(user_id)
            
            where_clause = " AND ".join(where_conditions) if where_conditions else "1=1"
            
            sql = f'''
                SELECT * FROM access_logs 
                WHERE {where_clause}
                ORDER BY timestamp DESC
                LIMIT ?
            '''
            params.append(limit)
            
            cursor.execute(sql, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    
    def update_file_metadata(self, file_id: str, metadata: Dict) -> bool:
        """Update file metadata"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Build dynamic update query
            set_clauses = []
            params = []
            
            for key, value in metadata.items():
                if key in ['is_chunked', 'is_encrypted', 'keystroke_auth_required']:
                    set_clauses.append(f"{key} = ?")
                    params.append(value)
                elif key in ['encryption_algorithm']:
                    set_clauses.append(f"{key} = ?")
                    params.append(value)
            
            if set_clauses:
                set_clauses.append("modified_at = CURRENT_TIMESTAMP")
                params.append(file_id)
                
                sql = f"UPDATE files SET {', '.join(set_clauses)} WHERE file_id = ?"
                cursor.execute(sql, params)
                conn.commit()
                return True
        
        return False
    
    def delete_file(self, file_id: str) -> bool:
        """Delete file and all associated data"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Delete chunks
            cursor.execute('DELETE FROM chunks WHERE file_id = ?', (file_id,))
            
            # Delete tags
            cursor.execute('DELETE FROM file_tags WHERE file_id = ?', (file_id,))
            
            # Delete access logs
            cursor.execute('DELETE FROM access_logs WHERE file_id = ?', (file_id,))
            
            # Delete file
            cursor.execute('DELETE FROM files WHERE file_id = ?', (file_id,))
            
            conn.commit()
            return cursor.rowcount > 0
    
    def get_database_stats(self) -> Dict:
        """Get database statistics"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            stats = {}
            
            # Count users
            cursor.execute('SELECT COUNT(*) FROM users')
            stats['total_users'] = cursor.fetchone()[0]
            
            # Count files
            cursor.execute('SELECT COUNT(*) FROM files')
            stats['total_files'] = cursor.fetchone()[0]
            
            # Count chunks
            cursor.execute('SELECT COUNT(*) FROM chunks')
            stats['total_chunks'] = cursor.fetchone()[0]
            
            # Count chunked files
            cursor.execute('SELECT COUNT(*) FROM files WHERE is_chunked = 1')
            stats['chunked_files'] = cursor.fetchone()[0]
            
            # Count encrypted files
            cursor.execute('SELECT COUNT(*) FROM files WHERE is_encrypted = 1')
            stats['encrypted_files'] = cursor.fetchone()[0]
            
            # Total storage used
            cursor.execute('SELECT SUM(file_size) FROM files')
            total_size = cursor.fetchone()[0] or 0
            stats['total_storage_bytes'] = total_size
            stats['total_storage_mb'] = round(total_size / (1024 * 1024), 2)
            
            return stats

def main():
    """Test the database functionality"""
    db = IntelliVaultDB("test_intellivault.db")
    
    # Test user creation
    user_id = db.create_user("test_user", "keystroke_model.joblib")
    print(f"Created user: {user_id}")
    
    # Test file registration
    file_id = db.register_file(user_id, "Test Files/vov.pdf", {
        'is_chunked': True,
        'is_encrypted': True,
        'encryption_algorithm': 'AES-256-GCM',
        'keystroke_auth_required': True
    })
    print(f"Registered file: {file_id}")
    
    # Test chunk addition
    chunks_info = [
        {
            'index': 0,
            'filename': 'chunk_00001.part',
            'path': 'Test Chunks/chunk_00001.part',
            'size': 1048576,
            'hash': 'abc123',
            'is_encrypted': True,
            'nonce': 'def456'
        },
        {
            'index': 1,
            'filename': 'chunk_00002.part',
            'path': 'Test Chunks/chunk_00002.part',
            'size': 1048576,
            'hash': 'ghi789',
            'is_encrypted': True,
            'nonce': 'jkl012'
        }
    ]
    
    chunk_ids = db.add_chunks(file_id, chunks_info)
    print(f"Added chunks: {chunk_ids}")
    
    # Test file retrieval
    file_info = db.get_file(file_id)
    print(f"File info: {file_info}")
    
    # Test chunk retrieval
    chunks = db.get_file_chunks(file_id)
    print(f"File chunks: {len(chunks)} chunks")
    
    # Test search
    search_results = db.search_files(user_id, file_type='.pdf')
    print(f"Search results: {len(search_results)} files")
    
    # Test stats
    stats = db.get_database_stats()
    print(f"Database stats: {stats}")

if __name__ == "__main__":
    main()
