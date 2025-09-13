#!/usr/bin/env python3
"""
Database Management Utility for IntelliVault
Handles database initialization, migration, and maintenance
"""

import sqlite3
import json
import os
from pathlib import Path
from typing import Dict, List, Optional
from Database import IntelliVaultDB

class DatabaseManager:
    """Database management and maintenance utilities"""
    
    def __init__(self, db_path: str = "intellivault.db"):
        self.db_path = db_path
        self.db = IntelliVaultDB(db_path)
    
    def backup_database(self, backup_path: str = None) -> str:
        """Create a backup of the database"""
        if not backup_path:
            backup_path = f"{self.db_path}.backup"
        
        # Simple file copy for SQLite
        import shutil
        shutil.copy2(self.db_path, backup_path)
        
        print(f"✓ Database backed up to: {backup_path}")
        return backup_path
    
    def restore_database(self, backup_path: str) -> bool:
        """Restore database from backup"""
        if not os.path.exists(backup_path):
            print(f"✗ Backup file not found: {backup_path}")
            return False
        
        try:
            import shutil
            shutil.copy2(backup_path, self.db_path)
            print(f"✓ Database restored from: {backup_path}")
            return True
        except Exception as e:
            print(f"✗ Failed to restore database: {e}")
            return False
    
    def export_data(self, export_path: str = "intellivault_export.json") -> bool:
        """Export all data to JSON format"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                export_data = {
                    'users': [],
                    'files': [],
                    'chunks': [],
                    'file_tags': [],
                    'access_logs': []
                }
                
                # Export users
                cursor.execute('SELECT * FROM users')
                export_data['users'] = [dict(row) for row in cursor.fetchall()]
                
                # Export files
                cursor.execute('SELECT * FROM files')
                export_data['files'] = [dict(row) for row in cursor.fetchall()]
                
                # Export chunks
                cursor.execute('SELECT * FROM chunks')
                export_data['chunks'] = [dict(row) for row in cursor.fetchall()]
                
                # Export file tags
                cursor.execute('SELECT * FROM file_tags')
                export_data['file_tags'] = [dict(row) for row in cursor.fetchall()]
                
                # Export access logs
                cursor.execute('SELECT * FROM access_logs')
                export_data['access_logs'] = [dict(row) for row in cursor.fetchall()]
                
                # Write to file
                with open(export_path, 'w') as f:
                    json.dump(export_data, f, indent=2, default=str)
                
                print(f"✓ Data exported to: {export_path}")
                return True
                
        except Exception as e:
            print(f"✗ Failed to export data: {e}")
            return False
    
    def import_data(self, import_path: str) -> bool:
        """Import data from JSON format"""
        if not os.path.exists(import_path):
            print(f"✗ Import file not found: {import_path}")
            return False
        
        try:
            with open(import_path, 'r') as f:
                import_data = json.load(f)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Import users
                for user in import_data.get('users', []):
                    cursor.execute('''
                        INSERT OR REPLACE INTO users 
                        (user_id, username, created_at, last_login, keystroke_model_path, is_active)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        user['user_id'], user['username'], user['created_at'],
                        user['last_login'], user['keystroke_model_path'], user['is_active']
                    ))
                
                # Import files
                for file in import_data.get('files', []):
                    cursor.execute('''
                        INSERT OR REPLACE INTO files 
                        (file_id, user_id, original_filename, original_path, file_size, file_hash,
                         file_type, created_at, modified_at, is_chunked, is_encrypted,
                         encryption_algorithm, keystroke_auth_required)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        file['file_id'], file['user_id'], file['original_filename'],
                        file['original_path'], file['file_size'], file['file_hash'],
                        file['file_type'], file['created_at'], file['modified_at'],
                        file['is_chunked'], file['is_encrypted'], file['encryption_algorithm'],
                        file['keystroke_auth_required']
                    ))
                
                # Import chunks
                for chunk in import_data.get('chunks', []):
                    cursor.execute('''
                        INSERT OR REPLACE INTO chunks 
                        (chunk_id, file_id, chunk_index, chunk_filename, chunk_path,
                         chunk_size, chunk_hash, is_encrypted, encryption_nonce, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        chunk['chunk_id'], chunk['file_id'], chunk['chunk_index'],
                        chunk['chunk_filename'], chunk['chunk_path'], chunk['chunk_size'],
                        chunk['chunk_hash'], chunk['is_encrypted'], chunk['encryption_nonce'],
                        chunk['created_at']
                    ))
                
                # Import file tags
                for tag in import_data.get('file_tags', []):
                    cursor.execute('''
                        INSERT OR REPLACE INTO file_tags 
                        (tag_id, file_id, tag_name, tag_value, created_at)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (
                        tag['tag_id'], tag['file_id'], tag['tag_name'],
                        tag['tag_value'], tag['created_at']
                    ))
                
                # Import access logs
                for log in import_data.get('access_logs', []):
                    cursor.execute('''
                        INSERT OR REPLACE INTO access_logs 
                        (log_id, file_id, user_id, action, success, ip_address,
                         user_agent, timestamp, details)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        log['log_id'], log['file_id'], log['user_id'], log['action'],
                        log['success'], log['ip_address'], log['user_agent'],
                        log['timestamp'], log['details']
                    ))
                
                conn.commit()
                print(f"✓ Data imported from: {import_path}")
                return True
                
        except Exception as e:
            print(f"✗ Failed to import data: {e}")
            return False
    
    def cleanup_orphaned_data(self) -> Dict:
        """Clean up orphaned data (chunks without files, etc.)"""
        cleanup_stats = {
            'orphaned_chunks': 0,
            'orphaned_tags': 0,
            'orphaned_logs': 0
        }
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Find orphaned chunks
                cursor.execute('''
                    DELETE FROM chunks 
                    WHERE file_id NOT IN (SELECT file_id FROM files)
                ''')
                cleanup_stats['orphaned_chunks'] = cursor.rowcount
                
                # Find orphaned tags
                cursor.execute('''
                    DELETE FROM file_tags 
                    WHERE file_id NOT IN (SELECT file_id FROM files)
                ''')
                cleanup_stats['orphaned_tags'] = cursor.rowcount
                
                # Find orphaned access logs
                cursor.execute('''
                    DELETE FROM access_logs 
                    WHERE file_id NOT IN (SELECT file_id FROM files)
                ''')
                cleanup_stats['orphaned_logs'] = cursor.rowcount
                
                conn.commit()
                
                print(f"✓ Cleanup completed:")
                print(f"  - Removed {cleanup_stats['orphaned_chunks']} orphaned chunks")
                print(f"  - Removed {cleanup_stats['orphaned_tags']} orphaned tags")
                print(f"  - Removed {cleanup_stats['orphaned_logs']} orphaned logs")
                
                return cleanup_stats
                
        except Exception as e:
            print(f"✗ Cleanup failed: {e}")
            return cleanup_stats
    
    def optimize_database(self) -> bool:
        """Optimize database performance"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Analyze tables for better query planning
                cursor.execute('ANALYZE')
                
                # Vacuum to reclaim space
                cursor.execute('VACUUM')
                
                print("✓ Database optimized successfully")
                return True
                
        except Exception as e:
            print(f"✗ Database optimization failed: {e}")
            return False
    
    def get_database_info(self) -> Dict:
        """Get detailed database information"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get database file size
                db_size = os.path.getsize(self.db_path)
                
                # Get table information
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in cursor.fetchall()]
                
                table_info = {}
                for table in tables:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    count = cursor.fetchone()[0]
                    table_info[table] = count
                
                # Get database version
                cursor.execute("SELECT sqlite_version()")
                sqlite_version = cursor.fetchone()[0]
                
                return {
                    'database_path': self.db_path,
                    'database_size_bytes': db_size,
                    'database_size_mb': round(db_size / (1024 * 1024), 2),
                    'sqlite_version': sqlite_version,
                    'tables': table_info
                }
                
        except Exception as e:
            print(f"✗ Failed to get database info: {e}")
            return {}
    
    def reset_database(self) -> bool:
        """Reset database (WARNING: This will delete all data!)"""
        response = input("WARNING: This will delete ALL data! Are you sure? (yes/no): ")
        if response.lower() != 'yes':
            print("Database reset cancelled")
            return False
        
        try:
            # Remove existing database
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
            
            # Reinitialize database
            self.db = IntelliVaultDB(self.db_path)
            
            print("✓ Database reset successfully")
            return True
            
        except Exception as e:
            print(f"✗ Database reset failed: {e}")
            return False

def main():
    """Main function for database management"""
    import argparse
    
    parser = argparse.ArgumentParser(description="IntelliVault Database Manager")
    parser.add_argument("--backup", help="Backup database to specified path")
    parser.add_argument("--restore", help="Restore database from backup")
    parser.add_argument("--export", help="Export data to JSON file")
    parser.add_argument("--import", dest="import_file", help="Import data from JSON file")
    parser.add_argument("--cleanup", action="store_true", help="Clean up orphaned data")
    parser.add_argument("--optimize", action="store_true", help="Optimize database")
    parser.add_argument("--info", action="store_true", help="Show database information")
    parser.add_argument("--reset", action="store_true", help="Reset database (WARNING: deletes all data)")
    parser.add_argument("--db-path", default="intellivault.db", help="Database file path")
    
    args = parser.parse_args()
    
    manager = DatabaseManager(args.db_path)
    
    if args.backup:
        manager.backup_database(args.backup)
    elif args.restore:
        manager.restore_database(args.restore)
    elif args.export:
        manager.export_data(args.export)
    elif args.import_file:
        manager.import_data(args.import_file)
    elif args.cleanup:
        manager.cleanup_orphaned_data()
    elif args.optimize:
        manager.optimize_database()
    elif args.info:
        info = manager.get_database_info()
        if info:
            print(f"\nDatabase Information:")
            print(f"  Path: {info['database_path']}")
            print(f"  Size: {info['database_size_mb']} MB")
            print(f"  SQLite Version: {info['sqlite_version']}")
            print(f"  Tables:")
            for table, count in info['tables'].items():
                print(f"    {table}: {count} records")
    elif args.reset:
        manager.reset_database()
    else:
        # Show stats
        stats = manager.db.get_database_stats()
        print(f"\nDatabase Statistics:")
        print(f"  Total Users: {stats['total_users']}")
        print(f"  Total Files: {stats['total_files']}")
        print(f"  Chunked Files: {stats['chunked_files']}")
        print(f"  Encrypted Files: {stats['encrypted_files']}")
        print(f"  Total Storage: {stats['total_storage_mb']} MB")

if __name__ == "__main__":
    main()

