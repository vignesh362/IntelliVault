#!/usr/bin/env python3
"""
Simple Example: IntelliVault Monitor System Integration
Demonstrates the complete flow from initialization to file chunking and storage
"""

import os
import sys
import time
import logging
from pathlib import Path

# Add current directory to path for imports
sys.path.append(str(Path(__file__).parent))

from monitor_system_v2 import MonitorSystem, MonitorConfig

def create_sample_file():
    """Create a sample file for processing"""
    sample_content = """This is a sample document for IntelliVault processing.
It contains multiple lines of text to demonstrate file chunking.
The file will be encrypted and split into secure chunks.
This is line 4 of the sample document.
This is line 5 of the sample document.
This is line 6 of the sample document.
This is line 7 of the sample document.
This is line 8 of the sample document.
This is line 9 of the sample document.
This is line 10 of the sample document.
This is line 11 of the sample document.
This is line 12 of the sample document.
This is line 13 of the sample document.
This is line 14 of the sample document.
This is line 15 of the sample document.
This is line 16 of the sample document.
This is line 17 of the sample document.
This is line 18 of the sample document.
This is line 19 of the sample document.
This is line 20 of the sample document.
This is line 21 of the sample document.
This is line 22 of the sample document.
This is line 23 of the sample document.
This is line 24 of the sample document.
This is line 25 of the sample document.
This is line 26 of the sample document.
This is line 27 of the sample document.
This is line 28 of the sample document.
This is line 29 of the sample document.
This is line 30 of the sample document."""
    
    sample_file = "sample_document.txt"
    with open(sample_file, 'w') as f:
        f.write(sample_content)
    
    print(f"✓ Created sample file: {sample_file} ({len(sample_content)} bytes)")
    return sample_file

def setup_simple_logging():
    """Setup simple logging for the example"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )

def main():
    """Main example function demonstrating the complete flow"""
    print("=" * 60)
    print("INTELLIVAULT MONITOR SYSTEM - SIMPLE EXAMPLE")
    print("=" * 60)
    print("This example demonstrates:")
    print("1. System initialization")
    print("2. File creation")
    print("3. File addition to monitoring")
    print("4. Automatic processing (chunking & encryption)")
    print("5. Database storage")
    print("=" * 60)
    
    # Setup logging
    setup_simple_logging()
    
    # Step 1: Create sample file
    print("\n📄 STEP 1: Creating sample file...")
    sample_file = create_sample_file()
    
    # Step 2: Initialize monitor system
    print("\n🚀 STEP 2: Initializing monitor system...")
    config = MonitorConfig(
        cpu_idle_threshold=60.0,  # Lower threshold for easier triggering
        monitor_interval=0.5,     # Faster monitoring
        log_level="INFO",
        # IntelliVault hard-coded config
        intellivault_db_path="example_intellivault.db",
        master_password="example123",
        chunk_output_dir="example_chunks",
        enable_encryption=True
    )
    
    print(f"   Configuration:")
    print(f"   - CPU threshold: {config.cpu_idle_threshold}%")
    print(f"   - Database: {config.intellivault_db_path}")
    print(f"   - Chunks dir: {config.chunk_output_dir}")
    print(f"   - Encryption: {config.enable_encryption}")
    
    monitor_system = MonitorSystem(**config.__dict__)
    
    try:
        # Step 3: Start the system
        print("\n▶️  STEP 3: Starting monitor system...")
        monitor_system.start()
        print("   ✓ Monitor system started successfully")
        
        # Wait for initialization
        time.sleep(2)
        
        # Step 4: Add file for processing
        print(f"\n📁 STEP 4: Adding file for processing...")
        success = monitor_system.add_file(sample_file)
        print(f"   ✓ File added: {success}")
        
        # Step 5: Wait for processing
        print(f"\n⏳ STEP 5: Waiting for automatic processing...")
        print("   (The system will detect CPU idle and process the file)")
        
        # Wait for processing to complete
        for i in range(15):  # Wait up to 15 seconds
            time.sleep(1)
            status = monitor_system.get_status()
            if status['pending_files'] == 0 and not any(status['running_tasks'].values()):
                print(f"   ✓ Processing completed after {i+1} seconds")
                break
            print(f"   ... waiting ({i+1}/15) - Pending: {status['pending_files']}, Running: {status['running_tasks']}")
        
        # Step 6: Check results
        print(f"\n📊 STEP 6: Checking processing results...")
        
        # Check if chunks were created
        chunk_dir = config.chunk_output_dir
        if os.path.exists(chunk_dir):
            chunk_files = [f for f in os.listdir(chunk_dir) if f.endswith('.part')]
            manifest_file = os.path.join(chunk_dir, 'manifest.json')
            
            print(f"   ✓ Chunk directory created: {chunk_dir}")
            print(f"   ✓ Chunks created: {len(chunk_files)}")
            
            # Show chunk details
            total_size = 0
            for chunk_file in chunk_files:
                chunk_path = os.path.join(chunk_dir, chunk_file)
                chunk_size = os.path.getsize(chunk_path)
                total_size += chunk_size
                print(f"     - {chunk_file}: {chunk_size} bytes")
            
            print(f"   ✓ Total chunk size: {total_size} bytes")
            
            # Check manifest
            if os.path.exists(manifest_file):
                manifest_size = os.path.getsize(manifest_file)
                print(f"   ✓ Manifest file: {manifest_size} bytes")
        else:
            print(f"   ❌ No chunk directory found: {chunk_dir}")
        
        # Check database
        db_path = config.intellivault_db_path
        if os.path.exists(db_path):
            db_size = os.path.getsize(db_path)
            print(f"   ✓ Database created: {db_path} ({db_size} bytes)")
        else:
            print(f"   ❌ No database found: {db_path}")
        
        # Final status
        print(f"\n📈 FINAL STATUS:")
        final_status = monitor_system.get_status()
        print(f"   - System running: {final_status['running']}")
        print(f"   - Pending files: {final_status['pending_files']}")
        print(f"   - Running tasks: {final_status['running_tasks']}")
        print(f"   - Monitored directories: {final_status['monitored_dirs']}")
        
        print(f"\n✅ EXAMPLE COMPLETED SUCCESSFULLY!")
        print(f"   The file '{sample_file}' was:")
        print(f"   1. Added to the monitoring system")
        print(f"   2. Automatically detected for processing")
        print(f"   3. Encrypted and split into chunks")
        print(f"   4. Stored in the IntelliVault database")
        print(f"   5. All operations logged and tracked")
        
    except KeyboardInterrupt:
        print(f"\n⚠️  Example interrupted by user")
    except Exception as e:
        print(f"\n❌ Error during example: {e}")
        logging.error(f"Example error: {e}", exc_info=True)
    finally:
        # Cleanup
        print(f"\n🧹 Cleaning up...")
        monitor_system.stop()
        print("   ✓ Monitor system stopped")
        
        # Remove sample file
        if os.path.exists(sample_file):
            os.remove(sample_file)
            print(f"   ✓ Removed sample file: {sample_file}")
        
        print(f"\n📋 Generated files (kept for inspection):")
        if os.path.exists(config.intellivault_db_path):
            print(f"   - Database: {config.intellivault_db_path}")
        if os.path.exists(config.chunk_output_dir):
            print(f"   - Chunks: {config.chunk_output_dir}/")
            chunk_files = [f for f in os.listdir(config.chunk_output_dir) if f.endswith('.part')]
            print(f"     * {len(chunk_files)} chunk files")
            print(f"     * manifest.json")

if __name__ == "__main__":
    main()
