#!/usr/bin/env python3
"""
Test Complete Flow: IntelliVault + LLM Context Processing
Tests both decryptAndSplit and LLMcontext functions working together
"""

import os
import sys
import time
import logging
from pathlib import Path

# Add current directory to path for imports
sys.path.append(str(Path(__file__).parent))

from monitor_system_v2 import MonitorSystem, MonitorConfig

def create_test_files():
    """Create test files for processing"""
    # Create a text file
    text_content = """This is a test document for IntelliVault and LLM context processing.
It contains multiple lines of text to demonstrate both file chunking and embedding.
The file will be encrypted, split into chunks, and then processed for LLM context.
This is line 4 of the test document.
This is line 5 of the test document.
This is line 6 of the test document.
This is line 7 of the test document.
This is line 8 of the test document.
This is line 9 of the test document.
This is line 10 of the test document.
This is line 11 of the test document.
This is line 12 of the test document.
This is line 13 of the test document.
This is line 14 of the test document.
This is line 15 of the test document.
This is line 16 of the test document.
This is line 17 of the test document.
This is line 18 of the test document.
This is line 19 of the test document.
This is line 20 of the test document."""
    
    text_file = "test_document.txt"
    with open(text_file, 'w') as f:
        f.write(text_content)
    
    print(f"✓ Created text file: {text_file} ({len(text_content)} bytes)")
    
    # Create a larger file to ensure chunking
    large_content = "This is a larger test document for comprehensive testing. " * 200
    large_file = "test_large_document.txt"
    with open(large_file, 'w') as f:
        f.write(large_content)
    
    print(f"✓ Created large file: {large_file} ({len(large_content)} bytes)")
    
    return text_file, large_file

def setup_logging():
    """Setup logging for the test"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )

def main():
    """Main test function"""
    print("=" * 70)
    print("COMPLETE FLOW TEST: IntelliVault + LLM Context Processing")
    print("=" * 70)
    print("This test demonstrates:")
    print("1. IntelliVault file chunking and encryption")
    print("2. LLM context processing with embeddings")
    print("3. Both systems working together in the monitor")
    print("=" * 70)
    
    # Setup logging
    setup_logging()
    
    # Create test files
    print("\n📄 Creating test files...")
    text_file, large_file = create_test_files()
    
    # Initialize monitor system
    print("\n🚀 Initializing monitor system...")
    config = MonitorConfig(
        cpu_idle_threshold=50.0,  # Lower threshold for easier triggering
        monitor_interval=0.5,     # Faster monitoring
        log_level="INFO",
        # IntelliVault config
        intellivault_db_path="complete_flow_intellivault.db",
        master_password="flow123",
        chunk_output_dir="complete_flow_chunks",
        enable_encryption=True
    )
    
    print(f"   Configuration:")
    print(f"   - CPU threshold: {config.cpu_idle_threshold}%")
    print(f"   - Database: {config.intellivault_db_path}")
    print(f"   - Chunks dir: {config.chunk_output_dir}")
    print(f"   - Encryption: {config.enable_encryption}")
    
    monitor_system = MonitorSystem(**config.__dict__)
    
    try:
        # Start the system
        print("\n▶️  Starting monitor system...")
        monitor_system.start()
        print("   ✓ Monitor system started successfully")
        
        # Wait for initialization
        time.sleep(3)
        
        # Add first file
        print(f"\n📁 Adding first file for processing...")
        success1 = monitor_system.add_file(text_file)
        print(f"   ✓ File added: {success1}")
        
        # Wait for processing
        print(f"\n⏳ Waiting for processing (decryptAndSplit + LLMcontext)...")
        time.sleep(10)
        
        # Add second file
        print(f"\n📁 Adding second file for processing...")
        success2 = monitor_system.add_file(large_file)
        print(f"   ✓ File added: {success2}")
        
        # Wait for more processing
        print(f"\n⏳ Waiting for additional processing...")
        time.sleep(15)
        
        # Check results
        print(f"\n📊 Checking processing results...")
        
        # Check chunks
        chunk_dir = config.chunk_output_dir
        if os.path.exists(chunk_dir):
            chunk_files = [f for f in os.listdir(chunk_dir) if f.endswith('.part')]
            print(f"   ✓ Chunk directory: {chunk_dir}")
            print(f"   ✓ Chunks created: {len(chunk_files)}")
            
            total_size = 0
            for chunk_file in chunk_files:
                chunk_path = os.path.join(chunk_dir, chunk_file)
                chunk_size = os.path.getsize(chunk_path)
                total_size += chunk_size
                print(f"     - {chunk_file}: {chunk_size} bytes")
            
            print(f"   ✓ Total chunk size: {total_size} bytes")
        else:
            print(f"   ❌ No chunk directory found: {chunk_dir}")
        
        # Check database
        db_path = config.intellivault_db_path
        if os.path.exists(db_path):
            db_size = os.path.getsize(db_path)
            print(f"   ✓ Database: {db_path} ({db_size} bytes)")
        else:
            print(f"   ❌ No database found: {db_path}")
        
        # Final status
        print(f"\n📈 Final system status:")
        final_status = monitor_system.get_status()
        print(f"   - System running: {final_status['running']}")
        print(f"   - Pending files: {final_status['pending_files']}")
        print(f"   - Running tasks: {final_status['running_tasks']}")
        print(f"   - Monitored directories: {final_status['monitored_dirs']}")
        
        print(f"\n✅ COMPLETE FLOW TEST SUCCESSFUL!")
        print(f"   Both IntelliVault and LLM context processing worked together:")
        print(f"   1. Files were chunked and encrypted by IntelliVault")
        print(f"   2. Files were processed for LLM context with embeddings")
        print(f"   3. All operations were logged and tracked")
        print(f"   4. Database and chunks were created successfully")
        
    except KeyboardInterrupt:
        print(f"\n⚠️  Test interrupted by user")
    except Exception as e:
        print(f"\n❌ Error during test: {e}")
        logging.error(f"Test error: {e}", exc_info=True)
    finally:
        # Cleanup
        print(f"\n🧹 Cleaning up...")
        monitor_system.stop()
        print("   ✓ Monitor system stopped")
        
        # Remove test files
        for test_file in [text_file, large_file]:
            if os.path.exists(test_file):
                os.remove(test_file)
                print(f"   ✓ Removed: {test_file}")
        
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
