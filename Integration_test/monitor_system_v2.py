#!/usr/bin/env python3
"""
Resource Monitor System with Dynamic File Processing

This program monitors CPU/GPU idle states and file changes, automatically
running tasks based on resource availability and file modifications.
Files can be added dynamically to the monitoring system.
"""

import os
import sys
import time
import logging
import threading
import queue
from pathlib import Path
from typing import Optional, Dict, Any, Set
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import signal

# Third-party imports
import psutil
try:
    import pynvml
    GPU_AVAILABLE = True
except ImportError:
    GPU_AVAILABLE = False
    print("Warning: pynvml not available. GPU monitoring will be disabled.")

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# IntelliVault imports
from IntelliVaultFunctions import initialize_intellivault, login, split_file, logout

# File processing imports
from process_files import FileProcessor


@dataclass
class MonitorConfig:
    """Configuration for the monitor system."""
    cpu_idle_threshold: float = 80.0  # CPU idle percentage threshold
    gpu_idle_threshold: float = 20.0  # GPU usage percentage threshold (idle when below this)
    monitor_interval: float = 1.0     # Seconds between resource checks
    log_level: str = "INFO"
    
    # IntelliVault hard-coded configuration
    intellivault_db_path: str = "monitor_intellivault.db"
    master_password: str = "monitor123"
    chunk_output_dir: str = "monitor_chunks"
    enable_encryption: bool = True


class TaskManager:
    """Manages task execution with priority and resource allocation."""
    
    def __init__(self, config: MonitorConfig):
        self.config = config
        self.task_queue = queue.PriorityQueue()
        self.running_tasks: Dict[str, bool] = {
            'decryptAndSplit_cpu': False,
            'LLMcontext_cpu': False,
            'LLMcontext_gpu': False
        }
        self.task_lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=3)
        self.pending_files: Set[str] = set()
        self.pending_files_lock = threading.Lock()
        
        # IntelliVault integration
        self.intellivault_api = None
        self._initialize_intellivault()
        
        # File processing integration
        self.file_processor = None
        self._initialize_file_processor()
    
    def _initialize_intellivault(self):
        """Initialize IntelliVault API and authenticate"""
        try:
            self.intellivault_api = initialize_intellivault(self.config.intellivault_db_path)
            login_result = self.intellivault_api.login(self.config.master_password)
            
            if login_result['success']:
                logging.info("IntelliVault API initialized and authenticated successfully")
            else:
                logging.error(f"IntelliVault authentication failed: {login_result['message']}")
                self.intellivault_api = None
        except Exception as e:
            logging.error(f"Failed to initialize IntelliVault API: {e}")
            self.intellivault_api = None
    
    def _cleanup_intellivault(self):
        """Cleanup IntelliVault resources"""
        if self.intellivault_api:
            try:
                self.intellivault_api.logout()
                logging.info("IntelliVault API logged out successfully")
            except Exception as e:
                logging.error(f"Error during IntelliVault logout: {e}")
    
    def _initialize_file_processor(self):
        """Initialize FileProcessor for LLM context processing"""
        try:
            self.file_processor = FileProcessor()
            logging.info("FileProcessor initialized successfully")
        except Exception as e:
            logging.error(f"Failed to initialize FileProcessor: {e}")
            self.file_processor = None
        
    def add_file(self, file_path: str):
        """Add a file to the pending processing queue."""
        if not os.path.exists(file_path):
            logging.error(f"File does not exist: {file_path}")
            return False
            
        with self.pending_files_lock:
            self.pending_files.add(file_path)
            logging.info(f"Added file to processing queue: {file_path}")
        return True
    
    def get_next_file(self) -> Optional[str]:
        """Get the next file from the pending queue."""
        with self.pending_files_lock:
            if self.pending_files:
                file_path = self.pending_files.pop()
                logging.debug(f"Retrieved file from queue: {file_path}")
                return file_path
        return None
    
    def has_pending_files(self) -> bool:
        """Check if there are files pending processing."""
        with self.pending_files_lock:
            return len(self.pending_files) > 0
    
    def is_task_running(self, task_name: str) -> bool:
        """Check if a specific task is currently running."""
        with self.task_lock:
            return self.running_tasks.get(task_name, False)
    
    def set_task_running(self, task_name: str, running: bool):
        """Set the running state of a task."""
        with self.task_lock:
            self.running_tasks[task_name] = running
    
    def can_run_task(self, task_name: str) -> bool:
        """Check if a task can be run based on current state."""
        with self.task_lock:    
            # High priority: decryptAndSplit on CPU
            if task_name == 'decryptAndSplit_cpu':
                return not any(self.running_tasks.values()) and self.has_pending_files()
            
            # Medium priority: LLMcontext on CPU
            elif task_name == 'LLMcontext_cpu':
                return not self.running_tasks['decryptAndSplit_cpu'] and self.has_pending_files()
            
            # Low priority: LLMcontext on GPU
            elif task_name == 'LLMcontext_gpu':
                return not self.running_tasks['decryptAndSplit_cpu'] and self.has_pending_files()
            
            return False
    
    def submit_task(self, task_name: str, task_func, *args, **kwargs):
        """Submit a task for execution if conditions are met."""
        if self.can_run_task(task_name):
            file_path = self.get_next_file()
            if file_path:
                self.set_task_running(task_name, True)
                future = self.executor.submit(self._execute_task, task_name, task_func, file_path, *args, **kwargs)
                logging.info(f"Task '{task_name}' submitted for execution on file: {file_path}")
                return future
            else:
                logging.debug(f"No files available for task '{task_name}'")
        else:
            logging.debug(f"Task '{task_name}' cannot run due to resource constraints")
        return None
    
    def _execute_task(self, task_name: str, task_func, file_path: str, *args, **kwargs):
        """Execute a task and update running state."""
        try:
            logging.info(f"Starting task: {task_name} on file: {file_path}")
            result = task_func(file_path, *args, **kwargs)
            logging.info(f"Completed task: {task_name} on file: {file_path}")
            return result
        except Exception as e:
            logging.error(f"Task '{task_name}' failed on file '{file_path}': {e}")
        finally:
            self.set_task_running(task_name, False)


class IntelliVaultFunctions:
    """Real IntelliVault implementations for file processing."""
    
    @staticmethod
    def decryptAndSplit(file_path: str, task_manager) -> str:
        """Real function for encryption and splitting using IntelliVault."""
        try:
            # Check if IntelliVault API is available and authenticated
            if not task_manager.intellivault_api or not task_manager.intellivault_api.authenticated:
                logging.error("IntelliVault not authenticated")
                return f"Error: Authentication required for {file_path}"
            
            logging.info(f"Running IntelliVault decryptAndSplit on: {file_path}")
            
            # Call IntelliVault's split_file function with hard-coded config
            result = split_file(
                file_path=file_path,
                output_dir=task_manager.config.chunk_output_dir,
                encrypt=task_manager.config.enable_encryption,
                tags=["monitor_processed", "auto_split"]
            )
            
            # Handle result
            if result['success']:
                logging.info(f"Successfully split file: {file_path}")
                logging.info(f"Created {result['data']['total_chunks']} chunks")
                return f"Successfully processed: {file_path} -> {result['data']['total_chunks']} chunks"
            else:
                logging.error(f"Failed to split file: {result['message']}")
                return f"Error processing {file_path}: {result['message']}"
                
        except Exception as e:
            logging.error(f"Exception in decryptAndSplit: {e}")
            return f"Exception processing {file_path}: {str(e)}"
    
    @staticmethod
    def LLMcontext(file_path: str, device: str = "cpu", task_manager=None) -> str:
        """Real function for LLM context processing using FileProcessor."""
        try:
            # Check if FileProcessor is available
            if not task_manager or not task_manager.file_processor:
                logging.error("FileProcessor not available for LLM context processing")
                return f"Error: FileProcessor not available for {file_path}"
            
            logging.info(f"Running LLMcontext on {device} for: {file_path}")
            
            # Use FileProcessor to embed file content
            embeddings = task_manager.file_processor.embed_file_content(file_path)
            
            if embeddings:
                logging.info(f"Successfully processed file for LLM context: {file_path}")
                logging.info(f"Created {len(embeddings)} embeddings")
                return f"LLM context processed on {device}: {file_path} -> {len(embeddings)} embeddings"
            else:
                logging.error(f"No embeddings created for file: {file_path}")
                return f"Error: No embeddings created for {file_path}"
                
        except Exception as e:
            logging.error(f"Exception in LLMcontext: {e}")
            return f"Exception processing LLM context for {file_path}: {str(e)}"


class CPUIdleMonitor:
    """Monitors CPU idle percentage and triggers tasks when idle."""
    
    def __init__(self, config: MonitorConfig, task_manager: TaskManager):
        self.config = config
        self.task_manager = task_manager
        self.running = False
        self.thread = None
        
    def start(self):
        """Start the CPU idle monitor."""
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logging.info("CPU Idle Monitor started")
    
    def stop(self):
        """Stop the CPU idle monitor."""
        self.running = False
        if self.thread:
            self.thread.join()
        logging.info("CPU Idle Monitor stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        while self.running:
            try:
                # Get CPU usage percentage
                cpu_percent = psutil.cpu_percent(interval=0.1)
                cpu_idle = 100 - cpu_percent
                
                logging.debug(f"CPU Usage: {cpu_percent:.1f}%, Idle: {cpu_idle:.1f}%")
                
                if cpu_idle > self.config.cpu_idle_threshold:
                    logging.info(f"CPU idle ({cpu_idle:.1f}%) exceeds threshold ({self.config.cpu_idle_threshold}%)")
                    
                    # Try to run decryptAndSplit first (highest priority)
                    if self.task_manager.can_run_task('decryptAndSplit_cpu'):
                        self.task_manager.submit_task(
                            'decryptAndSplit_cpu',
                            IntelliVaultFunctions.decryptAndSplit,
                            self.task_manager
                        )
                    # If decryptAndSplit can't run, try LLMcontext on CPU
                    elif self.task_manager.can_run_task('LLMcontext_cpu'):
                        self.task_manager.submit_task(
                            'LLMcontext_cpu',
                            IntelliVaultFunctions.LLMcontext,
                            'cpu',
                            self.task_manager
                        )
                
                time.sleep(self.config.monitor_interval)
                
            except Exception as e:
                logging.error(f"Error in CPU monitor: {e}")
                time.sleep(self.config.monitor_interval)


class GPUIdleMonitor:
    """Monitors GPU usage and triggers tasks when idle."""
    
    def __init__(self, config: MonitorConfig, task_manager: TaskManager):
        self.config = config
        self.task_manager = task_manager
        self.running = False
        self.thread = None
        self.gpu_available = GPU_AVAILABLE
        
        if self.gpu_available:
            try:
                pynvml.nvmlInit()
                self.device_count = pynvml.nvmlDeviceGetCount()
                logging.info(f"GPU monitoring enabled. Found {self.device_count} GPU(s)")
            except Exception as e:
                logging.error(f"Failed to initialize GPU monitoring: {e}")
                self.gpu_available = False
        else:
            logging.warning("GPU monitoring disabled - pynvml not available")
    
    def start(self):
        """Start the GPU idle monitor."""
        if not self.gpu_available:
            logging.info("GPU Idle Monitor not started - GPU not available")
            return
            
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logging.info("GPU Idle Monitor started")
    
    def stop(self):
        """Stop the GPU idle monitor."""
        self.running = False
        if self.thread:
            self.thread.join()
        logging.info("GPU Idle Monitor stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        while self.running:
            try:
                gpu_usage = 0
                
                # Get GPU usage from all available GPUs
                for i in range(self.device_count):
                    handle = pynvml.nvmlDeviceGetHandleByIndex(i)
                    utilization = pynvml.nvmlDeviceGetUtilizationRates(handle)
                    gpu_usage = max(gpu_usage, utilization.gpu)
                
                logging.debug(f"GPU Usage: {gpu_usage}%")
                
                if gpu_usage < self.config.gpu_idle_threshold:
                    logging.info(f"GPU usage ({gpu_usage}%) below threshold ({self.config.gpu_idle_threshold}%)")
                    
                    # Try to run LLMcontext on GPU
                    if self.task_manager.can_run_task('LLMcontext_gpu'):
                        self.task_manager.submit_task(
                            'LLMcontext_gpu',
                            IntelliVaultFunctions.LLMcontext,
                            'gpu',
                            self.task_manager
                        )
                
                time.sleep(self.config.monitor_interval)
                
            except Exception as e:
                logging.error(f"Error in GPU monitor: {e}")
                time.sleep(self.config.monitor_interval)


class FileChangeHandler(FileSystemEventHandler):
    """Handles file system events for monitored files."""
    
    def __init__(self, config: MonitorConfig, task_manager: TaskManager):
        self.config = config
        self.task_manager = task_manager
        self.last_modified: Dict[str, float] = {}
        self.monitored_files: Set[str] = set()
        self.monitored_files_lock = threading.Lock()
        
    def add_file(self, file_path: str):
        """Add a file to monitoring."""
        with self.monitored_files_lock:
            self.monitored_files.add(file_path)
            logging.info(f"Added file to change monitoring: {file_path}")
    
    def remove_file(self, file_path: str):
        """Remove a file from monitoring."""
        with self.monitored_files_lock:
            self.monitored_files.discard(file_path)
            self.last_modified.pop(file_path, None)
            logging.info(f"Removed file from change monitoring: {file_path}")
    
    def on_modified(self, event):
        """Handle file modification events."""
        if event.is_directory:
            return
            
        file_path = event.src_path
        current_time = time.time()
        
        with self.monitored_files_lock:
            if file_path in self.monitored_files:
                # Avoid duplicate events (some systems fire multiple events)
                if file_path not in self.last_modified or current_time - self.last_modified[file_path] > 1.0:
                    self.last_modified[file_path] = current_time
                    logging.info(f"File modified: {file_path}")
                    
                    # Add file to processing queue
                    self.task_manager.add_file(file_path)
                    
                    # Prefer GPU for LLMcontext, fallback to CPU
                    if self.task_manager.can_run_task('LLMcontext_gpu'):
                        self.task_manager.submit_task(
                            'LLMcontext_gpu',
                            IntelliVaultFunctions.LLMcontext,
                            'gpu',
                            self.task_manager
                        )
                    elif self.task_manager.can_run_task('LLMcontext_cpu'):
                        self.task_manager.submit_task(
                            'LLMcontext_cpu',
                            IntelliVaultFunctions.LLMcontext,
                            'cpu',
                            self.task_manager
                        )


class FileChangeMonitor:
    """Monitors file changes using watchdog."""
    
    def __init__(self, config: MonitorConfig, task_manager: TaskManager):
        self.config = config
        self.task_manager = task_manager
        self.observer = None
        self.event_handler = FileChangeHandler(config, task_manager)
        self.monitored_dirs: Set[str] = set()
        
    def start(self):
        """Start the file change monitor."""
        self.observer = Observer()
        self.observer.start()
        logging.info("File Change Monitor started")
    
    def stop(self):
        """Stop the file change monitor."""
        if self.observer:
            self.observer.stop()
            self.observer.join()
        logging.info("File Change Monitor stopped")
    
    def add_file(self, file_path: str):
        """Add a file to monitoring."""
        if not os.path.exists(file_path):
            logging.error(f"File does not exist: {file_path}")
            return False
            
        file_dir = os.path.dirname(file_path)
        
        # Add to event handler
        self.event_handler.add_file(file_path)
        
        # Add directory to observer if not already monitored
        if file_dir not in self.monitored_dirs:
            self.observer.schedule(self.event_handler, file_dir, recursive=False)
            self.monitored_dirs.add(file_dir)
            logging.info(f"Started monitoring directory: {file_dir}")
        
        return True
    
    def remove_file(self, file_path: str):
        """Remove a file from monitoring."""
        self.event_handler.remove_file(file_path)
        logging.info(f"Stopped monitoring file: {file_path}")


class MonitorSystem:
    """Main system that coordinates all monitors."""
    
    def __init__(self, **kwargs):
        self.config = MonitorConfig(**kwargs)
        self.task_manager = TaskManager(self.config)
        self.monitors = {}
        self.running = False
        
        # Setup logging
        logging.basicConfig(
            level=getattr(logging, self.config.log_level.upper()),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('monitor_system.log')
            ]
        )
        
        logging.info("Monitor System initialized")
    
    def start(self):
        """Start all monitors."""
        if self.running:
            logging.warning("Monitor system is already running")
            return
            
        self.running = True
        
        # Initialize monitors
        self.monitors['cpu'] = CPUIdleMonitor(self.config, self.task_manager)
        self.monitors['gpu'] = GPUIdleMonitor(self.config, self.task_manager)
        self.monitors['file'] = FileChangeMonitor(self.config, self.task_manager)
        
        # Start all monitors
        for name, monitor in self.monitors.items():
            monitor.start()
        
        logging.info("All monitors started successfully")
    
    def stop(self):
        """Stop all monitors."""
        if not self.running:
            return
            
        self.running = False
        
        # Stop all monitors
        for name, monitor in self.monitors.items():
            monitor.stop()
        
        # Shutdown task manager
        self.task_manager.executor.shutdown(wait=True)
        
        # Cleanup IntelliVault resources
        self.task_manager._cleanup_intellivault()
        
        logging.info("All monitors stopped")
    
    def add_file(self, file_path: str) -> bool:
        """Add a file to the monitoring and processing system."""
        if not self.running:
            logging.error("Monitor system is not running. Call start() first.")
            return False
            
        # Add to task manager queue
        success1 = self.task_manager.add_file(file_path)
        
        # Add to file change monitoring
        success2 = self.monitors['file'].add_file(file_path)
        
        if success1 and success2:
            logging.info(f"Successfully added file to monitoring system: {file_path}")
            return True
        else:
            logging.error(f"Failed to add file to monitoring system: {file_path}")
            return False
    
    def remove_file(self, file_path: str):
        """Remove a file from monitoring."""
        self.monitors['file'].remove_file(file_path)
        logging.info(f"Removed file from monitoring: {file_path}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current system status."""
        return {
            'running': self.running,
            'pending_files': len(self.task_manager.pending_files),
            'running_tasks': dict(self.task_manager.running_tasks),
            'monitored_dirs': len(self.monitors['file'].monitored_dirs)
        }
    
    def run(self):
        """Run the monitor system until interrupted."""
        try:
            self.start()
            logging.info("Monitor system running. Press Ctrl+C to stop.")
            logging.info("Use add_file() method to add files for processing.")
            
            # Keep the main thread alive
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            logging.info("Received interrupt signal")
        finally:
            self.stop()


def main():
    """Main entry point with example usage."""
    print("Resource Monitor System v2.0")
    print("============================")
    print("This system runs continuously and processes files as they are added.")
    print("Use the add_file() method to add files for processing.")
    print()
    
    # Parse command line arguments
    config_kwargs = {}
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == '--cpu-threshold' and i + 1 < len(sys.argv):
            config_kwargs['cpu_idle_threshold'] = float(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == '--gpu-threshold' and i + 1 < len(sys.argv):
            config_kwargs['gpu_idle_threshold'] = float(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == '--monitor-interval' and i + 1 < len(sys.argv):
            config_kwargs['monitor_interval'] = float(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == '--log-level' and i + 1 < len(sys.argv):
            config_kwargs['log_level'] = sys.argv[i + 1]
            i += 2
        else:
            i += 1
    
    try:
        monitor_system = MonitorSystem(**config_kwargs)
        
        # Example: Add some test files if they exist
        test_files = ['test_file.txt', 'test_file2.txt']
        for test_file in test_files:
            if os.path.exists(test_file):
                print(f"Adding test file: {test_file}")
                monitor_system.add_file(test_file)
        
        monitor_system.run()
    except Exception as e:
        logging.error(f"Failed to start monitor system: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
