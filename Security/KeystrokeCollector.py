#!/usr/bin/env python3
"""
Real-time Keystroke Data Collection Utility
Captures actual keyboard events for keystroke dynamics analysis
"""

import time
import threading
import queue
import sys
from typing import Dict, List, Optional
from KeystrokeAuth import KeystrokeData

try:
    import pynput
    from pynput import keyboard
    PYNPUT_AVAILABLE = True
except ImportError:
    PYNPUT_AVAILABLE = False
    print("Warning: pynput not available. Install with: pip install pynput")

class RealTimeKeystrokeCollector:
    """Real-time keystroke collector using pynput"""
    
    def __init__(self):
        self.keystroke_data = KeystrokeData()
        self.is_collecting = False
        self.key_events = queue.Queue()
        self.listener = None
        self.current_sequence = []
        
    def on_key_press(self, key):
        """Handle key press events"""
        if not self.is_collecting:
            return
            
        try:
            # Convert key to string
            if hasattr(key, 'char') and key.char is not None:
                key_char = key.char
            elif key == keyboard.Key.space:
                key_char = ' '
            elif key == keyboard.Key.enter:
                key_char = '\n'
            elif key == keyboard.Key.backspace:
                key_char = '\b'
            else:
                key_char = str(key).replace('Key.', '')
                
            self.key_events.put(('press', key_char, time.time()))
            
        except AttributeError:
            pass
            
    def on_key_release(self, key):
        """Handle key release events"""
        if not self.is_collecting:
            return
            
        try:
            # Convert key to string
            if hasattr(key, 'char') and key.char is not None:
                key_char = key.char
            elif key == keyboard.Key.space:
                key_char = ' '
            elif key == keyboard.Key.enter:
                key_char = '\n'
            elif key == keyboard.Key.backspace:
                key_char = '\b'
            else:
                key_char = str(key).replace('Key.', '')
                
            self.key_events.put(('release', key_char, time.time()))
            
        except AttributeError:
            pass
            
    def start_collection(self):
        """Start collecting keystroke data"""
        if not PYNPUT_AVAILABLE:
            print("Error: pynput not available. Cannot collect real-time keystroke data.")
            return False
            
        self.is_collecting = True
        self.keystroke_data.start_typing()
        
        # Start keyboard listener
        self.listener = keyboard.Listener(
            on_press=self.on_key_press,
            on_release=self.on_key_release
        )
        self.listener.start()
        
        print("✓ Keystroke collection started. Type your passphrase...")
        return True
        
    def stop_collection(self) -> List[Dict]:
        """Stop collecting and return keystroke sequence"""
        if not self.is_collecting:
            return []
            
        self.is_collecting = False
        
        if self.listener:
            self.listener.stop()
            self.listener = None
            
        # Process collected events
        self._process_events()
        
        sequence = self.keystroke_data.finish_typing()
        print(f"✓ Collected {len(sequence)} keystroke events")
        return sequence
        
    def _process_events(self):
        """Process collected key events"""
        while not self.key_events.empty():
            try:
                event_type, key_char, timestamp = self.key_events.get_nowait()
                
                if event_type == 'press':
                    self.keystroke_data.record_key_press(key_char)
                elif event_type == 'release':
                    self.keystroke_data.record_key_release(key_char)
                    
            except queue.Empty:
                break

class SimulatedKeystrokeCollector:
    """Simulated keystroke collector for testing without pynput"""
    
    def __init__(self):
        self.keystroke_data = KeystrokeData()
        
    def collect_sequence(self, passphrase: str) -> List[Dict]:
        """Simulate keystroke collection for a passphrase"""
        print(f"Simulating keystroke collection for: {passphrase}")
        
        self.keystroke_data.start_typing()
        
        # Simulate realistic typing patterns
        for i, char in enumerate(passphrase):
            # Simulate key press
            self.keystroke_data.record_key_press(char)
            
            # Simulate realistic hold time (50-200ms)
            hold_time = 0.05 + (hash(char) % 150) / 1000
            time.sleep(hold_time)
            
            # Simulate key release
            self.keystroke_data.record_key_release(char)
            
            # Simulate inter-key delay (100-300ms)
            if i < len(passphrase) - 1:
                delay = 0.1 + (hash(passphrase[i:i+2]) % 200) / 1000
                time.sleep(delay)
                
        sequence = self.keystroke_data.finish_typing()
        print(f"✓ Simulated {len(sequence)} keystroke events")
        return sequence

def collect_keystroke_data(username: str, num_samples: int = 10, use_real_time: bool = True) -> bool:
    """
    Collect keystroke data for a user
    Args:
        username: Username for the user
        num_samples: Number of samples to collect
        use_real_time: Whether to use real-time collection (requires pynput)
    """
    print(f"\n=== Collecting Keystroke Data for {username} ===")
    print(f"Collecting {num_samples} samples...")
    
    if use_real_time and PYNPUT_AVAILABLE:
        collector = RealTimeKeystrokeCollector()
    else:
        if use_real_time:
            print("Warning: pynput not available, using simulation mode")
        collector = SimulatedKeystrokeCollector()
        
    all_sequences = []
    
    for sample in range(num_samples):
        print(f"\nSample {sample + 1}/{num_samples}")
        
        if use_real_time and PYNPUT_AVAILABLE:
            # Real-time collection
            if not collector.start_collection():
                return False
                
            input("Press Enter when you've finished typing your passphrase...")
            sequence = collector.stop_collection()
            
        else:
            # Simulated collection
            passphrase = input("Enter your passphrase: ")
            if not passphrase:
                print("Error: Passphrase cannot be empty")
                continue
                
            sequence = collector.collect_sequence(passphrase)
            
        if sequence:
            all_sequences.append(sequence)
            print(f"✓ Sample {sample + 1} collected successfully")
        else:
            print(f"✗ Sample {sample + 1} failed")
            
    if len(all_sequences) >= 3:  # Minimum samples required
        print(f"\n✓ Successfully collected {len(all_sequences)} samples for {username}")
        return True
    else:
        print(f"\n✗ Insufficient samples collected ({len(all_sequences)}/3 minimum)")
        return False

def main():
    """Main function for testing keystroke collection"""
    print("=== Keystroke Data Collection Utility ===")
    
    username = input("Enter username: ").strip()
    if not username:
        print("Error: Username cannot be empty")
        return
        
    num_samples = input("Number of samples (default 10): ").strip()
    try:
        num_samples = int(num_samples) if num_samples else 10
    except ValueError:
        num_samples = 10
        
    use_real_time = input("Use real-time collection? (Y/n): ").strip().lower()
    use_real_time = use_real_time != 'n'
    
    success = collect_keystroke_data(username, num_samples, use_real_time)
    
    if success:
        print(f"\n✓ Keystroke data collection completed for {username}")
    else:
        print(f"\n✗ Keystroke data collection failed for {username}")

if __name__ == "__main__":
    main()

