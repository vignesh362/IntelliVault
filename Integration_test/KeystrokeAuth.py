#!/usr/bin/env python3
"""
Keystroke Dynamics Authentication Module
Based on the methodology from: https://github.com/nikhilagr/User-Authentication-using-keystroke-dynamics
"""

import json
import time
import numpy as np
import pandas as pd
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
import getpass
import sys

class KeystrokeData:
    """Class to handle keystroke timing data collection and processing"""
    
    def __init__(self):
        self.timings = []
        self.current_sequence = []
        self.start_time = None
        
    def start_typing(self):
        """Start recording keystroke timings"""
        self.current_sequence = []
        self.start_time = time.time()
        
    def record_key_press(self, key: str):
        """Record key press event"""
        current_time = time.time()
        if self.start_time is None:
            self.start_time = current_time
            
        self.current_sequence.append({
            'key': key,
            'press_time': current_time,
            'release_time': None,
            'hold_time': None,
            'keydown_keydown': None,
            'keyup_keydown': None
        })
        
    def record_key_release(self, key: str):
        """Record key release event"""
        current_time = time.time()
        
        # Find the most recent press of this key
        for i in range(len(self.current_sequence) - 1, -1, -1):
            if (self.current_sequence[i]['key'] == key and 
                self.current_sequence[i]['release_time'] is None):
                self.current_sequence[i]['release_time'] = current_time
                self.current_sequence[i]['hold_time'] = (
                    current_time - self.current_sequence[i]['press_time']
                )
                break
                
    def finish_typing(self) -> List[Dict]:
        """Finish recording and calculate timing features"""
        if not self.current_sequence:
            return []
            
        # Calculate keydown-keydown and keyup-keydown times
        for i in range(len(self.current_sequence)):
            if i > 0:
                # Keydown-keydown time
                self.current_sequence[i]['keydown_keydown'] = (
                    self.current_sequence[i]['press_time'] - 
                    self.current_sequence[i-1]['press_time']
                )
                
                # Keyup-keydown time (if previous key was released)
                if self.current_sequence[i-1]['release_time'] is not None:
                    self.current_sequence[i]['keyup_keydown'] = (
                        self.current_sequence[i]['press_time'] - 
                        self.current_sequence[i-1]['release_time']
                    )
        
        # Filter out incomplete sequences
        complete_sequence = [
            event for event in self.current_sequence 
            if event['release_time'] is not None
        ]
        
        self.timings.extend(complete_sequence)
        return complete_sequence

class KeystrokeAuthenticator:
    """Main class for keystroke dynamics authentication"""
    
    def __init__(self, data_dir: str = "keystroke_data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        self.model = None
        self.scaler = None
        self.user_profiles = {}
        
    def collect_training_data(self, username: str, num_samples: int = 10) -> bool:
        """
        Collect keystroke training data for a user
        Returns True if successful, False otherwise
        """
        print(f"\n=== Collecting Training Data for {username} ===")
        print(f"Please type the same passphrase {num_samples} times.")
        print("We'll measure your unique typing patterns for authentication.")
        
        passphrase = getpass.getpass("Enter your passphrase: ")
        if not passphrase:
            print("Error: Passphrase cannot be empty")
            return False
            
        keystroke_data = KeystrokeData()
        all_sequences = []
        
        for sample in range(num_samples):
            print(f"\nSample {sample + 1}/{num_samples}")
            print("Type your passphrase now...")
            
            keystroke_data.start_typing()
            
            # Simulate keystroke collection (in real implementation, use keyboard hooks)
            for char in passphrase:
                keystroke_data.record_key_press(char)
                time.sleep(0.1)  # Simulate typing delay
                keystroke_data.record_key_release(char)
                
            sequence = keystroke_data.finish_typing()
            if sequence:
                all_sequences.append(sequence)
                print(f"✓ Collected {len(sequence)} keystroke events")
            else:
                print("✗ Failed to collect keystroke data")
                return False
                
        # Save training data
        self._save_user_data(username, all_sequences)
        print(f"\n✓ Successfully collected {len(all_sequences)} training samples for {username}")
        return True
        
    def _save_user_data(self, username: str, sequences: List[List[Dict]]):
        """Save user keystroke data to file"""
        user_file = self.data_dir / f"{username}_keystroke_data.json"
        
        # Convert to serializable format
        serializable_data = []
        for sequence in sequences:
            serializable_sequence = []
            for event in sequence:
                serializable_sequence.append({
                    'key': event['key'],
                    'hold_time': event['hold_time'],
                    'keydown_keydown': event['keydown_keydown'],
                    'keyup_keydown': event['keyup_keydown']
                })
            serializable_data.append(serializable_sequence)
            
        with open(user_file, 'w') as f:
            json.dump(serializable_data, f, indent=2)
            
    def _load_user_data(self, username: str) -> List[List[Dict]]:
        """Load user keystroke data from file"""
        user_file = self.data_dir / f"{username}_keystroke_data.json"
        
        if not user_file.exists():
            return []
            
        with open(user_file, 'r') as f:
            return json.load(f)
            
    def _extract_features(self, sequences: List[List[Dict]]) -> np.ndarray:
        """Extract features from keystroke sequences"""
        features = []
        
        for sequence in sequences:
            if not sequence:
                continue
                
            # Extract timing features
            hold_times = [event['hold_time'] for event in sequence if event['hold_time'] is not None]
            keydown_keydown = [event['keydown_keydown'] for event in sequence if event['keydown_keydown'] is not None]
            keyup_keydown = [event['keyup_keydown'] for event in sequence if event['keyup_keydown'] is not None]
            
            # Calculate statistical features
            sequence_features = []
            
            # Hold time features
            if hold_times:
                sequence_features.extend([
                    np.mean(hold_times),
                    np.std(hold_times),
                    np.min(hold_times),
                    np.max(hold_times)
                ])
            else:
                sequence_features.extend([0, 0, 0, 0])
                
            # Keydown-keydown features
            if keydown_keydown:
                sequence_features.extend([
                    np.mean(keydown_keydown),
                    np.std(keydown_keydown),
                    np.min(keydown_keydown),
                    np.max(keydown_keydown)
                ])
            else:
                sequence_features.extend([0, 0, 0, 0])
                
            # Keyup-keydown features
            if keyup_keydown:
                sequence_features.extend([
                    np.mean(keyup_keydown),
                    np.std(keyup_keydown),
                    np.min(keyup_keydown),
                    np.max(keyup_keydown)
                ])
            else:
                sequence_features.extend([0, 0, 0, 0])
                
            # Sequence length
            sequence_features.append(len(sequence))
            
            features.append(sequence_features)
            
        return np.array(features)
        
    def train_model(self, username: str) -> bool:
        """Train authentication model for a user"""
        print(f"\n=== Training Model for {username} ===")
        
        # Load user data
        user_sequences = self._load_user_data(username)
        if not user_sequences:
            print(f"Error: No training data found for {username}")
            return False
            
        # Extract features
        X = self._extract_features(user_sequences)
        if len(X) == 0:
            print("Error: No valid features extracted")
            return False
            
        # Create labels (1 for genuine user, 0 for imposter)
        y = np.ones(len(X))  # All samples are from genuine user
        
        # Split data for validation
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        
        # Train multiple models and select the best one
        models = {
            'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42),
            'SVM': SVC(kernel='rbf', random_state=42),
            'Logistic Regression': LogisticRegression(random_state=42),
            'KNN': KNeighborsClassifier(n_neighbors=3)
        }
        
        best_model = None
        best_score = 0
        best_name = ""
        
        for name, model in models.items():
            # Cross-validation
            cv_scores = cross_val_score(model, X_train, y_train, cv=3)
            avg_score = cv_scores.mean()
            
            print(f"{name}: {avg_score:.3f} accuracy")
            
            if avg_score > best_score:
                best_score = avg_score
                best_model = model
                best_name = name
                
        # Train best model on full training set
        best_model.fit(X_train, y_train)
        
        # Test on validation set
        y_pred = best_model.predict(X_test)
        test_accuracy = accuracy_score(y_test, y_pred)
        
        print(f"\nBest model: {best_name}")
        print(f"Validation accuracy: {test_accuracy:.3f}")
        
        # Save model
        model_file = self.data_dir / f"{username}_model.joblib"
        joblib.dump(best_model, model_file)
        
        # Save user profile
        self.user_profiles[username] = {
            'model_file': str(model_file),
            'accuracy': test_accuracy,
            'model_name': best_name
        }
        
        print(f"✓ Model saved for {username}")
        return True
        
    def authenticate_user(self, username: str, passphrase: str) -> Tuple[bool, float]:
        """
        Authenticate a user based on keystroke dynamics
        Returns (is_authentic, confidence_score)
        """
        if username not in self.user_profiles:
            # Load user profile
            model_file = self.data_dir / f"{username}_model.joblib"
            if not model_file.exists():
                return False, 0.0
                
            try:
                model = joblib.load(model_file)
                self.user_profiles[username] = {
                    'model': model,
                    'model_file': str(model_file)
                }
            except:
                return False, 0.0
                
        # Collect keystroke data for authentication
        keystroke_data = KeystrokeData()
        keystroke_data.start_typing()
        
        # Simulate keystroke collection
        for char in passphrase:
            keystroke_data.record_key_press(char)
            time.sleep(0.1)  # Simulate typing delay
            keystroke_data.record_key_release(char)
            
        sequence = keystroke_data.finish_typing()
        if not sequence:
            return False, 0.0
            
        # Extract features
        X = self._extract_features([sequence])
        if len(X) == 0:
            return False, 0.0
            
        # Get model and predict
        model = self.user_profiles[username]['model']
        prediction = model.predict(X)[0]
        confidence = model.predict_proba(X)[0][1] if hasattr(model, 'predict_proba') else 0.5
        
        return bool(prediction), confidence
        
    def register_user(self, username: str) -> bool:
        """Register a new user with keystroke dynamics"""
        print(f"\n=== Registering User: {username} ===")
        
        # Check if user already exists
        if (self.data_dir / f"{username}_keystroke_data.json").exists():
            response = input(f"User {username} already exists. Overwrite? (y/N): ")
            if response.lower() != 'y':
                return False
                
        # Collect training data
        if not self.collect_training_data(username, num_samples=10):
            return False
            
        # Train model
        if not self.train_model(username):
            return False
            
        print(f"✓ User {username} registered successfully!")
        return True
        
    def list_users(self) -> List[str]:
        """List all registered users"""
        users = []
        for file in self.data_dir.glob("*_keystroke_data.json"):
            username = file.stem.replace("_keystroke_data", "")
            users.append(username)
        return users

def main():
    """Main function for testing keystroke authentication"""
    auth = KeystrokeAuthenticator()
    
    while True:
        print("\n=== Keystroke Dynamics Authentication ===")
        print("1. Register new user")
        print("2. Authenticate user")
        print("3. List users")
        print("4. Exit")
        
        choice = input("\nSelect option (1-4): ").strip()
        
        if choice == '1':
            username = input("Enter username: ").strip()
            if username:
                auth.register_user(username)
                
        elif choice == '2':
            username = input("Enter username: ").strip()
            if username:
                passphrase = getpass.getpass("Enter passphrase: ")
                is_authentic, confidence = auth.authenticate_user(username, passphrase)
                
                if is_authentic:
                    print(f"✓ Authentication successful! (Confidence: {confidence:.3f})")
                else:
                    print(f"✗ Authentication failed! (Confidence: {confidence:.3f})")
                    
        elif choice == '3':
            users = auth.list_users()
            if users:
                print("Registered users:")
                for user in users:
                    print(f"  - {user}")
            else:
                print("No users registered")
                
        elif choice == '4':
            break
            
        else:
            print("Invalid option")

if __name__ == "__main__":
    main()

