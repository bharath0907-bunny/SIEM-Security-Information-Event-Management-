#!/usr/bin/env python3
# ==============================================================================
# Enterprise SIEM & Threat Detection Platform - AI Model Trainer
# ==============================================================================
# Description: Generates synthetic baseline data representing typical corporate
#              network activity, trains an Isolation Forest model, and saves it.
# ==============================================================================

import os
import pickle
# pyrefly: ignore [missing-import]
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Ensure models directory exists
MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
os.makedirs(MODEL_DIR, exist_ok=True)

MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")

def generate_synthetic_baseline(n_samples=2000):
    """
    Generates synthetic profile representing NORMAL behavior:
    - login_hour: 8 AM to 6 PM (8.0 - 18.0)
    - login_duration: 10 mins to 480 mins (8 hours max)
    - failed_attempts: mostly 0, occasionally 1 or 2
    - data_transmitted: 50 KB to 50 MB (50 - 50000 KB)
    - cpu_utilization: 5% to 50%
    - ram_utilization: 20% to 60%
    """
    np.random.seed(42)
    
    # Hour of day (normal distribution around 13:00 / 1 PM)
    login_hour = np.random.normal(loc=13, scale=3, size=n_samples)
    login_hour = np.clip(login_hour, 0, 23)
    
    # Login duration
    login_duration = np.random.exponential(scale=120, size=n_samples) + 10
    login_duration = np.clip(login_duration, 5, 600)
    
    # Failed attempts (skewed heavily towards 0)
    failed_attempts = np.random.choice([0, 1, 2, 3], size=n_samples, p=[0.85, 0.10, 0.04, 0.01])
    
    # Data volume (KB)
    data_transmitted = np.random.lognormal(mean=8, sigma=1.5, size=n_samples)
    data_transmitted = np.clip(data_transmitted, 10, 100000)
    
    # CPU & RAM percentages
    cpu_utilization = np.random.beta(a=2, b=5, size=n_samples) * 100
    ram_utilization = np.random.normal(loc=40, scale=10, size=n_samples)
    ram_utilization = np.clip(ram_utilization, 10, 95)
    
    df = pd.DataFrame({
        'login_hour': login_hour,
        'login_duration': login_duration,
        'failed_attempts': failed_attempts,
        'data_transmitted': data_transmitted,
        'cpu_utilization': cpu_utilization,
        'ram_utilization': ram_utilization
    })
    
    print(f"[*] Generated {n_samples} normal behavior baseline records.")
    return df

def train_and_save():
    # 1. Get baseline dataset (normal + synthetic anomalies)
    normal_data = generate_synthetic_baseline()
    anomaly_data = generate_synthetic_anomalies()
    data = pd.concat([normal_data, anomaly_data], ignore_index=True)
    print(f"[*] Combined dataset size: {len(data)} (normal + anomalies)")
    
    # 2. Scale features
    scaler = StandardScaler()
    scaled_data = scaler.fit_transform(data.values)

    
    # 3. Initialize and fit Isolation Forest
    # Contamination set to 0.05% for stricter anomaly detection
    model = IsolationForest(
        n_estimators=200,
        max_samples='auto',
        contamination=0.02,
        random_state=42,
        n_jobs=-1
    )
    
    print("[*] Training Isolation Forest model...")
    model.fit(scaled_data)
    
    # 4. Save artifacts
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    with open(SCALER_PATH, 'wb') as f:
        pickle.dump(scaler, f)
        
    print(f"[+] Model successfully saved to: {MODEL_PATH}")
    print(f"[+] Scaler successfully saved to: {SCALER_PATH}")
    
    # Verify anomaly thresholds
    test_normal = np.array([[12.0, 60.0, 0, 1000, 15.0, 45.0]]) # Noon, 60m duration, 0 fails, 1MB, low CPU/RAM
    test_anomaly = np.array([[2.0, 5.0, 15, 80000, 95.0, 90.0]]) # 2 AM, 15 failed logins, 80MB data, high CPU
    
    scaled_normal = scaler.transform(test_normal)
    scaled_anomaly = scaler.transform(test_anomaly)
    
    pred_normal = model.predict(scaled_normal)[0]
    pred_anomaly = model.predict(scaled_anomaly)[0]
    
    score_normal = model.decision_function(scaled_normal)[0]
    score_anomaly = model.decision_function(scaled_anomaly)[0]
    
    print("\n--- Model Test Verification ---")
    print(f"Normal Case  -> Class: {pred_normal} (+1 is normal, -1 is anomaly) | Score: {score_normal:.4f}")
    print(f"Anomaly Case -> Class: {pred_anomaly} (+1 is normal, -1 is anomaly) | Score: {score_anomaly:.4f}")
    if pred_anomaly == -1:
        print("[INFO] Anomaly correctly detected in test.")
    else:
        print("[WARN] Anomaly NOT detected; consider adjusting contamination.")

def generate_synthetic_anomalies(n_samples=600):
    """Generate synthetic anomalous behavior for training.
    - login_hour: unusual times (0-4 or 22-23)
    - login_duration: very short or extremely long
    - failed_attempts: high counts (10-20)
    - data_transmitted: very high volumes
    - cpu_utilization and ram_utilization: very high percentages
    """
    np.random.seed(99)
    # Extreme hours (choose from 0-4 and 22-23)
    hour_choices = np.concatenate([np.arange(0, 5), np.arange(22, 24)])
    login_hour = np.random.choice(hour_choices, size=n_samples)
    # Duration extremes (1 minute or 12 hours)
    login_duration = np.random.choice([1, 720], size=n_samples)
    # High failed attempts
    failed_attempts = np.random.randint(10, 21, size=n_samples)
    # Data transmitted huge (50MB to 200MB in KB)
    data_transmitted = np.random.uniform(50000, 200000, size=n_samples)
    # CPU & RAM high (80% to 100%)
    cpu_utilization = np.random.uniform(80, 100, size=n_samples)
    ram_utilization = np.random.uniform(80, 100, size=n_samples)
    df = pd.DataFrame({
        'login_hour': login_hour,
        'login_duration': login_duration,
        'failed_attempts': failed_attempts,
        'data_transmitted': data_transmitted,
        'cpu_utilization': cpu_utilization,
        'ram_utilization': ram_utilization
    })
    print(f"[*] Generated {n_samples} anomalous records for training.")
    return df

if __name__ == '__main__':
    train_and_save()

