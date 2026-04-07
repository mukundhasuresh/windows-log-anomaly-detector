"""
anomaly_detector.py: Implements anomaly detection on log data using machine learning (e.g., Isolation Forest from scikit-learn).
Trains models on normal log patterns and detects outliers.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import Optional, Tuple

def train_model(df: pd.DataFrame, contamination: float = 0.1) -> Tuple[IsolationForest, StandardScaler]:
    """
    Train Isolation Forest model on log features.
    
    Args:
        df (pd.DataFrame): Log data with numerical/categorical features.
        contamination (float): Fraction of anomalies.
    
    Returns:
        Tuple[model, scaler]: Trained model and scaler.
    """
    if df.empty:
        # Dummy for stubs
        model = IsolationForest(contamination=contamination)
        scaler = StandardScaler()
        model.fit(np.array([[0]]).reshape(1, -1))  # Dummy fit
        scaler.fit(np.array([[0]]).reshape(1, -1))
        return model, scaler
    
    # Feature engineering stub: numerical features
    features = pd.DataFrame({
        'event_id_num': df['event_id'].astype(float),
        'logon_type_num': df['logon_type'].astype(float),
        'failed_count': (df['status'] == 'failed').astype(int)
    })
    
    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(features.fillna(0))
    
    model = IsolationForest(contamination=contamination, random_state=42)
    model.fit(scaled_features)
    
    return model, scaler

def detect_anomalies(df: pd.DataFrame, model: IsolationForest, scaler: StandardScaler) -> pd.DataFrame:
    """
    Detect anomalies in new log data.
    
    Args:
        df: New log data.
        model: Trained model.
        scaler: Fitted scaler.
    
    Returns:
        pd.DataFrame: Input df with 'anomaly_score' and 'is_anomaly' columns.
    """
    if df.empty:
        df = df.copy()
        df['anomaly_score'] = 0.0
        df['is_anomaly'] = False
        return df
    
    # Same features
    features = pd.DataFrame({
        'event_id_num': df['event_id'].astype(float),
        'logon_type_num': df['logon_type'].astype(float),
        'failed_count': (df['status'] == 'failed').astype(int)
    }).fillna(0)
    
    scaled_features = scaler.transform(features)
    anomaly_scores = model.decision_function(scaled_features)
    is_anomaly = model.predict(scaled_features) == -1
    
    df_out = df.copy()
    df_out['anomaly_score'] = anomaly_scores
    df_out['is_anomaly'] = is_anomaly
    
    return df_out
