"""
anomaly_detector.py: Implements anomaly detection on log data using Isolation Forest.
Features: failed logins per IP/hour, login hour, off-hours, unique users per IP.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
from typing import Optional

class AnomalyDetector:
    """
    AnomalyDetector for Windows log events.
    """
    def __init__(self, contamination: float = 0.05):
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.scaler = StandardScaler()
        self.contamination = contamination
        self.is_fitted = False
        self.feature_cols = None

    def fit(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Engineer features and train model. Returns labeled df.
        Saves model to model/isolation_forest.pkl
        """
        if df.empty:
            print("Empty df for fit, using dummy model.")
            dummy_features = np.array([[0, 12, 0, 1]] )  # dummy
            self.scaler.fit(dummy_features)
            self.model.fit(self.scaler.transform(dummy_features))
            self.feature_cols = ['failed_login_count', 'login_hour', 'is_off_hours', 'unique_usernames_per_ip']
            self.is_fitted = True
            joblib.dump({'model': self.model, 'scaler': self.scaler, 'feature_cols': self.feature_cols}, 'model/isolation_forest.pkl')
            return pd.DataFrame(columns=['label'])

        # 1. Timestamp to dt
        df = df.copy()
        df['timestamp_dt'] = pd.to_datetime(df['timestamp'], errors='coerce')

        # 2. Features
        df['login_hour'] = df['timestamp_dt'].dt.hour.fillna(12)
        df['is_off_hours'] = ~df['login_hour'].between(9, 17)
        
        # Failed per IP per hour
        df_failed = df[df['status'] == 'failed'].copy()
        df_failed['hour'] = df_failed['timestamp_dt'].dt.floor('H')
        failed_count = df_failed.groupby(['source_ip', 'hour'])['event_id'].size().reset_index(name='failed_login_count')
        df = df.merge(failed_count, on=['source_ip', 'hour'], how='left').fillna({'failed_login_count': 0})
        
        # Unique usernames per IP
        unique_users = df.groupby('source_ip')['username'].nunique().reset_index(name='unique_usernames_per_ip')
        df = df.merge(unique_users, on='source_ip', how='left').fillna({'unique_usernames_per_ip': 1})
        
        features = df[['failed_login_count', 'login_hour', 'is_off_hours', 'unique_usernames_per_ip']].copy()
        features['is_off_hours'] = features['is_off_hours'].astype(int)
        
        # Scale fit
        scaled_features = self.scaler.fit_transform(features)
        self.model.fit(scaled_features)
        
        self.feature_cols = features.columns.tolist()
        self.is_fitted = True
        
        # Save model
        joblib.dump({'model': self.model, 'scaler': self.scaler, 'feature_cols': self.feature_cols}, 'model/isolation_forest.pkl')
        print("Model trained and saved to model/isolation_forest.pkl")
        
        # Label all rows
        anomaly_scores = self.model.decision_function(scaled_features)
        predictions = self.model.predict(scaled_features)
        df['anomaly_score'] = anomaly_scores
        df['label'] = np.where(predictions == -1, 'anomaly', 'normal')
        
        return df

    def detect(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Detect anomalies, return only anomalous rows with score.
        """
        if not self.is_fitted:
            raise ValueError("Model not fitted. Call fit first.")
        
        df = df.copy()
        df['timestamp_dt'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df['login_hour'] = df['timestamp_dt'].dt.hour.fillna(12)
        df['is_off_hours'] = ~df['login_hour'].between(9, 17)
        
        df_failed = df[df['status'] == 'failed'].copy()
        df_failed['hour'] = df_failed['timestamp_dt'].dt.floor('H')
        failed_count = df_failed.groupby(['source_ip', 'hour'])['event_id'].size().reset_index(name='failed_login_count')
        df = df.merge(failed_count, on=['source_ip', 'hour'], how='left').fillna({'failed_login_count': 0})
        
        unique_users = df.groupby('source_ip')['username'].nunique().reset_index(name='unique_usernames_per_ip')
        df = df.merge(unique_users, on='source_ip', how='left').fillna({'unique_usernames_per_ip': 1})
        
        features = df[self.feature_cols].copy()
        features['is_off_hours'] = features['is_off_hours'].astype(int)
        
        scaled_features = self.scaler.transform(features)
        anomaly_scores = self.model.decision_function(scaled_features)
        predictions = self.model.predict(scaled_features)
        
        df['anomaly_score'] = anomaly_scores
        df['label'] = np.where(predictions == -1, 'anomaly', 'normal')
        
        anomalies = df[df['label'] == 'anomaly'].copy()
        return anomalies[['timestamp', 'event_id', 'source_ip', 'username', 'logon_type', 'status', 'anomaly_score', 'label']] 
