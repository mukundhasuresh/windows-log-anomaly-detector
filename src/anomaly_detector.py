"""
anomaly_detector.py: Implements anomaly detection on log data using Isolation Forest.
Features: failed logins per IP/hour, login hour, off-hours, unique users per IP.
Handles dummy data without 'hour' column issues.
"""

import pandas as pd
import numpy as np
import os
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
from typing import Optional
from datetime import datetime

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

    def _extract_hour(self, timestamp_dt):
        """Helper to extract hour floor for merge."""
        return timestamp_dt.dt.floor('h')

    def fit(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Engineer features and train model. Returns labeled df.
        """
        if df.empty:
            print("Empty df for fit, using dummy model.")
            dummy_features = np.random.random((10, 4))
            self.scaler.fit(dummy_features)
            self.model.fit(self.scaler.transform(dummy_features))
            self.feature_cols = ['failed_login_count', 'login_hour', 'is_off_hours', 'unique_usernames_per_ip']
            self.is_fitted = True
            os.makedirs('model', exist_ok=True)
            joblib.dump({'model': self.model, 'scaler': self.scaler, 'feature_cols': self.feature_cols}, 'model/isolation_forest.pkl')
            return pd.DataFrame(columns=df.columns.tolist() + ['anomaly_score', 'label'])

        # Safe copy and dt parse
        df = df.copy()
        df['timestamp_dt'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df = df.dropna(subset=['timestamp_dt'])

        if df.empty:
            return pd.DataFrame(columns=df.columns.tolist() + ['anomaly_score', 'label'])

        # Features: login_hour, is_off_hours
        df['login_hour'] = df['timestamp_dt'].dt.hour
        df['is_off_hours'] = ((df['login_hour'] < 9) | (df['login_hour'] > 17)).astype(int)
        df['hour'] = self._extract_hour(df['timestamp_dt'])
        
        # Failed login count per IP per hour
        df_failed = df[df['status'] == 'failed'].copy()
        df['failed_login_count'] = 0
        if not df_failed.empty:
            failed_grp = df_failed.groupby(['source_ip', 'hour'])['event_id'].size().reset_index(name='failed_login_count')
            merged = df.merge(failed_grp[['source_ip', 'hour', 'failed_login_count']], 
                              on=['source_ip', 'hour'], how='left', suffixes=('', '_merge'))
            df.loc[merged.index, 'failed_login_count'] = merged['failed_login_count_merge'].fillna(0)
        
        # Unique users per IP
        unique_users = df.groupby('source_ip')['username'].nunique().reset_index(name='unique_usernames_per_ip')
        df = df.merge(unique_users, on='source_ip', how='left')
        df['unique_usernames_per_ip'] = df['unique_usernames_per_ip'].fillna(1)
        
        # Select features
        feature_cols = ['failed_login_count', 'login_hour', 'is_off_hours', 'unique_usernames_per_ip']
        features = df[feature_cols].fillna(0)
        
        # Train
        scaled_features = self.scaler.fit_transform(features)
        self.model.fit(scaled_features)
        self.feature_cols = feature_cols
        self.is_fitted = True
        
        # Save
        os.makedirs('model', exist_ok=True)
        joblib.dump({'model': self.model, 'scaler': self.scaler, 'feature_cols': self.feature_cols}, 'model/isolation_forest.pkl')
        print("Model saved")
        
        # Scores
        anomaly_scores = self.model.decision_function(scaled_features)
        predictions = self.model.predict(scaled_features)
        df['anomaly_score'] = anomaly_scores
        df['label'] = np.where(predictions == -1, 'anomaly', 'normal')
        return df

    def detect(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Detect anomalies.
        """
        if not self.is_fitted:
            raise ValueError("Fit model first")
        
        if df.empty:
            return pd.DataFrame(columns=['timestamp', 'event_id', 'source_ip', 'username', 'logon_type', 'status', 'anomaly_score', 'label'])
        
        df = df.copy()
        df['timestamp_dt'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df = df.dropna(subset=['timestamp_dt'])
        
        if df.empty:
            return pd.DataFrame(columns=['timestamp', 'event_id', 'source_ip', 'username', 'logon_type', 'status', 'anomaly_score', 'label'])
        
        df['login_hour'] = df['timestamp_dt'].dt.hour
        df['is_off_hours'] = ((df['login_hour'] < 9) | (df['login_hour'] > 17)).astype(int)
        df['hour'] = self._extract_hour(df['timestamp_dt'])
        
        df['failed_login_count'] = 0
        df_failed = df[df['status'] == 'failed'].copy()
        if not df_failed.empty:
            failed_grp = df_failed.groupby(['source_ip', 'hour'])['event_id'].size().reset_index(name='failed_login_count')
            merged = df.merge(failed_grp[['source_ip', 'hour', 'failed_login_count']], 
                              on=['source_ip', 'hour'], how='left', suffixes=('', '_merge'))
            df.loc[merged.index, 'failed_login_count'] = merged['failed_login_count_merge'].fillna(0)
        
        unique_users = df.groupby('source_ip')['username'].nunique().reset_index(name='unique_usernames_per_ip')
        df = df.merge(unique_users, on='source_ip', how='left')
        df['unique_usernames_per_ip'] = df['unique_usernames_per_ip'].fillna(1)
        
        features = df[self.feature_cols].fillna(0)
        scaled_features = self.scaler.transform(features)
        anomaly_scores = self.model.decision_function(scaled_features)
        predictions = self.model.predict(scaled_features)
        
        df['anomaly_score'] = anomaly_scores
        df['label'] = np.where(predictions == -1, 'anomaly', 'normal')
        
        anomalies = df[df['label'] == 'anomaly'][['timestamp', 'event_id', 'source_ip', 'username', 'logon_type', 'status', 'anomaly_score', 'label']]
        if anomalies.empty:
            anomalies = pd.DataFrame(columns=['timestamp', 'event_id', 'source_ip', 'username', 'logon_type', 'status', 'anomaly_score', 'label'])
        return anomalies

