"""
main.py: Entry point for the Windows Log Anomaly Detector.
Orchestrates log reading, anomaly detection, alerting, and dashboard.
"""

import pandas as pd
from src.log_reader import LogReader
from src.anomaly_detector import AnomalyDetector
from src.alerts import AlertManager
from src.dashboard import run_dashboard

def main():
    """Run the full pipeline."""
    print("Starting Windows Log Anomaly Detector...")
    
    # Read logs
    print("Reading Security logs...")
    log_reader = LogReader()
    try:
        log_df = log_reader.read_events()
        print(f"Loaded {len(log_df)} Security events.")
    except PermissionError as e:
        print(str(e))
        log_df = pd.DataFrame(columns=['timestamp', 'event_id', 'source_ip', 'username', 'logon_type', 'status'])
        print("Using dummy DataFrame (run as admin for real logs).")
    except Exception as e:
        print(f"Log read error: {e}")
        log_df = pd.DataFrame()
    
    # Anomaly detection
    print("Fitting anomaly detector...")
    detector = AnomalyDetector(contamination=0.05)
    labeled_df = detector.fit(log_df)
    
    print("Detecting anomalies...")
    anomalies = detector.detect(log_df)
    
    # Alerts
    alert_manager = AlertManager()
    alert_manager.process_anomalies(anomalies)
    
    # Export
    try:
        log_reader.export_baseline()
    except:
        print("Export skipped.")
    
    print("Pipeline complete.")

if __name__ == "__main__":
    main()

