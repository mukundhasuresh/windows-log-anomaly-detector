"""
main.py: Entry point for the Windows Log Anomaly Detector.
Orchestrates log reading, anomaly detection, alerting, and dashboard.
"""

import pandas as pd
from src.log_reader import LogReader
from src.anomaly_detector import train_model, detect_anomalies
from src.alerts import send_alert, setup_alert_channel
from src.dashboard import run_dashboard

def main():
    """Run the full pipeline."""
    print("Starting Windows Log Anomaly Detector...")
    
    # Read logs using LogReader
    print("Reading Security logs...")
    log_reader = LogReader()
    try:
        parsed_df = log_reader.read_events()
        print(f"Loaded {len(parsed_df)} Security events.")
    except PermissionError as e:
        print(str(e))
        parsed_df = pd.DataFrame(columns=['timestamp', 'event_id', 'source_ip', 'username', 'logon_type', 'status'])
        print("Using dummy DataFrame (run as admin for real logs).")
    except Exception as e:
        print(f"Log read error: {e}")
        parsed_df = pd.DataFrame()
    
    # Train model (stub - handles empty df)
    print("Training model...")
    model, scaler = train_model(parsed_df)
    
    # Detect
    print("Detecting anomalies...")
    anomalies = detect_anomalies(parsed_df, model, scaler)
    
    # Alert
    setup_alert_channel("console")
    if isinstance(anomalies, pd.DataFrame) and len(anomalies) > 0:
        send_alert(anomalies)
    else:
        print("No anomalies to alert (stubs).")
    
    # Export baseline
    try:
        log_reader.export_baseline()
    except:
        print("Export skipped.")
    
    # Dashboard
    # run_dashboard()  # Uncomment to launch
    
    print("Pipeline complete.")

if __name__ == "__main__":
    main()
