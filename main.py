"""
main.py: Entry point for the Windows Log Anomaly Detector.
Orchestrates log reading, anomaly detection, alerting, and dashboard.
"""

from src.log_reader import read_logs, parse_log_events
from src.anomaly_detector import train_model, detect_anomalies
from src.alerts import send_alert, setup_alert_channel
from src.dashboard import run_dashboard

def main():
    """Run the full pipeline."""
    print("Starting Windows Log Anomaly Detector...")
    
    # Read logs
    print("Reading logs...")
    log_df = read_logs("System")
    
    # Parse
    parsed_df = parse_log_events([{}])  # Stub call
    
    # Train model (stub)
    model, scaler = train_model(parsed_df)
    
    # Detect
    anomalies = detect_anomalies(parsed_df, model, scaler)
    
    # Alert
    setup_alert_channel("console")
    send_alert(anomalies)
    
    # Dashboard
    # run_dashboard()  # Uncomment to launch
    
    print("Pipeline complete.")

if __name__ == "__main__":
    main()
