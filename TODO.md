# Windows Log Anomaly Detector - Implementation TODO

## Planned Steps (from approved plan):

- [x] Populate requirements.txt with pywin32, pandas, scikit-learn, streamlit, pytz
- [x] Create src/log_reader.py with header comment and stubs (read_logs, parse_log_events)
- [x] Create src/anomaly_detector.py with header comment and stubs (train_model, detect_anomalies)
- [x] Create src/dashboard.py with header comment and stubs (run_dashboard)
- [x] Create src/alerts.py with header comment and stubs (send_alert, setup_alert_channel)
- [x] Create main.py with header comment, imports, and basic entrypoint calling all modules
- [x] Install dependencies: pip install -r requirements.txt 
- [ ] Test main.py with LogReader
- [x] Fix syntax and test LogReader standalone
- [x] Implement LogReader class in src/log_reader.py
- [x] Update main.py to use LogReader
- [ ] streamlit run src/dashboard.py

Updated after each step.
