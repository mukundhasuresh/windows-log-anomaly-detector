# Windows Log Anomaly Detector

![Python](https://img.shields.io/badge/Python-3.9+-blue)
![ML](https://img.shields.io/badge/ML-IsolationForest-green)
![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-red)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)

> ML-powered security tool that detects anomalies in Windows Event Logs in real time.

## Screenshot
![Dashboard Preview](data/screenshot.png)

## Features
- Reads Windows Security Event Logs (Event IDs 4624, 4625, 4672, 4720, 4740)
- Isolation Forest ML model for anomaly detection
- Severity-based alerting (HIGH / MEDIUM / LOW)
- Windows desktop notifications for HIGH alerts
- Interactive Streamlit dashboard with live charts
- CLI interface for automation

## Installation
```bash
pip install -r requirements.txt
```

## Usage
```bash
# Run detection once
python main.py --mode detect

# Launch dashboard
python main.py --mode dashboard
```

**Note:** Run as Administrator for real Security log access

## How It Works
1. LogReader pulls Windows Security events via pywin32
2. AnomalyDetector engineers features (failed logins/hour, off-hours activity, unique IPs)
3. Isolation Forest flags statistical outliers as anomalies
4. AlertManager classifies severity and sends notifications
5. Streamlit dashboard visualizes everything in real time

## Tech Stack
- Python + pywin32 for Windows Event Log access
- scikit-learn Isolation Forest for ML detection
- Streamlit for interactive dashboard
- rich for beautiful CLI output
- plyer for Windows desktop notifications
