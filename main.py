"""
main.py: CLI entrypoint for Windows Log Anomaly Detector.
Supports --mode detect/dashboard with rich output & ASCII banner.
"""

import os
import argparse
import sys
from rich.console import Console
from rich.panel import Panel
from rich import print as rprint
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

from src.log_reader import LogReader
from src.anomaly_detector import AnomalyDetector
from src.alerts import AlertManager

BANNER = """
  ███╗   ███╗███╗   ███╗███████╗███╗   ██╗███████╗██████╗ 
  ████╗ ████║████╗ ████║██╔════╝████╗  ██║██╔════╝██╔══██╗
  ██╔████╔██║██╔████╔██║███████╗██╔██╗ ██║█████╗  ██████╔╝
  ██║╚██╔╝██║██║╚██╔╝██║╚════██║██║╚██╗██║██╔══╝  ██╔══██╗
  ██║ ╚═╝ ██║██║ ╚═╝ ██║███████║██║ ╚████║███████╗██║  ██║
  ╚═╝     ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
"""

console = Console()

def status_success(msg):
    console.print(f"[green]✓ {msg}[/green]")

def status_warning(msg):
    console.print(f"[yellow]⚠ {msg}[/yellow]")

def status_error(msg):
    console.print(f"[red]✗ {msg}[/red]")

def generate_dummy_data():
    from datetime import datetime, timedelta
    import pandas as pd
    now = datetime.now()
    n = 100
    dummy_df = pd.DataFrame({
        'timestamp': pd.date_range(now - timedelta(hours=2), now, periods=n),
        'event_id': [4624, 4625]* (n//2),
        'source_ip': ['192.168.1.' + str(i%10) for i in range(n)],
        'username': ['user' + str(i%5) for i in range(n)],
        'logon_type': [2, 10] * (n//2),
        'status': ['success', 'failed'] * (n//2)
    })
    return dummy_df

def run_detect():
    console.print(Panel.fit(BANNER, title="Windows Log Anomaly Detector", border_style="green"))
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), 
                  console=console) as progress:
        task = progress.add_task("Initializing...", total=None)
        
        log_df = None
        progress.update(task, description="Reading Security logs...")
        try:
            log_reader = LogReader()
            log_df = log_reader.read_events()
            status_success(f"Loaded {len(log_df)} real events")
            progress.advance(task)
        except Exception as e:
            if "1314" in str(e) or "privilege" in str(e).lower():
                status_warning("Run as Administrator for real Security log data. Using dummy data for demo...")
                log_df = generate_dummy_data()
                status_success(f"Loaded {len(log_df)} demo events")
            else:
                status_error(f"Log error: {e}")
                progress.remove_task(task)
                return
            progress.advance(task)
        
        # Detect
        progress.update(task, description="Running anomaly detection...")
        detector = AnomalyDetector(contamination=0.05)
        detector.fit(log_df)
        anomalies = detector.detect(log_df)
        status_success(f"Detected {len(anomalies)} anomalies")
        progress.advance(task)
        
        # Alert
        progress.update(task, description="Processing alerts...")
        alert_mgr = AlertManager()
        alert_mgr.process_anomalies(anomalies)
        status_success("Alerts processed & saved")
        progress.advance(task)
        
        # Export
        try:
            log_reader.export_baseline()
            status_success("Baseline exported")
        except:
            status_warning("Export skipped")
        
        progress.update(task, description="Complete!")
        status_success("Detection pipeline finished successfully")

def run_dashboard():
    console.print(Panel.fit(BANNER, title="Dashboard Mode", border_style="cyan"))
    status_success("Launching Streamlit dashboard...")
    os.system("python -m streamlit run src/dashboard.py")
    status_success("Dashboard launched (open http://localhost:8501)")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Windows Log Anomaly Detector")
    parser.add_argument("--mode", choices=["detect", "dashboard"], default="detect", 
                       help="Mode: detect (pipeline) or dashboard (UI)")
    args = parser.parse_args()
    
    if args.mode == "detect":
        run_detect()
    else:
        run_dashboard()

