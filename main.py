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
    """Green success message."""
    console.print(f"[green]✓ {msg}[/green]")

def status_warning(msg):
    """Yellow warning."""
    console.print(f"[yellow]⚠ {msg}[/yellow]")

def status_error(msg):
    """Red error."""
    console.print(f"[red]✗ {msg}[/red]")

def run_detect():
    """Run detection pipeline."""
    console.print(Panel.fit(BANNER, title="Windows Log Anomaly Detector", border_style="green"))
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), 
                  console=console) as progress:
        task = progress.add_task("Initializing...", total=None)
        
        try:
            # Read logs
            progress.update(task, description="Reading Security logs...")
            log_reader = LogReader()
            log_df = log_reader.read_events()
            status_success(f"Loaded {len(log_df)} events")
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
            
            # Export
            try:
                log_reader.export_baseline()
                status_success("Baseline exported")
            except:
                status_warning("Export skipped")
            
            progress.update(task, description="Complete!")
            status_success("Detection pipeline finished successfully")
            
        except PermissionError as e:
            status_warning(str(e))
            status_warning("Run as Administrator for real logs (using dummy)")
        except Exception as e:
            status_error(f"Pipeline error: {e}")
            sys.exit(1)

def run_dashboard():
    """Launch Streamlit dashboard."""
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
