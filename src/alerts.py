"""
alerts.py: AlertManager for anomaly alerts with severity grouping, rich console, JSON save, desktop notifications.
"""

import pandas as pd
import json
from datetime import datetime
from typing import Optional
from collections import defaultdict
import rich.console
from rich.table import Table
from rich import box
from plyer import notification

class AlertManager:
    """
    Manages alerts from anomalous events.
    """
    HIGH_EVENT_IDS = [4720, 4740]  # new account, lockout
    MEDIUM_EVENT_IDS = [4672, 4625]

    def __init__(self):
        self.console = rich.console.Console()
        self.alerts = []

    def process_anomalies(self, anomalies_df: pd.DataFrame):
        """
        Process anomalies: assign severity, print table, save JSON, notify HIGH.
        """
        if anomalies_df.empty:
            print("No anomalies to process.")
            return
        
        # Group severity
        anomalies_df = anomalies_df.copy()
        anomalies_df['severity'] = 'LOW'
        anomalies_df.loc[anomalies_df['event_id'].isin(self.HIGH_EVENT_IDS), 'severity'] = 'HIGH'
        
        # MEDIUM: 4625/4672 count >5 /hour per IP
        anomalies_df['timestamp_dt'] = pd.to_datetime(anomalies_df['timestamp'])
        anomalies_df['hour'] = anomalies_df['timestamp_dt'].dt.floor('H')
        medium_counts = anomalies_df[anomalies_df['event_id'].isin(self.MEDIUM_EVENT_IDS)].groupby(['source_ip', 'hour'])['event_id'].size()
        medium_ips_hours = medium_counts[medium_counts > 5].index
        mask_medium = anomalies_df.set_index(['source_ip', 'hour']).index.isin(medium_ips_hours)
        anomalies_df.loc[anomalies_df['event_id'].isin(self.MEDIUM_EVENT_IDS) & mask_medium, 'severity'] = 'MEDIUM'
        
        self.alerts = anomalies_df[['timestamp', 'severity', 'event_id', 'username', 'source_ip']].to_dict('records')
        
        # Print rich table
        self.print_alert_table(anomalies_df)
        
        # Save JSON
        self.save_json()
        
        # HIGH notification
        high_alerts = [a for a in self.alerts if a['severity'] == 'HIGH']
        if high_alerts:
            self.notify_high(high_alerts)

    def print_alert_table(self, df: pd.DataFrame):
        """Print formatted rich table."""
        table = Table(title="Anomaly Alerts", box=box.ROUNDED)
        table.add_column("Timestamp", style="cyan")
        table.add_column("Severity", style="bold magenta")
        table.add_column("Event ID", style="green")
        table.add_column("Username", style="yellow")
        table.add_column("IP", style="blue")
        
        for _, row in df.iterrows():
            table.add_row(
                str(row['timestamp']),
                row['severity'],
                str(row['event_id']),
                str(row['username']),
                str(row['source_ip'])
            )
        self.console.print(table)

    def save_json(self):
        """Save alerts to data/alerts.json."""
        output_path = 'data/alerts.json'
        with open(output_path, 'w') as f:
            json.dump(self.alerts, f, indent=2, default=str)
        print(f"Alerts saved to {output_path}")

    def notify_high(self, high_alerts: list):
        """Send desktop notification for HIGH alerts."""
        title = f"HIGH Severity Alert - {len(high_alerts)} events"
        message = "\\n".join([f"Event {a['event_id']} for {a['username']} from {a['source_ip']}" for a in high_alerts[:3]])
        notification.notify(
            title=title,
            message=message,
            app_name="Log Anomaly Detector",
            timeout=10
        )
