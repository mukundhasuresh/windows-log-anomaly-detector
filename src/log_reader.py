"""
log_reader.py: Reads Windows event logs using pywin32, parses them into pandas DataFrames for analysis.
Handles different log types like System, Application, Security.
"""

import pandas as pd
import re
from typing import List, Dict
import datetime

try:
    import win32evtlog
    import win32evtlogutil
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False

class LogReader:
    """
    Windows Security Log Reader using pywin32.
    Filters specific Event IDs for anomaly detection baseline.
    """

    TARGET_EVENT_IDS = [4624, 4625, 4672, 4720, 4740]

    def __init__(self, log_type: str = "Security"):
        self.log_type = log_type

    def read_events(self, max_count: int = 10000) -> pd.DataFrame:
        """
        Read and parse Security events into DataFrame.
        
        Columns: timestamp, event_id, source_ip, username, logon_type, status
        
        Handles permission/empty logs.
        """
        if not HAS_WIN32:
            raise RuntimeError('Windows only - pywin32 required')
        events_data = []
        try:
            hand = win32evtlog.OpenEventLog(None, self.log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            total = 0
            while total < max_count:
                event_list = win32evtlog.ReadEventLog(hand, flags, 0)
                if not event_list:
                    break
                for event in event_list:
                    if event.EventID in self.TARGET_EVENT_IDS:
                        timestamp = str(event.TimeGenerated)
                        event_id = event.EventID
                        try:
                            message = win32evtlogutil.SafeFormatMessage(event, hand)
                        except:
                            message = ''
                        
                        # Regex parse Security event fields
                        username_match = re.search(r'Account Name[:\\-]?\\s*([^\\r\\n\\s]+(?:\\\\[^\\\\\\r\\n]+)?)', message, re.I)
                        username = username_match.group(1) if username_match else ''
                        
                        ip_match = re.search(r'(?:Source Network Address|IpAddress|Network Address)[:\\-]?\\s*([0-9a-f.:]+)', message, re.I)
                        source_ip = ip_match.group(1) if ip_match else ''
                        
                        logon_match = re.search(r'Logon Type[:\\-]?\\s*(\\d+)', message, re.I)
                        logon_type = int(logon_match.group(1)) if logon_match else 0
                        
                        status = 'failed' if event_id == 4625 else 'success'
                        
                        events_data.append({
                            'timestamp': timestamp,
                            'event_id': event_id,
                            'source_ip': source_ip,
                            'username': username,
                            'logon_type': logon_type,
                            'status': status
                        })
                        total += 1
                        if total >= max_count:
                            break
            win32evtlog.CloseEventLog(hand)
        except Exception as e:
            if 'access denied' in str(e).lower() or 'permission' in str(e).lower():
                raise PermissionError(f"Permission denied for {self.log_type} log. Run as Administrator.")
            raise Exception(f"Error reading logs: {e}")
        
        df = pd.DataFrame(events_data)
        if df.empty:
            print("No matching Security events found in recent logs.")
        return df

    def export_baseline(self, max_count: int = 10000):
        """
        Export filtered events to data/baseline_events.csv
        """
        df = self.read_events(max_count)
        output_path = 'data/baseline_events.csv'
        df.to_csv(output_path, index=False)
        print(f"Exported {len(df)} events to {output_path}")
