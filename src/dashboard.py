"""
dashboard.py: Streamlit dashboard for log anomalies.
Sidebar filters, metrics, charts, pipeline trigger.
"""

import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# Local imports
from src.log_reader import LogReader
from src.anomaly_detector import AnomalyDetector
from src.alerts import AlertManager

def load_data():
    """Load or simulate data for dashboard."""
    try:
        log_reader = LogReader()
        log_df = log_reader.read_events()
        detector = AnomalyDetector(0.05)
        detector.fit(log_df)
        anomalies = detector.detect(log_df)
        alert_mgr = AlertManager()
        alert_mgr.process_anomalies(anomalies)
        return log_df, anomalies, alert_mgr.alerts
    except Exception as e:
        st.warning(f"Live data error (admin needed): {e}. Using dummy data.")
        # Dummy data
        now = datetime.now()
        dummy_log = pd.DataFrame({
            'timestamp': pd.date_range(now - timedelta(hours=6), now, periods=100),
            'event_id': [4624, 4625]*50,
            'source_ip': ['192.168.1.' + str(i%10) for i in range(100)],
            'username': ['user' + str(i%5) for i in range(100)],
            'logon_type': [2, 10]*50,
            'status': ['success', 'failed']*50
        })
        dummy_detector = AnomalyDetector(0.05)
        dummy_labeled = dummy_detector.fit(dummy_log)
        dummy_anomalies = dummy_detector.detect(dummy_log)
        dummy_alerts = [{'timestamp': t, 'severity': 'LOW', 'event_id': 4625, 'username': u, 'source_ip': ip} 
                       for t, u, ip in zip(dummy_anomalies['timestamp'][:3], dummy_anomalies['username'][:3], dummy_anomalies['source_ip'][:3])]
        return dummy_log, dummy_anomalies, dummy_alerts

def filter_by_time(df: pd.DataFrame, time_range: str):
    """Filter df by time range."""
    now = datetime.now()
    if time_range == "1h":
        cutoff = now - timedelta(hours=1)
    elif time_range == "6h":
        cutoff = now - timedelta(hours=6)
    elif time_range == "24h":
        cutoff = now - timedelta(days=1)
    elif time_range == "7d":
        cutoff = now - timedelta(days=7)
    df_filtered = df[df['timestamp'] >= cutoff]
    return df_filtered

def main():
    st.set_page_config(page_title="Log Anomaly Detector", layout="wide")
    st.title("🛡️ Windows Log Anomaly Detector Dashboard")
    
    # Sidebar
    st.sidebar.header("Filters")
    time_range = st.sidebar.selectbox("Time Range", ["1h", "6h", "24h", "7d"])
    
    # Load data
    with st.spinner("Loading logs & running detection..."):
        log_df, anomalies_df, alerts = load_data()
    
    filtered_log = filter_by_time(log_df, time_range)
    filtered_anomalies = filter_by_time(anomalies_df, time_range)
    
    # Metrics
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Events", len(filtered_log))
    with col2:
        st.metric("Anomalies Found", len(filtered_anomalies), delta=f"{len(filtered_anomalies)/len(filtered_log)*100:.1f}%")
    with col3:
        high_alerts = sum(1 for a in alerts if a.get('severity') == 'HIGH')
        st.metric("High Severity Alerts", high_alerts)
    
    # Charts row 1
    col1, col2 = st.columns(2)
    
    # Line chart: logins over time
    with col1:
        st.subheader("Login Attempts Over Time")
        filtered_log['timestamp_dt'] = pd.to_datetime(filtered_log['timestamp'])
        filtered_log.set_index('timestamp_dt', inplace=True)
        hourly_counts = filtered_log.resample('H').size()
        anomaly_hourly = filtered_anomalies.set_index(pd.to_datetime(filtered_anomalies['timestamp'])).resample('H').size()
        
        fig_line = go.Figure()
        fig_line.add_trace(go.Scatter(x=hourly_counts.index, y=hourly_counts.values, name="Normal", line=dict(color='blue')))
        fig_line.add_trace(go.Scatter(x=anomaly_hourly.index, y=anomaly_hourly.values, name="Anomaly", line=dict(color='red')))
        fig_line.update_layout(hovermode='x unified')
        st.plotly_chart(fig_line, use_container_width=True)
    
    # Bar: top IPs failed
    with col2:
        st.subheader("Top 10 IPs by Failed Logins")
        failed_logs = filtered_log[filtered_log['status'] == 'failed']
        ip_failed = failed_logs.groupby('source_ip').size().sort_values(ascending=False).head(10)
        fig_bar = px.bar(x=ip_failed.values, y=ip_failed.index, orientation='h', 
                        title="Failed Logins", color=ip_failed.values)
        st.plotly_chart(fig_bar, use_container_width=True)
    
    # Anomalies table
    st.subheader("Anomalous Events")
    
    # Severity color
    def severity_color(severity):
        if severity == 'HIGH': return 'background-color: #ff4444'
        elif severity == 'MEDIUM': return 'background-color: #ffaa00'
        elif severity == 'LOW': return 'background-color: #ffff44'
        return ''
    
    if not filtered_anomalies.empty:
        # Add severity to anomalies (reuse logic)
        filtered_anomalies['severity'] = 'LOW'
        filtered_anomalies.loc[filtered_anomalies['event_id'].isin([4720, 4740]), 'severity'] = 'HIGH'
        # Simplified medium (for display)
        medium_mask = (filtered_anomalies['event_id'].isin([4672, 4625])) & (filtered_anomalies.duplicated(['source_ip'], keep=False))
        filtered_anomalies.loc[medium_mask, 'severity'] = 'MEDIUM'
        
        st.dataframe(
            filtered_anomalies[['timestamp', 'severity', 'event_id', 'source_ip', 'username', 'logon_type', 'anomaly_score']],
            column_config={
                "severity": st.column_config.SelectboxColumn("Severity", options=["LOW", "MEDIUM", "HIGH"]),
                "anomaly_score": st.column_config.NumberColumn("Score", format="%.3f")
            },
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No anomalies in selected time range.")
    
    # Run button
    st.subheader("Manual Detection")
    if st.button("🔄 Run Detection Now", type="primary"):
        with st.spinner("Running full pipeline..."):
            alert_mgr = AlertManager()
            alert_mgr.process_anomalies(filtered_anomalies)
            st.success("Detection complete! Check alerts table.")

if __name__ == "__main__":
    main()
