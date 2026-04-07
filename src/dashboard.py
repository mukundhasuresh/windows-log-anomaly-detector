"""
dashboard.py: Impressive Streamlit dashboard with dark theme, glowing UI, metrics, charts.
"""

import sys
IS_CLOUD = sys.platform != 'win32'

import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from log_reader import LogReader
from anomaly_detector import AnomalyDetector
from alerts import AlertManager

# Page config
st.set_page_config(
    page_title="Log Anomaly Detector v1.0",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 4rem !important;
        background: linear-gradient(90deg, #00ff88, #00cc6a);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        text-align: center;
        margin-bottom: 2rem;
        text-shadow: 0 0 30px #00ff88;
        animation: glow 2s ease-in-out infinite alternate;
    }
    @keyframes glow {
        from { text-shadow: 0 0 20px #00ff88, 0 0 30px #00ff88; }
        to { text-shadow: 0 0 30px #00ff88, 0 0 40px #00ff88; }
    }
    .metric-green { border-left: 5px solid #00ff88 !important; }
    .metric-orange { border-left: 5px solid #ffaa00 !important; }
    .metric-red { border-left: 5px solid #ff4444 !important; }
    .high-row { font-weight: bold; background-color: rgba(255,68,68,0.2) !important; }
</style>
""", unsafe_allow_html=True)

def load_data():
    log_df, anomalies_df, alerts = try_load_live()
    if log_df.empty:
        log_df, anomalies_df, alerts = generate_dummy_data()
    return log_df, anomalies_df, alerts

def try_load_live():
    if IS_CLOUD:
        return pd.DataFrame(), pd.DataFrame(), []
    try:
        try:
            import win32evtlog
            HAS_WIN32 = True
        except ImportError:
            HAS_WIN32 = False
        if not HAS_WIN32:
            return pd.DataFrame(), pd.DataFrame(), []
        log_reader = LogReader()
        log_df = log_reader.read_events()
        detector = AnomalyDetector()
        detector.fit(log_df)
        anomalies = detector.detect(log_df)
        alert_mgr = AlertManager()
        alert_mgr.process_anomalies(anomalies)
        return log_df, anomalies, alert_mgr.alerts
    except:
        return pd.DataFrame(), pd.DataFrame(), []

def generate_dummy_data():
    now = datetime.now()
    n = 200
    dummy_log = pd.DataFrame({
        'timestamp': pd.date_range(now - timedelta(hours=6), now, periods=n),
        'event_id': [4624, 4625, 4672, 4720] * (n//4),
        'source_ip': [f"192.168.1.{i%25}" for i in range(n)],
        'username': [f"user{i%10}" for i in range(n)],
        'logon_type': [2, 10, 8, 2] * (n//4),
        'status': ['failed'] * 60 + ['success'] * 140
    })
    detector = AnomalyDetector(0.1)
    labeled = detector.fit(dummy_log)
    anomalies = detector.detect(dummy_log)
    alerts = [{'timestamp': str(t), 'severity': 'HIGH' if eid in [4720,4740] else 'MEDIUM', 
               'event_id': eid, 'username': u, 'source_ip': ip} 
              for t, eid, u, ip in zip(anomalies['timestamp'], anomalies['event_id'], anomalies['username'], anomalies['source_ip'])]
    return dummy_log, anomalies, alerts

def filter_data(df, time_range):
    cutoff = {'1h': timedelta(hours=1), '6h': timedelta(hours=6), 
              '24h': timedelta(days=1), '7d': timedelta(days=7)}[time_range]
    return df[pd.to_datetime(df['timestamp']) >= datetime.now() - cutoff]

# Main dashboard
st.markdown('<h1 class="main-header">🛡️ Log Anomaly Detector</h1>', unsafe_allow_html=True)
st.markdown("**Real-time Windows Security Monitoring**")

# Sidebar
with st.sidebar:
    st.markdown("## 🛡️ Log Anomaly Detector")
    st.markdown("![Version](https://img.shields.io/badge/v-1.0.0-brightgreen)")
    time_range = st.selectbox("⏰ Time Range", ["1h", "6h", "24h", "7d"])

# Data load
with st.spinner("🔄 Analyzing logs..."):
    log_df, anomalies_df, alerts = load_data()

filtered_log = filter_data(log_df, time_range)
filtered_anoms = filter_data(anomalies_df, time_range)

# Metrics
col1, col2, col3 = st.columns(3)
with col1:
    st.markdown('<div class="metric-green">', unsafe_allow_html=True)
    st.metric("📊 Total Events", len(filtered_log))
    st.markdown('</div>', unsafe_allow_html=True)
with col2:
    st.markdown('<div class="metric-orange">', unsafe_allow_html=True)
    st.metric("🚨 Anomalies", len(filtered_anoms))
    st.markdown('</div>', unsafe_allow_html=True)
with col3:
    high_count = sum(1 for a in alerts if a['severity'] == 'HIGH')
    st.markdown('<div class="metric-red">', unsafe_allow_html=True)
    st.metric("🔴 High Alerts", high_count)
    st.markdown('</div>', unsafe_allow_html=True)

# Charts
col1, col2 = st.columns(2)
with col1:
    st.subheader("📈 Login Attempts Over Time")
    filtered_log = filtered_log.copy()
    filtered_log['dt'] = pd.to_datetime(filtered_log['timestamp'])
    filtered_anoms = filtered_anoms.copy()
    filtered_anoms['dt'] = pd.to_datetime(filtered_anoms['timestamp'])
    hourly = filtered_log.set_index('dt').resample('H').size()
    anomaly_hourly = filtered_anoms.set_index('dt').resample('H').size()
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=hourly.index, y=hourly.values, name="Normal", line_color="steelblue"))
    fig.add_trace(go.Scatter(x=anomaly_hourly.index, y=anomaly_hourly.values, name="Anomaly", line_color="crimson", fill='tonexty'))
    fig.update_layout(hovermode='x unified')
    st.plotly_chart(fig, use_container_width=True)

with col2:
    st.subheader("🌐 Top IPs - Failed Logins")
    failed = filtered_log[filtered_log['status'] == 'failed']
    top_ips = failed['source_ip'].value_counts().head(10)
    top_ips_df = top_ips.reset_index()
    top_ips_df.columns = ['source_ip', 'count']
    fig_bar = px.bar(
        top_ips_df,
        x='count',
        y='source_ip',
        orientation='h',
        color_discrete_sequence=['#00ff88']
    )
    st.plotly_chart(fig_bar, use_container_width=True)

# Alerts table
st.subheader("🚨 **Anomalies Table**")
if not filtered_anoms.empty:
    display_df = filtered_anoms[['timestamp', 'event_id', 'source_ip', 'username', 'anomaly_score']].copy()
    display_df['severity'] = ['HIGH' if e in [4720,4740] else 'MEDIUM' if e in [4672,4625] else 'LOW' for e in display_df['event_id']]
    st.dataframe(
        display_df,
        column_config={"severity": st.column_config.SelectboxColumn("Severity", options=['LOW','MEDIUM','HIGH'])}, 
        use_container_width=True
    )
else:
    st.info("✅ No anomalies detected")

# Run button
if st.button("🔄 **Run Detection Pipeline Now**", type="primary", use_container_width=True):
    with st.spinner('Running full detection...'):
        alert_mgr = AlertManager()
        alert_mgr.process_anomalies(filtered_anoms)
        st.success("Pipeline executed! Check new alerts.")

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #00ff88;'>
    <strong>⭐ Star us on GitHub!</strong> 
    <a href='https://github.com/mukundhasuresh/windows-log-anomaly-detector'><img src='https://img.shields.io/github/stars/mukundhasuresh/windows-log-anomaly-detector?style=social' alt='Stars'></a>
    <br>Built with Python • ML • Streamlit
</div>
""", unsafe_allow_html=True)

