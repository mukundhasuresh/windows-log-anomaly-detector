"""
dashboard.py: Streamlit-based web dashboard to visualize logs, anomalies, and alerts.
Displays charts, tables, real-time updates.
"""

import streamlit as st
import pandas as pd
import plotly.express as px

def run_dashboard():
    """
    Launch the Streamlit dashboard.
    Run with: streamlit run src/dashboard.py
    """
    st.title("Windows Log Anomaly Detector")
    st.write("Dashboard stub - to be implemented.")
    # TODO: Load data, show charts, anomaly highlights
    pass

if __name__ == "__main__":
    run_dashboard()
