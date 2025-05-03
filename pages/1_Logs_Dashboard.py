import streamlit as st
import pandas as pd
import plotly.express as px
import subprocess
from datetime import datetime
from utils import classify_log

# Initialize session state for historical data
if 'historical_data' not in st.session_state:
    st.session_state.historical_data = pd.DataFrame(columns=['timestamp', 'label', 'message'])

st.set_page_config(layout="wide")
st.title("🚨 Real-time Log Monitoring & Anomaly Detection")

# Function to fetch the latest logs using `journalctl`
def fetch_latest_logs():
    try:
        # Run the journalctl command to get the latest logs
        result = subprocess.run(
            ["journalctl", "-n", "50", "--no-pager", "--output=short"],  # Fetch the last 50 logs
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode != 0:
            st.error("Failed to fetch logs. Ensure you have the necessary permissions to run `journalctl`.")
            return []
        return result.stdout.splitlines()
    except Exception as e:
        st.error(f"Error fetching logs: {e}")
        return []

# Real-time metrics and dashboard updates
def update_dashboard():
    # Fetch the latest logs
    logs = fetch_latest_logs()
    if logs:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Process logs through the model
        new_entries = []
        for line in logs:
            try:
                classification = classify_log(line)
                # Ensure the classification contains the expected keys
                label = classification.get('label', 'UNKNOWN')
                message = classification.get('message', line)  # Default to the raw log line if 'message' is missing
                new_entries.append({
                    'timestamp': current_time,
                    'label': label,
                    'message': message
                })
            except Exception as e:
                # Handle unexpected errors in classification
                new_entries.append({
                    'timestamp': current_time,
                    'label': 'ERROR',
                    'message': f"Failed to classify log: {line} (Error: {e})"
                })
        
        # Update historical data
        new_df = pd.DataFrame(new_entries)
        st.session_state.historical_data = pd.concat(
            [st.session_state.historical_data, new_df],
            ignore_index=True
        )
        
        # Display anomalies
        anomalies = new_df[new_df['label'] == 'ANOMALY']
        if not anomalies.empty:
            st.error(f"🚨 {len(anomalies)} NEW ANOMALIES DETECTED!")
            with st.expander("View Anomalies"):
                st.table(anomalies)
        
        # Update metrics
        col1.metric("Total Logs Processed", len(st.session_state.historical_data))
        col2.metric("Active Anomalies", len(st.session_state.historical_data[st.session_state.historical_data['label'] == 'ANOMALY']))
        
        # Visualizations
        with col3:
            st.subheader("Real-time Distribution")
            fig1 = px.pie(
                st.session_state.historical_data, 
                names='label', 
                hole=0.3,
                color_discrete_sequence=px.colors.qualitative.Pastel
            )
            st.plotly_chart(fig1, use_container_width=True)
        
        with col4:
            st.subheader("Anomaly Trend (Last 30 mins)")
            time_filtered = st.session_state.historical_data[
                st.session_state.historical_data['timestamp'] >= 
                (datetime.now() - pd.Timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S")
            ]
            if not time_filtered.empty:
                fig2 = px.histogram(
                    time_filtered[time_filtered['label'] == 'ANOMALY'],
                    x='timestamp',
                    nbins=10,
                    color_discrete_sequence=['#ff4b4b']
                )
                st.plotly_chart(fig2, use_container_width=True)
        
        # Add a table to display all system logs and their labels
        st.subheader("All System Logs")
        st.dataframe(st.session_state.historical_data)

# Dashboard layout
col1, col2 = st.columns([3, 1])
col3, col4 = st.columns(2)

# Main loop
try:
    update_dashboard()
except Exception as e:
    st.error(f"An error occurred: {e}")