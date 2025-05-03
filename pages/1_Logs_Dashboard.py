import streamlit as st
import pandas as pd
import plotly.express as px
import time
from datetime import datetime
from utils import classify_log, LogHandler
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Initialize session state for historical data
if 'historical_data' not in st.session_state:
    st.session_state.historical_data = pd.DataFrame(columns=['timestamp', 'label', 'message'])

if 'observer_started' not in st.session_state:
    st.session_state.buffer = []
    handler = LogHandler(log_file="/var/log/auth.log", buffer=st.session_state.buffer)
    observer = Observer()
    observer.schedule(handler, path="/var/log/", recursive=False)
    observer.start()
    st.session_state.observer = observer
    st.session_state.observer_started = True

    
st.set_page_config(layout="wide")
st.title("🚨 Real-time Log Monitoring & Anomaly Detection")

log_file = st.text_input("Log file path", "/var/log/auth.log")
if not log_file:
    st.warning("Please enter a log file path.")
    st.stop()

# Dashboard columns
col1, col2 = st.columns([3, 1])
col3, col4 = st.columns(2)

buffer = []
handler = LogHandler(log_file, buffer)
observer = Observer()
observer.schedule(handler, path=log_file, recursive=False)
observer.start()


# Real-time metrics
def update_dashboard():
    if buffer:
        current_time = datetime.now().strftime("%H:%M:%S")
        
        # Process new logs
        new_entries = []
        for line in buffer:
            classification = classify_log(line)
            new_entries.append({
                'timestamp': current_time,
                'label': classification['label'],
                'message': classification['message']
            })
        
        # Update historical data
        new_df = pd.DataFrame(new_entries)
        st.session_state.historical_data = pd.concat(
            [st.session_state.historical_data, new_df],
            ignore_index=True
        )
        buffer.clear()
        
        # Alert for anomalies
        anomalies = new_df[new_df['label'] == 'ANOMALY']
        if not anomalies.empty:
            col2.error(f"🚨 {len(anomalies)} NEW ANOMALIES DETECTED!")
            with st.expander("View Anomalies"):
                st.table(anomalies)
        
        # Update metrics
        col1.metric("Total Logs Processed", len(st.session_state.historical_data))
        col2.metric("Active Anomalies",
        len(st.session_state.historical_data[st.session_state.historical_data['label'] == 'ANOMALY']))
        
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
                (datetime.now() - pd.Timedelta(minutes=30)).strftime("%H:%M:%S")
            ]
            if not time_filtered.empty:
                fig2 = px.histogram(
                    time_filtered[time_filtered['label'] == 'ANOMALY'],
                    x='timestamp',
                    nbins=10,
                    color_discrete_sequence=['#ff4b4b']
                )
                st.plotly_chart(fig2, use_container_width=True)

# Main loop
try:
    while True:
        update_dashboard()
        time.sleep(2)  # Refresh rate
except KeyboardInterrupt:
    observer.stop()
observer.join()