import streamlit as st
import pandas as pd
import plotly.express as px
import time
from utils import classify_log, LogHandler
from watchdog.observers import Observer

st.title("🚨 Real-time Log Monitoring & Anomaly Detection")

log_file = st.text_input("Log file path", "/var/log/auth.log")
if not log_file:
    st.warning("Please enter a log file path.")
    st.stop()

buffer = []
handler = LogHandler(log_file, buffer)
observer = Observer()
observer.schedule(handler, path=log_file, recursive=False)
observer.start()

placeholder = st.empty()
chart_placeholder = st.empty()

try:
    while True:
        if buffer:
            df = pd.DataFrame([classify_log(line) for line in buffer])
            buffer.clear()
            # show table
            placeholder.dataframe(df)
            # pie chart
            counts = df['label'].value_counts().reset_index()
            counts.columns = ['label','count']
            fig = px.pie(counts, names='label', values='count', title='Batch Label Distribution')
            chart_placeholder.plotly_chart(fig, use_container_width=True)
        time.sleep(2)
except KeyboardInterrupt:
    observer.stop()
observer.join()