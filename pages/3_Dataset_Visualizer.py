import streamlit as st
import pandas as pd
import plotly.express as px

# Page Title
st.title("📊 Dataset Visualizer")

# Load the dataset
DATA_PATH = "data/synthetic_detailed_logs.csv"

try:
    df = pd.read_csv(DATA_PATH)
    st.write("### Dataset Preview")
    st.dataframe(df)

    # Define default columns (update these based on your dataset)
    label_column = "label"  # Replace with the actual column name for labels
    ip_source_column = "source_ip"  # Replace with the actual column name for IP sources
    ip_dest_column = "dest_ip"  # Replace with the actual column name for IP destinations
    status_column = "status"  # Replace with the actual column name for statuses
    service_column = "process"  # Replace with the actual column name for services
    host_column = "hostname"  # Replace with the actual column name for hosts

    # Donut Chart for Labels
    st.subheader("Label Distribution")
    label_counts = df[label_column].value_counts()
    fig_label = px.pie(
        names=label_counts.index,
        values=label_counts.values,
        title="Label Distribution",
        hole=0.4,
    )
    st.plotly_chart(fig_label)

    # Bar Chart for IP Sources
    st.subheader("IP Source Distribution")
    ip_source_counts = df[ip_source_column].value_counts().head(10)
    fig_ip_source = px.bar(
        x=ip_source_counts.index,
        y=ip_source_counts.values,
        labels={"x": "IP Source", "y": "Count"},
        title="Top 10 IP Sources",
    )
    st.plotly_chart(fig_ip_source)

    # Bar Chart for IP Destinations
    st.subheader("IP Destination Distribution")
    ip_dest_counts = df[ip_dest_column].value_counts().head(10)
    fig_ip_dest = px.bar(
        x=ip_dest_counts.index,
        y=ip_dest_counts.values,
        labels={"x": "IP Destination", "y": "Count"},
        title="Top 10 IP Destinations",
    )
    st.plotly_chart(fig_ip_dest)

    # Bar Chart for Status
    st.subheader("Status Distribution")
    status_counts = df[status_column].value_counts()
    fig_status = px.bar(
        x=status_counts.index,
        y=status_counts.values,
        labels={"x": "Status", "y": "Count"},
        title="Status Distribution",
    )
    st.plotly_chart(fig_status)

    # Bar Chart for Services
    st.subheader("Service Distribution")
    service_counts = df[service_column].value_counts().head(10)
    fig_service = px.bar(
        x=service_counts.index,
        y=service_counts.values,
        labels={"x": "Service", "y": "Count"},
        title="Top 10 Services",
    )
    st.plotly_chart(fig_service)

    # Bar Chart for Hosts
    st.subheader("Host Distribution")
    host_counts = df[host_column].value_counts().head(10)
    fig_host = px.bar(
        x=host_counts.index,
        y=host_counts.values,
        labels={"x": "Host", "y": "Count"},
        title="Top 10 Hosts",
    )
    st.plotly_chart(fig_host)

except FileNotFoundError:
    st.error(f"Dataset not found at {DATA_PATH}. Please ensure the file exists.")