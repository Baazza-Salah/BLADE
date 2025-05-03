import streamlit as st

# Set page configuration
st.set_page_config(
    page_title="BLADE - Insider Threat Detection",
    page_icon="🛡️",
    layout="wide"
)

# Main Title
st.title("🛡️ BLADE: Insider Threat Detection & Dashboard")

# Project Description
st.markdown(
    """
    Welcome to **BLADE** (Behavioral Log Analysis for Detecting Exploits), a powerful tool for real-time **Insider Threat Detection**.  
    This application leverages **machine learning** and **log analysis** to help security teams identify and respond to suspicious activities effectively.

    ### Key Features:
    - **Logs Dashboard**: Monitor Linux system logs in real-time and visualize key metrics.
    - **Test Model**: Perform ad-hoc classification of log entries to detect potential threats.
    - **Dataset Visualizer**: Explore and analyze the dataset with interactive visualizations.

    ### How to Use:
    Use the **sidebar** to navigate between the following sections:
    - **Logs Dashboard**: Real-time monitoring and visualization of log data.
    - **Test Model**: Upload or paste log entries to classify them as benign or threats.
    - **Dataset Visualizer**: Gain insights into the dataset with charts and summaries.

    ---
    **Note**: Ensure your dataset and pre-trained model are properly configured before using the application.
    """
)