import streamlit as st

st.set_page_config(page_title="Insider Threat App", layout="wide")
st.title("Insider Threat Detection & Dashboard")
st.markdown(
    """
    Welcome to the Insider Threat Dashboard!  
    Use the sidebar to navigate:  
    - **Logs Dashboard**: real-time monitoring  
    - **Test Model**: ad-hoc classification of log lines
    """
)