import streamlit as st
from utils import classify_log

st.title("🧪 Ad-hoc Log Classification")

user_log = st.text_area("Paste a single log line:")
if st.button("Classify"):
    if not user_log.strip():
        st.error("Please paste a log line to classify.")
    else:
        result = classify_log(user_log)
        st.subheader("Result")
        st.write("**Raw Log:**", result['raw'])
        st.write("**Prediction:**", result['label'])
        st.write("**Confidence:**", f"{result['confidence']:.2f}")