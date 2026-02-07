import streamlit as st

st.set_page_config(page_title="LogTrace AI", layout="wide")

st.title("🔍 LogTrace AI – Anti-Forensic Detection")

st.metric("Suspicion Score", 95)

st.subheader("🚨 Detected Issues")
st.error("Possible NTFS timestomping detected")
st.warning("Windows Event Log was cleared (Event ID 1102)")

st.subheader("🧠 Forensic Explanation")
st.write("""
LogTrace AI detected inconsistencies between NTFS timestamps
and USN Journal activity. Additionally, Windows Event Logs
were cleared, indicating possible anti-forensic techniques.
""")
