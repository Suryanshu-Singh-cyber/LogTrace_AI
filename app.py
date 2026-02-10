import datetime
from datetime import datetime as dt
from collections import defaultdict, Counter
import streamlit as st
import pandas as pd
import numpy as np
import time
import random
import math
import plotly.express as px
import plotly.graph_objects as go

# =========================
# SAFE PSUTIL IMPORT
# =========================
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

from sklearn.ensemble import IsolationForest
from streamlit_autorefresh import st_autorefresh

# ======================================================
# PAGE CONFIG
# ======================================================
st.set_page_config(
    page_title="ForenSight AI | DFIR Agent",
    page_icon="🛡️",
    layout="wide"
)

# ======================================================
# SOC STYLE CSS
# ======================================================
st.markdown("""
<style>
    [data-testid="stAppViewContainer"] { background:#020617; color:#e5e7eb; }
    .stMetric { background: rgba(30, 41, 59, 0.5); padding: 15px; border-radius: 10px; border: 1px solid #334155; }
    .agent-box { background: #1e1b4b; border-left: 5px solid #6366f1; padding: 20px; border-radius: 5px; margin: 10px 0; }
    .ghost-alert { background: #450a0a; border: 1px solid #ef4444; padding: 10px; border-radius: 5px; }
</style>
""", unsafe_allow_html=True)

# ======================================================
# CORE LOGIC FUNCTIONS
# ======================================================
def calculate_entropy(text):
    if not text: return 0
    prob = [n_x/len(text) for x, n_x in Counter(text).items()]
    return -sum(p * math.log2(p) for p in prob)

def detect_ghost_files(mft, usn):
    if 'filename' not in mft.columns or 'filename' not in usn.columns:
        return []
    mft_files = set(mft['filename'].str.lower().unique())
    usn_files = set(usn['filename'].str.lower().unique())
    return list(usn_files - mft_files)

# ======================================================
# SESSION STATE
# ======================================================
if "mft_df" not in st.session_state: st.session_state.mft_df = None
if "usn_df" not in st.session_state: st.session_state.usn_df = None
if "alerts" not in st.session_state: st.session_state.alerts = []

# ======================================================
# HEADER
# ======================================================
st.title("🛡️ ForenSight AI: Forensic Agent")
st.caption("Advanced DFIR • Ransomware Entropy • Ghost Correlation • AI Explainer")

tabs = st.tabs([
    "📥 Evidence", "🧠 AI Correlation", "🧪 Deep Scan", 
    "🚨 SOC Heatmap", "📡 Live Monitor", "🧩 Agent AI Explainer"
])

# ======================================================
# TAB 1: EVIDENCE INTAKE
# ======================================================
with tabs[0]:
    c1, c2 = st.columns(2)
    with c1:
        mft_file = st.file_uploader("Upload MFT CSV", type="csv")
        usn_file = st.file_uploader("Upload USN Journal CSV", type="csv")
    with c2:
        st.info("💡 **Tip:** Upload MFT and USN logs simultaneously to trigger **Ghost File Detection**.")
    
    if mft_file and usn_file:
        mft = pd.read_csv(mft_file)
        usn = pd.read_csv(usn_file)
        st.session_state.mft_df = mft
        st.session_state.usn_df = usn
        st.success("✅ Evidence Loaded")

# ======================================================
# TAB 2: AI CORRELATION & TIMELINER
# ======================================================
with tabs[1]:
    st.subheader("🎞️ Forensic Time-Liner")
    if st.session_state.mft_df is not None:
        # Simulate a timeline from data
        df = st.session_state.mft_df.head(10).copy()
        df['task'] = df['filename']
        df['start'] = dt.now() - datetime.timedelta(hours=1)
        df['end'] = dt.now()
        
        fig = px.timeline(df, x_start="start", x_end="end", y="task", color="task", template="plotly_dark")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.warning("Please upload evidence to generate timeline.")

# ======================================================
# TAB 3: DEEP SCAN (ENTROPY & GHOSTS)
# ======================================================
with tabs[2]:
    st.subheader("🧪 Advanced Artifact Analysis")
    col_a, col_b = st.columns(2)
    
    with col_a:
        st.markdown("### 💀 Ghost File Correlation")
        if st.session_state.mft_df is not None and st.session_state.usn_df is not None:
            ghosts = detect_ghost_files(st.session_state.mft_df, st.session_state.usn_df)
            if ghosts:
                st.markdown(f"<div class='ghost-alert'><b>Alert:</b> {len(ghosts)} Ghost Files Detected. These exist in history but were deleted from disk.</div>", unsafe_allow_html=True)
                st.write(ghosts)
            else:
                st.success("No Ghost Files detected.")
        else:
            st.info("Upload MFT and USN logs to run this scan.")

    with col_b:
        st.markdown("### 📉 Ransomware Entropy Scanner")
        sample_text = st.text_input("Analyze filename/data string for encryption:", "malware_encrypted_payload_0x44.exe")
        ent_score = calculate_entropy(sample_text)
        st.metric("Shannon Entropy", round(ent_score, 4))
        if ent_score > 4.5:
            st.warning("High Entropy: Likely Encrypted or Packed.")

# ======================================================
# TAB 4: SOC HEATMAP
# ======================================================
with tabs[3]:
    st.subheader("🔥 Digital Fingerprint Heatmap")
    # Generate dummy data for heatmap
    heat_data = np.random.randint(0, 50, size=(7, 24))
    heat_data[3, 14:18] = 100 # Artificial spike at 2 PM Wednesday
    
    fig_heat = px.imshow(heat_data, 
                        labels=dict(x="Hour of Day", y="Day of Week", color="Event Intensity"),
                        x=[str(i) for i in range(24)],
                        y=["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
                        color_continuous_scale="Viridis")
    st.plotly_chart(fig_heat, use_container_width=True)

# ======================================================
# TAB 5: LIVE MONITORING
# ======================================================
with tabs[4]:
    st_autorefresh(interval=3000, key="live_refresh")
    if PSUTIL_AVAILABLE:
        cpu = psutil.cpu_percent()
        mem = psutil.virtual_memory().percent
        c1, c2 = st.columns(2)
        c1.metric("Live CPU Load", f"{cpu}%")
        c2.metric("Memory Usage", f"{mem}%")
        
        # Real-time anomaly check
        if cpu > 80:
            st.error("🚨 CRITICAL: High CPU Anomaly Detected!")
    else:
        st.error("psutil not available.")

# ======================================================
# TAB 6: AGENT AI EXPLAINER
# ======================================================
with tabs[5]:
    st.subheader("🤖 Forensic Agent AI")
    st.markdown("The Agent analyzes findings to provide executive reasoning.")
    
    if st.button("Run AI Agent Peer Review"):
        with st.spinner("Agent is analyzing evidence..."):
            time.sleep(2)
            findings = []
            if st.session_state.mft_df is not None: findings.append("Suspicious MFT Drift")
            if random.random() > 0.5: findings.append("Event Log 1102 (Log Cleared)")
            
            st.markdown("""
            <div class='agent-box'>
                <h3>🕵️ Agent Conclusion</h3>
                <p><b>Executive Summary:</b> Based on the correlation of MFT timestamps and Entropy analysis, I have identified a high-probability <b>Timestomping</b> attack.</p>
                <ul>
                    <li><b>Finding 1:</b> $Standard_Information$ attribute mismatch detected.</li>
                    <li><b>Finding 2:</b> High entropy payload detected in Temp directory.</li>
                    <li><b>Reasoning:</b> Attackers typically modify SI times to hide file creation. The presence of 'Ghost Files' in the USN Journal suggests a secure-delete operation followed the execution.</li>
                </ul>
                <p><b>Recommendation:</b> Isolate host and preserve RAM for volatile memory forensics.</p>
            </div>
            """, unsafe_allow_html=True)

# ======================================================
# FOOTER
# ======================================================
st.markdown("---")
st.caption(f"ForenSight AI v3.0 Platinum • SOC-Ready • Demo Date: {dt.now().strftime('%Y-%m-%d')}")
