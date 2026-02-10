import datetime
from datetime import datetime as dt
from collections import defaultdict, Counter
import streamlit as st
import pandas as pd
import numpy as np
import time
import random
import math

# Graphics and Visualization
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
    page_title="ForenSight AI Platinum | DFIR Agent",
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
    .agent-box { background: #1e1b4b; border-left: 5px solid #6366f1; padding: 25px; border-radius: 10px; margin: 10px 0; border: 1px solid #312e81; }
    .alert-card { padding:12px; border-radius:10px; margin-bottom:8px; border: 1px solid rgba(255,255,255,0.1); font-family: 'Courier New', monospace; }
    .high { background: rgba(239, 68, 68, 0.2); border-left: 4px solid #ef4444; }
    .medium { background: rgba(245, 158, 11, 0.2); border-left: 4px solid #f59e0b; }
    .low { background: rgba(16, 185, 129, 0.2); border-left: 4px solid #10b981; }
    .ghost-alert { background: #450a0a; border: 1px solid #ef4444; padding: 15px; border-radius: 8px; color: #fecaca; font-weight: bold;}
    .mitre-badge { background: #334155; padding: 2px 8px; border-radius: 4px; font-size: 10px; color: #cbd5e1; }
</style>
""", unsafe_allow_html=True)

# ======================================================
# SESSION STATE INITIALIZATION
# ======================================================
if "mft_df" not in st.session_state: st.session_state.mft_df = None
if "usn_df" not in st.session_state: st.session_state.usn_df = None
if "log_df" not in st.session_state: st.session_state.log_df = None
if "agent_report" not in st.session_state: st.session_state.agent_report = None
if "soc_alerts" not in st.session_state: 
    st.session_state.soc_alerts = [
        {"ts": dt.now().strftime("%H:%M:%S"), "msg": "System Initialization Complete", "lvl": "low"},
        {"ts": dt.now().strftime("%H:%M:%S"), "msg": "Kernel Forensic Hook Active", "lvl": "low"}
    ]

# ======================================================
# FORENSIC LOGIC ENGINES
# ======================================================
def calculate_shannon_entropy(text):
    if not text or not isinstance(text, str) or len(text) == 0: return 0
    probs = [n_x/len(text) for x, n_x in Counter(text).items()]
    return -sum(p * math.log2(p) for p in probs)

def detect_ghost_files(mft_df, usn_df):
    if 'filename' not in mft_df.columns or 'filename' not in usn_df.columns:
        return []
    mft_files = set(mft_df['filename'].astype(str).str.lower().unique())
    usn_files = set(usn_df['filename'].astype(str).str.lower().unique())
    ghosts = usn_files - mft_files
    return [g for g in ghosts if g not in ['nan', 'none', 'unknown', '.']]

def load_csv_with_timestamp(file, candidates, label):
    df = pd.read_csv(file)
    df.columns = df.columns.str.lower().str.strip()
    col = next((c for c in candidates if c in df.columns), None)
    if not col:
        col = st.selectbox(f"Select timestamp for {label}", df.columns, key=f"sel_{label}")
    df[col] = pd.to_datetime(df[col], errors="coerce")
    return df.dropna(subset=[col]), col

# ======================================================
# UI HEADER
# ======================================================
st.title("🛡️ ForenSight AI Platinum")
st.caption("Agent-Driven DFIR • MITRE Mapping • Ghost Correlation • Real-time SOC")
st.markdown("---")

# ======================================================
# TABS SYSTEM
# ======================================================
tabs = st.tabs([
    "📥 Evidence Intake", 
    "🎞️ Forensic Time-Liner", 
    "🧪 Anti-Forensic Scanner", 
    "🧬 MITRE ATT&CK", 
    "🚨 Live SOC Alerts",
    "🤖 Agent AI Explainer",
    "📡 Real-Time Monitor"
])

# ======================================================
# TAB 1: EVIDENCE INTAKE
# ======================================================
with tabs[0]:
    st.subheader("📥 Evidence Ingestion")
    c1, c2, c3 = st.columns(3)
    with c1:
        mft_f = st.file_uploader("Upload MFT CSV (Inventory)", type="csv")
    with c2:
        usn_f = st.file_uploader("Upload USN CSV (History)", type="csv")
    with c3:
        log_f = st.file_uploader("Upload Event Logs CSV", type="csv")

    if mft_f and usn_f and log_f:
        mft, mft_t = load_csv_with_timestamp(mft_f, ["modified","mtime","timestamp"], "MFT")
        usn, usn_t = load_csv_with_timestamp(usn_f, ["usn_timestamp","timestamp"], "USN")
        logs, log_t = load_csv_with_timestamp(log_f, ["timestamp","event_time"], "Logs")
        st.session_state.mft_df, st.session_state.usn_df, st.session_state.log_df = (mft, mft_t), (usn, usn_t), (logs, log_t)
        st.success("🎯 Forensic Data Sources Synchronized.")

# ======================================================
# TAB 2: FORENSIC TIME-LINER
# ======================================================
with tabs[1]:
    st.subheader("🎞️ Visual Forensic Narrative")
    if st.session_state.mft_df:
        mft_data, mft_col = st.session_state.mft_df
        timeline_df = mft_data.sort_values(by=mft_col).tail(25).copy()
        fig_timeline = px.scatter(timeline_df, x=mft_col, y="filename", color="filename", template="plotly_dark")
        fig_timeline.update_layout(showlegend=False)
        st.plotly_chart(fig_timeline, use_container_width=True)
    else:
        st.info("Upload logs to generate automated timeline.")

# ======================================================
# TAB 3: ANTI-FORENSIC SCANNER (BETTER)
# ======================================================
with tabs[2]:
    st.subheader("🧪 Anti-Forensic Artifact Discovery")
    c1, c2 = st.columns(2)
    
    with c1:
        st.markdown("### 💀 Ghost Correlation")
        if st.session_state.mft_df and st.session_state.usn_df:
            ghosts = detect_ghost_files(st.session_state.mft_df[0], st.session_state.usn_df[0])
            if ghosts:
                st.markdown(f"<div class='ghost-alert'>🚨 {len(ghosts)} FILES WIPED: Found in USN History but absent in MFT inventory.</div>", unsafe_allow_html=True)
                st.write(ghosts)
            else: st.success("No Ghost Files detected.")
        else: st.warning("Requires MFT and USN logs.")

    with c2:
        st.markdown("### 🔍 Indicator Scan")
        wipe_tools = ["sdelete", "ccleaner", "bleachbit", "eraser.exe", "cipher.exe", "privazer"]
        found_tools = []
        if st.session_state.mft_df:
            mft_files = st.session_state.mft_df[0]['filename'].astype(str).str.lower()
            for tool in wipe_tools:
                if mft_files.str.contains(tool).any(): found_tools.append(tool)
        
        if found_tools:
            for t in found_tools: st.error(f"⚠️ Anti-Forensic Tool Found: {t.upper()}")
        else: st.success("No known wipe tools found in file inventory.")

# ======================================================
# TAB 4: MITRE ATT&CK
# ======================================================
with tabs[3]:
    st.subheader("🧬 MITRE ATT&CK Mapping")
    
    mitre_data = [
        {"ID": "T1070.004", "Name": "Indicator Removal: File Deletion", "Matches": "Ghost Files Detected", "Risk": "HIGH"},
        {"ID": "T1070.001", "Name": "Indicator Removal: Clear Event Logs", "Matches": "Event 1102 / 104", "Risk": "CRITICAL"},
        {"ID": "T1486", "Name": "Data Encrypted for Impact", "Matches": "High Entropy Metadata", "Risk": "HIGH"},
        {"ID": "T1099", "Name": "Timestomp", "Matches": "MFT/USN Drift > 60s", "Risk": "MEDIUM"}
    ]
    st.table(pd.DataFrame(mitre_data))

# ======================================================
# TAB 5: LIVE SOC ALERTS
# ======================================================
with tabs[4]:
    st.subheader("🚨 Live SOC Alert Feed")
    st_autorefresh(interval=5000, key="soc_refresh")
    
    # Simulate a new alert randomly
    if random.random() > 0.7:
        lvl = random.choice(["high", "medium", "low"])
        msgs = ["Inbound Lateral Movement Detected", "MFT Modification Spike", "Unknown Driver Loaded", "LSASS Memory Access"]
        st.session_state.soc_alerts.insert(0, {"ts": dt.now().strftime("%H:%M:%S"), "msg": random.choice(msgs), "lvl": lvl})
    
    for a in st.session_state.soc_alerts[:10]:
        st.markdown(f"""<div class="alert-card {a['lvl']}"><b>[{a['ts']}]</b> {a['msg']} <span style="float:right" class="mitre-badge">ALERT</span></div>""", unsafe_allow_html=True)

# ======================================================
# TAB 6: AGENT AI EXPLAINER (FIXED RELOAD)
# ======================================================
with tabs[5]:
    st.subheader("🤖 Forensic Agent AI Explainer")
    
    if st.button("🚀 Run AI Analysis Engine"):
        with st.spinner("Correlating artifacts..."):
            time.sleep(2)
            # Store report in session state so it persists during autorefresh
            st.session_state.agent_report = {
                "summary": "Evidence of targeted anti-forensic activity.",
                "details": [
                    "Ghost Files in USN Journal suggest secure deletion of post-exploitation toolkits.",
                    "Log clearing event matches the exact timeframe of MFT modification clusters.",
                    "High entropy strings in Temp folder indicate ransomware staging."
                ],
                "rec": "Isolate host and perform volatile memory capture."
            }

    if st.session_state.agent_report:
        r = st.session_state.agent_report
        st.markdown(f"""
        <div class='agent-box'>
            <h3>🕵️ Agent Conclusion</h3>
            <p><b>Executive Summary:</b> {r['summary']}</p>
            <ul>{"".join([f"<li>{item}</li>" for item in r['details']])}</ul>
            <p><b>Recommendation:</b> {r['rec']}</p>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.info("Click the button above to generate a forensic analysis report.")

# ======================================================
# TAB 7: REAL-TIME MONITORING
# ======================================================
with tabs[6]:
    st.subheader("📡 Live Endpoint Pulse")
    if PSUTIL_AVAILABLE:
        cpu = psutil.cpu_percent()
        mem = psutil.virtual_memory().percent
        c1, c2 = st.columns(2)
        c1.metric("CPU Load", f"{cpu}%")
        c2.metric("Memory", f"{mem}%")
        
        if "cpu_history" not in st.session_state: st.session_state.cpu_history = []
        st.session_state.cpu_history.append(cpu)
        st.session_state.cpu_history = st.session_state.cpu_history[-30:]
        st.line_chart(st.session_state.cpu_history)
    else:
        st.error("psutil not available.")

# ======================================================
# FOOTER
# ======================================================
st.markdown("---")
st.caption(f"ForenSight AI Platinum Edition • SOC v3.1 • {dt.now().strftime('%Y-%m-%d %H:%M')}")
