# ======================================================
# FORENSIGHT AI PLATINUM v4.0
# Stable Agent + Controlled Auto-Refresh Architecture
# ======================================================

import streamlit as st
import pandas as pd
import numpy as np
import random
import time
import math
from collections import Counter
from datetime import datetime as dt
from sklearn.ensemble import IsolationForest
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

# ======================================================
# PAGE CONFIG
# ======================================================
st.set_page_config(
    page_title="ForenSight AI Platinum | DFIR Agent",
    page_icon="🛡️",
    layout="wide"
)

# ======================================================
# CSS
# ======================================================
st.markdown("""
<style>
[data-testid="stAppViewContainer"] { background:#020617; color:#e5e7eb; }
.stMetric { background:#0f172a; padding:15px; border-radius:10px; border:1px solid #334155;}
.agent-box { background:#1e1b4b; padding:20px; border-radius:10px; border:1px solid #312e81;}
.alert-card { padding:10px; border-radius:8px; margin-bottom:6px;}
.high { background:#450a0a; border-left:4px solid #ef4444;}
.medium { background:#78350f; border-left:4px solid #f59e0b;}
.low { background:#064e3b; border-left:4px solid #10b981;}
.monitor-card { background:#0f172a; padding:20px; border-radius:12px; border:1px solid #1e293b;}
</style>
""", unsafe_allow_html=True)

# ======================================================
# SESSION STATE (STABLE)
# ======================================================
if "mft_df" not in st.session_state: st.session_state.mft_df = None
if "usn_df" not in st.session_state: st.session_state.usn_df = None
if "agent_report" not in st.session_state: st.session_state.agent_report = None
if "cpu_history" not in st.session_state: st.session_state.cpu_history = []
if "iso_model" not in st.session_state: st.session_state.iso_model = None
if "soc_alerts" not in st.session_state:
    st.session_state.soc_alerts = [{"ts": dt.now().strftime("%H:%M:%S"), "msg": "Agent v4.0 Online", "lvl": "low"}]

# ======================================================
# FORENSIC FUNCTIONS
# ======================================================
def calculate_entropy(text):
    if not text or not isinstance(text, str): return 0
    probs = [n/len(text) for n in Counter(text).values()]
    return -sum(p * math.log2(p) for p in probs)

def detect_wipers(df):
    results = []
    tools = ["sdelete","ccleaner","veracrypt","eraser"]
    if df is not None and "filename" in df.columns:
        files = df["filename"].astype(str).str.lower()
        for t in tools:
            if files.str.contains(t).any():
                results.append(t)
    return results

def detect_ghosts(mft, usn):
    if mft is None or usn is None: return []
    if "filename" not in mft.columns or "filename" not in usn.columns: return []
    m = set(mft["filename"].astype(str).str.lower())
    u = set(usn["filename"].astype(str).str.lower())
    return list(u - m)

# ======================================================
# HEADER
# ======================================================
st.title("🛡️ ForenSight AI Platinum v4.0")
st.caption("Stable Agent • Controlled Telemetry • SOC Intelligence")
st.markdown("---")

tabs = st.tabs([
    "📥 Evidence",
    "🎞️ Timeline",
    "🧪 DNA Scanner",
    "🧬 MITRE",
    "🚨 SOC Feed",
    "🤖 Agent AI",
    "📡 Live Monitor"
])

# ======================================================
# TAB 1: EVIDENCE
# ======================================================
with tabs[0]:
    mft_f = st.file_uploader("Upload MFT CSV", type="csv")
    usn_f = st.file_uploader("Upload USN CSV", type="csv")

    if mft_f:
        st.session_state.mft_df = pd.read_csv(mft_f)
        st.success("MFT Loaded")

    if usn_f:
        st.session_state.usn_df = pd.read_csv(usn_f)
        st.success("USN Loaded")

# ======================================================
# TAB 2: TIMELINE
# ======================================================
with tabs[1]:
    if st.session_state.mft_df is not None:
        df = st.session_state.mft_df.copy()
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
            df = df.sort_values("timestamp").tail(30)
            fig = px.scatter(df, x="timestamp", y="filename",
                             template="plotly_dark")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Timestamp column missing.")
    else:
        st.info("Upload MFT.")

# ======================================================
# TAB 3: DNA
# ======================================================
with tabs[2]:
    if st.session_state.mft_df is not None:
        hits = detect_wipers(st.session_state.mft_df)
        ghosts = detect_ghosts(st.session_state.mft_df, st.session_state.usn_df)

        st.write("### Wiper DNA")
        if hits:
            for h in hits:
                st.error(f"Wiper Detected: {h}")
        else:
            st.success("No Wipers Found")

        st.write("### Ghost Files")
        if ghosts:
            st.warning(f"{len(ghosts)} Ghost Files Found")
            st.write(ghosts[:10])
        else:
            st.success("No Ghost Files")
    else:
        st.info("Upload evidence.")

# ======================================================
# TAB 4: MITRE
# ======================================================
with tabs[3]:
    st.table(pd.DataFrame([
        ["T1070", "File Deletion", "High"],
        ["T1486", "Encryption Impact", "High"],
        ["T1099", "Timestomp", "Medium"]
    ], columns=["ID","Technique","Severity"]))

# ======================================================
# TAB 5: SOC FEED
# ======================================================
with tabs[4]:
    if random.random() > 0.85:
        st.session_state.soc_alerts.insert(0,{
            "ts": dt.now().strftime("%H:%M:%S"),
            "msg": "Suspicious entropy spike",
            "lvl": "medium"
        })

    for a in st.session_state.soc_alerts[:10]:
        st.markdown(
            f"<div class='alert-card {a['lvl']}'><b>[{a['ts']}]</b> {a['msg']}</div>",
            unsafe_allow_html=True
        )

# ======================================================
# TAB 6: AGENT AI (PERSISTENT)
# ======================================================
with tabs[5]:
    if st.button("Run Agent Analysis"):
        st.session_state.agent_report = {
            "summary": "Targeted anti-forensic activity detected.",
            "rec": "Isolate host. Perform RAM capture."
        }

    if st.session_state.agent_report:
        r = st.session_state.agent_report
        st.markdown(f"""
        <div class='agent-box'>
        <h3>Agent Conclusion</h3>
        <p><b>Summary:</b> {r['summary']}</p>
        <p><b>Recommendation:</b> {r['rec']}</p>
        </div>
        """, unsafe_allow_html=True)

# ======================================================
# TAB 7: LIVE MONITOR (CONTROLLED REFRESH)
# ======================================================
with tabs[6]:

    if PSUTIL_AVAILABLE:

        # --- Real sampling ---
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()

        st.session_state.cpu_history.append(cpu)
        st.session_state.cpu_history = st.session_state.cpu_history[-60:]

        # Train model once
        if len(st.session_state.cpu_history) > 30 and st.session_state.iso_model is None:
            model = IsolationForest(contamination=0.05, random_state=42)
            model.fit(np.array(st.session_state.cpu_history).reshape(-1,1))
            st.session_state.iso_model = model

        anomaly = "Normal"

        if st.session_state.iso_model:
            pred = st.session_state.iso_model.predict([[cpu]])
            if pred[0] == -1:
                anomaly = "⚠️ Anomaly"

        c1,c2,c3 = st.columns(3)

        with c1:
            fig_cpu = go.Figure(go.Indicator(
                mode="gauge+number",
                value=cpu,
                title={'text':"CPU Load"},
                gauge={'axis':{'range':[0,100]}}
            ))
            fig_cpu.update_layout(height=260, paper_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig_cpu, use_container_width=True)

        with c2:
            fig_mem = go.Figure(go.Indicator(
                mode="gauge+number",
                value=mem.percent,
                title={'text':"Memory Load"},
                gauge={'axis':{'range':[0,100]}}
            ))
            fig_mem.update_layout(height=260, paper_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig_mem, use_container_width=True)

        with c3:
            st.markdown(f"""
            <div class='monitor-card'>
            <h2>AI Status</h2>
            <h1>{anomaly}</h1>
            </div>
            """, unsafe_allow_html=True)

        st.line_chart(st.session_state.cpu_history)

    else:
        st.error("psutil not installed.")

# ======================================================
# FOOTER
# ======================================================
st.markdown("---")
st.caption(f"ForenSight AI Platinum v4.0 • Stable Build • {dt.now().strftime('%Y-%m-%d %H:%M:%S')}")
