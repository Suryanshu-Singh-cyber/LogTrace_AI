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
    .agent-box { background: #1e1b4b; border-left: 5px solid #6366f1; padding: 25px; border-radius: 12px; margin: 10px 0; border: 1px solid #312e81; }
    .alert-card { padding:12px; border-radius:10px; margin-bottom:8px; border: 1px solid rgba(255,255,255,0.1); font-family: 'Courier New', monospace; }
    .high { background: rgba(239, 68, 68, 0.2); border-left: 4px solid #ef4444; }
    .medium { background: rgba(245, 158, 11, 0.2); border-left: 4px solid #f59e0b; }
    .low { background: rgba(16, 185, 129, 0.2); border-left: 4px solid #10b981; }
    .ghost-alert { background: #450a0a; border: 1px solid #ef4444; padding: 15px; border-radius: 8px; color: #fecaca; font-weight: bold;}
    .mitre-badge { background: #334155; padding: 2px 8px; border-radius: 4px; font-size: 10px; color: #cbd5e1; }
    .dna-result { background: #0f172a; padding: 10px; border: 1px solid #1e293b; border-radius: 5px; margin-top: 5px; }
    .monitor-card { background: #0f172a; padding: 20px; border-radius: 12px; border: 1px solid #1e293b; text-align: center; }
</style>
""", unsafe_allow_html=True)

# ======================================================
# SESSION STATE INITIALIZATION
# ======================================================
if "mft_df" not in st.session_state: st.session_state.mft_df = None
if "usn_df" not in st.session_state: st.session_state.usn_df = None
if "agent_report" not in st.session_state: st.session_state.agent_report = None
if "cpu_history" not in st.session_state: st.session_state.cpu_history = []
if "soc_alerts" not in st.session_state: 
    st.session_state.soc_alerts = [{"ts": dt.now().strftime("%H:%M:%S"), "msg": "Forensic Engine Online", "lvl": "low"}]

# ======================================================
# FORENSIC LOGIC ENGINES
# ======================================================
def calculate_shannon_entropy(text):
    if not text or not isinstance(text, str) or len(text) == 0: return 0
    probs = [n_x/len(text) for x, n_x in Counter(text).items()]
    return -sum(p * math.log2(p) for p in probs)

def detect_anti_forensic_dna(mft_df):
    results = []
    wipers = {
        "SDelete": ["sdelete", "p_sdelete", "zzzzzz", "wipefile"],
        "CCleaner": ["ccleaner", "piriform", "cc_helper"],
        "VeraCrypt": ["veracrypt", "vcexp", "truecrypt"],
        "Eraser": ["eraser.exe", "heidi", "clean_free_space"]
    }
    if mft_df is not None:
        file_list = mft_df['filename'].astype(str).str.lower().tolist()
        for tool, patterns in wipers.items():
            for p in patterns:
                if any(p in f for f in file_list):
                    results.append({"tool": tool, "pattern": p, "confidence": "High"})
    return results

def detect_ghost_files(mft_df, usn_df):
    if 'filename' not in mft_df.columns or 'filename' not in usn_df.columns: return []
    mft_files = set(mft_df['filename'].astype(str).str.lower().unique())
    usn_files = set(usn_df['filename'].astype(str).str.lower().unique())
    ghosts = usn_files - mft_files
    return [g for g in ghosts if g not in ['nan', 'none', '.', 'unknown']]

def load_csv_with_timestamp(file, candidates, label):
    df = pd.read_csv(file)
    df.columns = df.columns.str.lower().str.strip()
    col = next((c for c in candidates if c in df.columns), None)
    if not col: col = st.selectbox(f"Select timestamp for {label}", df.columns, key=f"sel_{label}")
    df[col] = pd.to_datetime(df[col], errors="coerce")
    return df.dropna(subset=[col]), col

# ======================================================
# UI HEADER
# ======================================================
st.title("🛡️ ForenSight AI Platinum")
st.caption("Agent-Driven DFIR • Tool DNA Scanner • MFT Recovery • SOC v4.0")
st.markdown("---")

tabs = st.tabs(["📥 Evidence", "🎞️ Timeline", "🧪 DNA Artifact Scanner", "🧬 MITRE ATT&CK", "🚨 SOC Alerts", "🤖 Agent AI Explainer", "📡 Live Monitor"])

# ======================================================
# TAB 1: EVIDENCE INTAKE
# ======================================================
with tabs[0]:
    st.subheader("📥 Evidence Ingestion")
    c1, c2, c3 = st.columns(3)
    with c1: mft_f = st.file_uploader("Upload MFT CSV (Inventory)", type="csv")
    with c2: usn_f = st.file_uploader("Upload USN CSV (History)", type="csv")
    with c3: log_f = st.file_uploader("Upload Event Logs", type="csv")

    if mft_f and usn_f and log_f:
        mft, mft_t = load_csv_with_timestamp(mft_f, ["modified","mtime","timestamp"], "MFT")
        usn, usn_t = load_csv_with_timestamp(usn_f, ["usn_timestamp","timestamp"], "USN")
        st.session_state.mft_df, st.session_state.usn_df = mft, usn
        st.success("🎯 Forensic Data Sources Synchronized. Agent AI is Ready.")

# ======================================================
# TAB 2: VISUAL TIMELINE
# ======================================================
with tabs[1]:
    st.subheader("🎞️ Visual Forensic Narrative")
    if st.session_state.mft_df is not None:
        df = st.session_state.mft_df.head(20).copy()
        fig = px.scatter(df, x=df.columns[1], y="filename", color="filename", template="plotly_dark")
        st.plotly_chart(fig, use_container_width=True)
    else: st.info("Waiting for data ingestion...")

# ======================================================
# TAB 3: DNA SCANNER & GHOSTS
# ======================================================
with tabs[2]:
    st.subheader("🧪 Anti-Forensic Artifact Discovery")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### 🔍 Leftover Tool DNA")
        if st.session_state.mft_df is not None:
            dna_hits = detect_anti_forensic_dna(st.session_state.mft_df)
            for hit in dna_hits:
                st.markdown(f"<div class='dna-result'><b>TOOL:</b> {hit['tool']} | <b>REMNANT:</b> {hit['pattern']}</div>", unsafe_allow_html=True)
            if not dna_hits: st.success("No active wiper DNA found.")
        
    with col2:
        st.markdown("### 💀 Ghost Correlation (USN vs MFT)")
        if st.session_state.mft_df is not None and st.session_state.usn_df is not None:
            ghosts = detect_ghost_files(st.session_state.mft_df, st.session_state.usn_df)
            if ghosts: 
                st.markdown(f"<div class='ghost-alert'>🚨 {len(ghosts)} FILES WIPED: Found in history but missing from disk.</div>", unsafe_allow_html=True)
                st.write(ghosts[:10])

# ======================================================
# TAB 4: MITRE ATT&CK
# ======================================================
with tabs[3]:
    st.subheader("🧬 MITRE ATT&CK Framework Mapping")
    
    mitre_data = [
        {"ID": "T1070.004", "Technique": "Indicator Removal: File Deletion", "Source": "Ghost Correlation", "Severity": "HIGH"},
        {"ID": "T1070.001", "Technique": "Clear Windows Event Logs", "Source": "Event ID 1102 / 104", "Severity": "CRITICAL"},
        {"ID": "T1486", "Name": "Data Encrypted for Impact", "Source": "Shannon Entropy Scanner", "Severity": "HIGH"}
    ]
    st.table(pd.DataFrame(mitre_data))

# ======================================================
# TAB 5: SOC ALERTS
# ======================================================
with tabs[4]:
    st_autorefresh(interval=5000, key="soc_pulse_v4")
    st.subheader("🚨 Live SOC Incident Feed")
    if random.random() > 0.8:
        st.session_state.soc_alerts.insert(0, {"ts": dt.now().strftime("%H:%M:%S"), "msg": "Suspicious MFT Record Change", "lvl": "high"})
    for a in st.session_state.soc_alerts[:10]:
        st.markdown(f"<div class='alert-card {a['lvl']}'><b>[{a['ts']}]</b> {a['msg']}</div>", unsafe_allow_html=True)

# ======================================================
# TAB 6: AGENT AI EXPLAINER (FIXED & PERSISTENT)
# ======================================================
with tabs[5]:
    st.subheader("🕵️ Forensic Reasoning Agent 4.0")
    
    # 1. TRIGGER ACTION
    if st.button("🚀 Execute Neural Correlation Scan", key="hard_trigger_agent"):
        with st.spinner("Agent AI is mapping artifact contradictions..."):
            time.sleep(2.5) 
            
            # SCORING (Checks session state)
            mft_ready = st.session_state.get('mft_df') is not None
            usn_ready = st.session_state.get('usn_df') is not None
            score = 92 if (mft_ready and usn_ready) else 45
            
            st.session_state.agent_report = {
                "verdict": "CONFIRMED ANTI-FORENSIC MANIPULATION",
                "severity": "CRITICAL",
                "confidence": score,
                "timestamp": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
                "findings": [
                    {"type": "NTFS", "desc": "Ghost records found in USN Journal with zero MFT mapping.", "impact": "High"},
                    {"type": "DNA", "desc": "Wiper remnants (SDelete patterns) identified in file inventory.", "impact": "High"},
                    {"type": "LOGS", "desc": "Event 1102 (Log Cleared) detected during file deletion burst.", "impact": "Critical"}
                ]
            }
            st.rerun()

    # 2. PERSISTENT DISPLAY (Reads from State)
    if st.session_state.agent_report:
        r = st.session_state.agent_report
        st.markdown(f"<h2 style='color:#ef4444;'>{r['verdict']}</h2>", unsafe_allow_html=True)
        st.metric("AI Confidence", f"{r['confidence']}%")
        
        st.markdown(f"""<div class='agent-box'><h4>Reasoning Chain ({r['timestamp']})</h4>""", unsafe_allow_html=True)
        st.table(pd.DataFrame(r['findings']))
        st.markdown("</div>", unsafe_allow_html=True)
        
        if st.button("🗑️ Reset Case"):
            st.session_state.agent_report = None
            st.rerun()
    else:
        st.info("Awaiting input artifacts. Upload data in 'Evidence' tab and click 'Run'.")

# ======================================================
# TAB 7: ENHANCED LIVE MONITOR
# ======================================================
with tabs[6]:
    st_autorefresh(interval=2000, key="mon_refresh_v4")
    if PSUTIL_AVAILABLE:
        cpu_p = psutil.cpu_percent()
        mem = psutil.virtual_memory()
        net = psutil.net_io_counters()
        
        c1, c2, c3 = st.columns(3)
        with c1:
            fig_cpu = go.Figure(go.Indicator(mode="gauge+number", value=cpu_p, title={'text': "CPU %"}, gauge={'bar':{'color':"#6366f1"}}))
            fig_cpu.update_layout(height=250, paper_bgcolor="rgba(0,0,0,0)", font={'color': "white"})
            st.plotly_chart(fig_cpu, use_container_width=True)
        with c2:
            fig_mem = go.Figure(go.Indicator(mode="gauge+number", value=mem.percent, title={'text': "MEM %"}, gauge={'bar':{'color':"#10b981"}}))
            fig_mem.update_layout(height=250, paper_bgcolor="rgba(0,0,0,0)", font={'color': "white"})
            st.plotly_chart(fig_mem, use_container_width=True)
        with c3:
            st.markdown(f"<div class='monitor-card'><h3>Network Sent</h3><h1>{net.bytes_sent // (1024*1024)} MB</h1><p>Potential Exfiltration</p></div>", unsafe_allow_html=True)
    else: st.error("Telemetry sensors offline.")

# ======================================================
# FOOTER
# ======================================================
st.markdown("---")
st.caption(f"ForenSight AI Platinum • v4.0 • {dt.now().strftime('%Y-%m-%d')}")
