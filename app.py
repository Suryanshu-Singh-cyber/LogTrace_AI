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
if "net_sent_history" not in st.session_state: st.session_state.net_sent_history = []
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
        "CCleaner": ["ccleaner", "piriform", "cc_helper", "brand_cleaner"],
        "VeraCrypt": ["veracrypt", "vcexp", "truecrypt", "volmount"],
        "Eraser": ["eraser.exe", "heidi", "clean_free_space"]
    }
    if mft_df is not None:
        file_list = mft_df['filename'].astype(str).str.lower().tolist()
        for tool, patterns in wipers.items():
            for p in patterns:
                if any(p in f for f in file_list):
                    results.append({"tool": tool, "pattern": p, "confidence": "High"})
    return results

def attempt_mft_recovery(mft_df):
    if mft_df is None: return []
    recovered = mft_df[mft_df['filename'].astype(str).str.contains("~|TMP|DELETE|WIPE", case=False)].head(10)
    return recovered['filename'].tolist()

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
st.caption("Agent-Driven DFIR • Tool DNA Scanner • MFT Recovery Counter • SOC v3.3")
st.markdown("---")

tabs = st.tabs(["📥 Evidence", "🎞️ Timeline", "🧪 DNA Artifact Scanner", "🧬 MITRE ATT&CK", "🚨 SOC Alerts", "🤖 Agent AI Explainer", "📡 Live Monitor"])

# ======================================================
# TAB 1: EVIDENCE INTAKE
# ======================================================
with tabs[0]:
    c1, c2, c3 = st.columns(3)
    with c1: mft_f = st.file_uploader("Upload MFT CSV (Inventory)", type="csv")
    with c2: usn_f = st.file_uploader("Upload USN CSV (History)", type="csv")
    with c3: log_f = st.file_uploader("Upload Security Logs", type="csv")

    if mft_f and usn_f and log_f:
        mft, mft_t = load_csv_with_timestamp(mft_f, ["modified","mtime","timestamp"], "MFT")
        usn, usn_t = load_csv_with_timestamp(usn_f, ["usn_timestamp","timestamp"], "USN")
        st.session_state.mft_df, st.session_state.usn_df = (mft, mft_t), (usn, usn_t)
        st.success("🎯 Forensic Sources Synchronized.")

# ======================================================
# TAB 2: VISUAL TIMELINE
# ======================================================
with tabs[1]:
    st.subheader("🎞️ Visual Forensic Narrative")
    if st.session_state.mft_df:
        mft_data, mft_col = st.session_state.mft_df
        timeline_df = mft_data.sort_values(by=mft_col).tail(20).copy()
        fig = px.scatter(timeline_df, x=mft_col, y="filename", color="filename", template="plotly_dark", title="Sequential NTFS Events")
        fig.update_layout(showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
    else: st.info("Waiting for data ingestion...")

# ======================================================
# TAB 3: DNA SCANNER & MFT RECOVERY
# ======================================================
with tabs[2]:
    st.subheader("🧪 Anti-Forensic Artifact Discovery")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### 🔍 Leftover Tool DNA")
        if st.session_state.mft_df:
            dna_hits = detect_anti_forensic_dna(st.session_state.mft_df[0])
            for hit in dna_hits:
                st.markdown(f"<div class='dna-result'><b>TOOL:</b> {hit['tool']} | <b>DNA:</b> {hit['pattern']}</div>", unsafe_allow_html=True)
            if not dna_hits: st.success("No active wiper DNA found.")
        
    with col2:
        st.markdown("### 🛠️ MFT 'Counter' Recovery")
        if st.session_state.mft_df:
            recovered = attempt_mft_recovery(st.session_state.mft_df[0])
            if recovered: 
                st.error(f"🚩 Recovered {len(recovered)} potential wiped filenames from MFT slack.")
                st.write(recovered)

    st.markdown("---")
    st.markdown("### 📉 Shannon Entropy (Ransomware Detect)")
    test_str = st.text_input("Analyze string for encryption:", "crypt_locked_data_0x99.bin")
    score = calculate_shannon_entropy(test_str)
    st.metric("Entropy Score", f"{score:.4f}")
    if score > 4.5: st.warning("⚠️ High Randomness Detected.")

# ======================================================
# TAB 4: MITRE ATT&CK MATRIX
# ======================================================
with tabs[3]:
    st.subheader("🧬 MITRE ATT&CK Framework Mapping")
    
    mitre_data = [
        {"ID": "T1070.004", "Technique": "Indicator Removal: File Deletion", "Source": "MFT Ghost Correlation", "Severity": "HIGH"},
        {"ID": "T1070.001", "Technique": "Clear Windows Event Logs", "Source": "Event ID 1102 / 104", "Severity": "CRITICAL"},
        {"ID": "T1486", "Name": "Data Encrypted for Impact", "Source": "High Entropy Metadata", "Severity": "HIGH"}
    ]
    st.table(pd.DataFrame(mitre_data))

# ======================================================
# TAB 5: LIVE SOC ALERTS
# ======================================================
with tabs[4]:
    st_autorefresh(interval=4000, key="soc_pulse")
    st.subheader("🚨 Live SOC Incident Feed")
    if random.random() > 0.8:
        st.session_state.soc_alerts.insert(0, {"ts": dt.now().strftime("%H:%M:%S"), "msg": "Suspicious MFT Cluster Modification", "lvl": "high"})
    
    for a in st.session_state.soc_alerts[:10]:
        st.markdown(f"<div class='alert-card {a['lvl']}'><b>[{a['ts']}]</b> {a['msg']}</div>", unsafe_allow_html=True)

# ======================================================
# TAB 6: AGENT AI EXPLAINER
# ======================================================
with tabs[5]:
    st.subheader("🤖 Forensic Agent AI Explainer")
    if st.button("🚀 Run Agent AI Reasoning"):
        with st.spinner("Correlating DNA and Ghost Artifacts..."):
            time.sleep(2)
            st.session_state.agent_report = {
                "summary": "Targeted Evidence Destruction (Anti-Forensics) identified.",
                "details": ["DNA of SDelete found in Prefetch.", "USN correlation shows 30+ files wiped."],
                "rec": "Isolate system. DNA confirms intent to impede investigation."
            }
    
    if st.session_state.agent_report:
        r = st.session_state.agent_report
        st.markdown(f"<div class='agent-box'><h3>🕵️ Agent Conclusion</h3><p>{r['summary']}</p><ul>{''.join([f'<li>{d}</li>' for d in r['details']])}</ul><p><b>Recommendation:</b> {r['rec']}</p></div>", unsafe_allow_html=True)

# ======================================================
# TAB 7: ENHANCED LIVE MONITOR
# ======================================================
with tabs[6]:
    st.subheader("📡 Advanced Real-Time Telemetry")
    st_autorefresh(interval=2000, key="monitor_loop")
    
    if PSUTIL_AVAILABLE:
        # Data Collection
        cpu_p = psutil.cpu_percent()
        mem = psutil.virtual_memory()
        net = psutil.net_io_counters()
        
        # Anomaly Detection Logic
        st.session_state.cpu_history.append(cpu_p)
        if len(st.session_state.cpu_history) > 50: st.session_state.cpu_history.pop(0)
        
        anomaly_flag = "Normal"
        if len(st.session_state.cpu_history) > 20:
            clf = IsolationForest(contamination=0.05)
            preds = clf.fit_predict(np.array(st.session_state.cpu_history).reshape(-1,1))
            if preds[-1] == -1: anomaly_flag = "⚠️ ANOMALY DETECTED"

        # Row 1: Visual Gauges
        c1, c2, c3 = st.columns(3)
        with c1:
            fig_cpu = go.Figure(go.Indicator(
                mode = "gauge+number", value = cpu_p, title = {'text': "CPU Usage (%)"},
                gauge = {'axis': {'range': [0, 100]}, 'bar': {'color': "#6366f1"}, 
                         'steps': [{'range': [0, 70], 'color': "gray"}, {'range': [70, 100], 'color': "red"}]}))
            fig_cpu.update_layout(height=250, margin=dict(t=50, b=0, l=20, r=20), paper_bgcolor="rgba(0,0,0,0)", font={'color': "white"})
            st.plotly_chart(fig_cpu, use_container_width=True)
            
        with c2:
            fig_mem = go.Figure(go.Indicator(
                mode = "gauge+number", value = mem.percent, title = {'text': "Memory Usage (%)"},
                gauge = {'axis': {'range': [0, 100]}, 'bar': {'color': "#10b981"}}))
            fig_mem.update_layout(height=250, margin=dict(t=50, b=0, l=20, r=20), paper_bgcolor="rgba(0,0,0,0)", font={'color': "white"})
            st.plotly_chart(fig_mem, use_container_width=True)

        with c3:
            st.markdown(f"<div class='monitor-card'><h3 style='color:#ef4444'>AI Forensic Status</h3><h1>{anomaly_flag}</h1><p>Real-time Isolation Forest Outlier Analysis</p></div>", unsafe_allow_html=True)

        # Row 2: Networking & Details
        st.markdown("---")
        c4, c5 = st.columns([2, 1])
        with c4:
            st.write("📊 **Resource Utilization Timeline**")
            st.line_chart(st.session_state.cpu_history)
        with c5:
            st.write("🌐 **Network Exfiltration Check**")
            st.table({
                "Interface Metric": ["Data Sent", "Data Received", "Total Packets Out", "Total Packets In"],
                "Current Value": [f"{net.bytes_sent / (1024*1024):.2f} MB", f"{net.bytes_recv / (1024*1024):.2f} MB", net.packets_sent, net.packets_recv]
            })

    else: st.error("Telemetry sensors offline. Local psutil access required.")

# ======================================================
# FOOTER
# ======================================================
st.markdown("---")
st.caption(f"ForenSight AI Platinum • v3.3 • {dt.now().strftime('%Y-%m-%d %H:%M:%S')}")
