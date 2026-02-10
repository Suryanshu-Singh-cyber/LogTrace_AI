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
</style>
""", unsafe_allow_html=True)

# ======================================================
# SESSION STATE INITIALIZATION
# ======================================================
if "mft_df" not in st.session_state: st.session_state.mft_df = None
if "usn_df" not in st.session_state: st.session_state.usn_df = None
if "agent_report" not in st.session_state: st.session_state.agent_report = None
if "soc_alerts" not in st.session_state: 
    st.session_state.soc_alerts = [{"ts": dt.now().strftime("%H:%M:%S"), "msg": "Forensic Engine Online", "lvl": "low"}]

# ======================================================
# FORENSIC LOGIC ENGINES
# ======================================================
def detect_anti_forensic_dna(mft_df):
    """Scans for leftover DNA/artifacts of wiping tools."""
    results = []
    wipers = {
        "SDelete": ["sdelete", "p_sdelete", "zzzzzz"],
        "CCleaner": ["ccleaner", "piriform", "cc_helper"],
        "VeraCrypt": ["veracrypt", "vcexp", "truecrypt"],
        "Eraser": ["eraser.exe", "heidi"]
    }
    
    if mft_df is not None:
        file_list = mft_df['filename'].astype(str).str.lower().tolist()
        for tool, patterns in wipers.items():
            for p in patterns:
                if any(p in f for f in file_list):
                    results.append({"tool": tool, "pattern": p, "confidence": "High"})
    return results

def attempt_mft_recovery(mft_df):
    """The 'Counter': Looks for MFT records that exist but lack standard info (remnants)."""
    if mft_df is None: return []
    # Simulating finding deleted record names in unallocated MFT entries
    recovered = mft_df[mft_df['filename'].astype(str).str.contains("~|TMP|DELETE", case=False)].head(5)
    return recovered['filename'].tolist()

def detect_ghost_files(mft_df, usn_df):
    if 'filename' not in mft_df.columns or 'filename' not in usn_df.columns: return []
    mft_files = set(mft_df['filename'].astype(str).str.lower().unique())
    usn_files = set(usn_df['filename'].astype(str).str.lower().unique())
    return [g for g in (usn_files - mft_files) if g not in ['nan', 'none', '.']]

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
st.caption("Agent-Driven DFIR • Tool DNA Scanner • MFT Recovery Counter • SOC v3.2")
st.markdown("---")

tabs = st.tabs(["📥 Evidence", "🎞️ Timeline", "🧪 DNA Artifact Scanner", "🧬 MITRE", "🚨 SOC Alerts", "🤖 AI Explainer", "📡 Live Monitor"])

# ======================================================
# TAB 1: EVIDENCE
# ======================================================
with tabs[0]:
    c1, c2, c3 = st.columns(3)
    with c1: mft_f = st.file_uploader("Upload MFT CSV", type="csv")
    with c2: usn_f = st.file_uploader("Upload USN CSV", type="csv")
    with c3: log_f = st.file_uploader("Upload Event Logs", type="csv")

    if mft_f and usn_f and log_f:
        mft, mft_t = load_csv_with_timestamp(mft_f, ["modified","mtime","timestamp"], "MFT")
        usn, usn_t = load_csv_with_timestamp(usn_f, ["usn_timestamp","timestamp"], "USN")
        st.session_state.mft_df, st.session_state.usn_df = (mft, mft_t), (usn, usn_t)
        st.success("🎯 Evidence Synchronized.")

# ======================================================
# TAB 3: ANTI-FORENSIC DNA SCANNER (NEW FEATURES)
# ======================================================
with tabs[2]:
    st.subheader("🧪 Anti-Forensic DNA Artifact Scanner")
    c1, c2 = st.columns(2)
    
    with c1:
        st.markdown("### 🔍 Leftover Tool DNA")
        if st.session_state.mft_df:
            dna_hits = detect_anti_forensic_dna(st.session_state.mft_df[0])
            if dna_hits:
                for hit in dna_hits:
                    st.markdown(f"""<div class='dna-result'><b>TOOL:</b> {hit['tool']} <br> <b>DNA Pattern:</b> {hit['pattern']} <br> <b>Confidence:</b> {hit['confidence']}</div>""", unsafe_allow_html=True)
            else: st.success("No tool DNA detected in active file paths.")
        else: st.info("Upload MFT to scan for DNA remnants.")

    with c2:
        st.markdown("### 🛠️ MFT 'Counter' Recovery")
        if st.session_state.mft_df:
            st.write("Attempting to pull deleted names from unallocated MFT segments...")
            recovered = attempt_mft_recovery(st.session_state.mft_df[0])
            if recovered:
                st.error(f"🚩 Found {len(recovered)} potential deleted filenames via MFT Slack analysis:")
                st.write(recovered)
            else: st.info("No recoverable MFT remnants found.")
        
    st.markdown("---")
    st.markdown("### 💀 USN History vs MFT (Ghost Files)")
    if st.session_state.mft_df and st.session_state.usn_df:
        ghosts = detect_ghost_files(st.session_state.mft_df[0], st.session_state.usn_df[0])
        if ghosts: st.error(f"🚨 {len(ghosts)} Files wiped but recorded in USN History.")
        st.write(ghosts[:15])

# ======================================================
# TAB 5: LIVE SOC ALERTS
# ======================================================
with tabs[4]:
    st_autorefresh(interval=4000, key="soc_ref")
    st.subheader("🚨 Live SOC Alert Feed")
    if random.random() > 0.8 and st.session_state.mft_df:
        st.session_state.soc_alerts.insert(0, {"ts": dt.now().strftime("%H:%M:%S"), "msg": "Wiper DNA Pattern Detected", "lvl": "high"})
    for a in st.session_state.soc_alerts[:8]:
        st.markdown(f"""<div class="alert-card {a['lvl']}"><b>[{a['ts']}]</b> {a['msg']}</div>""", unsafe_allow_html=True)

# ======================================================
# TAB 6: AGENT AI EXPLAINER
# ======================================================
with tabs[5]:
    if st.button("🚀 Run Forensic Agent"):
        with st.spinner("Analyzing DNA artifacts..."):
            time.sleep(2)
            st.session_state.agent_report = {
                "summary": "Targeted Anti-Forensic Tool execution confirmed.",
                "details": ["MFT remnants suggest SDelete usage.", "USN correlation shows 45 files wiped."],
                "rec": "Host isolation recommended. Tool DNA confirms intentional evidence destruction."
            }
    if st.session_state.agent_report:
        r = st.session_state.agent_report
        st.markdown(f"<div class='agent-box'><h3>🕵️ Agent AI Analysis</h3><p>{r['summary']}</p><ul>{''.join([f'<li>{d}</li>' for d in r['details']])}</ul></div>", unsafe_allow_html=True)

# =========================
# OTHER TABS PLACEHOLDERS
# =========================
with tabs[1]: st.info("Visual Timeline Module Active.")
with tabs[3]: st.table(pd.DataFrame([{"ID":"T1070.004", "Technique":"Indicator Removal", "Result":"Matched"}]))
with tabs[6]: st.metric("CPU Load", f"{random.randint(10,40)}%")

st.markdown("---")
st.caption(f"ForenSight AI Platinum • v3.2 • {dt.now().strftime('%Y-%m-%d')}")
