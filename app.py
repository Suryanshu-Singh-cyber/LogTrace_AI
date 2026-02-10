import datetime
from datetime import datetime as dt
from collections import defaultdict
import streamlit as st
import pandas as pd
import numpy as np
import time
import random

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
    page_title="ForenSight AI | DFIR Platform",
    page_icon="🛡️",
    layout="wide"
)

# ======================================================
# SOC STYLE
# ======================================================
st.markdown("""
<style>
    [data-testid="stAppViewContainer"] { background:#020617; color:#e5e7eb; }
    .alert { padding:12px; border-radius:10px; margin-bottom:8px; border: 1px solid rgba(255,255,255,0.1); }
    .high { background:#7f1d1d; color: white; }
    .medium { background:#78350f; color: white; }
    .low { background:#064e3b; color: white; }
    .stMetric { background: rgba(30, 41, 59, 0.5); padding: 15px; border-radius: 10px; border: 1px solid #334155; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ ForenSight AI")
st.caption("DFIR • Anti-Forensics • SOC Intelligence Platform")
st.markdown("---")

# ======================================================
# HELPERS & SESSION STATE
# ======================================================
if "mft_df" not in st.session_state: st.session_state.mft_df = None
if "usn_df" not in st.session_state: st.session_state.usn_df = None
if "log_df" not in st.session_state: st.session_state.log_df = None

def load_csv_with_timestamp(file, candidates, label):
    df = pd.read_csv(file)
    df.columns = df.columns.str.lower().str.strip()
    col = next((c for c in candidates if c in df.columns), None)

    if not col:
        col = st.selectbox(f"Select timestamp for {label}", df.columns, key=f"sel_{label}")

    df[col] = pd.to_datetime(df[col], errors="coerce")
    return df.dropna(subset=[col]), col

# ======================================================
# TABS
# ======================================================
tabs = st.tabs([
    "📥 Evidence Intake",
    "🧠 AI Correlation",
    "🧪 Anti-Forensics",
    "🧬 MITRE",
    "🚨 SOC Alerts",
    "📡 Real-Time Monitoring",
    "🧩 EDR & Threat Intel"
])

# ======================================================
# TAB 1 — EVIDENCE
# ======================================================
with tabs[0]:
    st.subheader("📥 Evidence Intake")
    
    c1, c2, c3 = st.columns(3)
    with c1:
        mft_file = st.file_uploader("MFT CSV", type="csv")
    with c2:
        usn_file = st.file_uploader("USN CSV", type="csv")
    with c3:
        log_file = st.file_uploader("Security Log CSV", type="csv")

    if mft_file and usn_file and log_file:
        mft, mft_t = load_csv_with_timestamp(mft_file, ["modified","mtime","timestamp"], "MFT")
        usn, usn_t = load_csv_with_timestamp(usn_file, ["usn_timestamp","timestamp"], "USN")
        logs, log_t = load_csv_with_timestamp(log_file, ["timestamp","event_time"], "Logs")
        
        # Save to session state for other tabs
        st.session_state.mft_df = (mft, mft_t)
        st.session_state.usn_df = (usn, usn_t)
        st.session_state.log_df = (logs, log_t)
        st.success("✔ Evidence Loaded & Correlated in memory")

# ======================================================
# TAB 2 — AI CORRELATION
# ======================================================
with tabs[1]:
    st.subheader("🧠 AI Timeline Correlation")

    ai_conf = 0
    total = 0

    if st.session_state.mft_df and st.session_state.usn_df:
        mft, mft_t = st.session_state.mft_df
        usn, usn_t = st.session_state.usn_df
        
        # Ensure filenames exist in columns
        if 'filename' in mft.columns and 'filename' in usn.columns:
            deltas = []
            # Performance optimization: Sample data if too large
            mft_sample = mft.head(100) 
            for _, m in mft_sample.iterrows():
                match = usn[usn["filename"] == m["filename"]]
                for _, u in match.iterrows():
                    deltas.append(abs((u[usn_t]-m[mft_t]).total_seconds()))

            total = len(deltas)

            if total >= 5:
                X = np.array(deltas).reshape(-1,1)
                model = IsolationForest(contamination=0.2, random_state=42)
                model.fit(X)
                score = model.decision_function(X)
                ai_conf = round((1 - np.abs(np.mean(score))) * 100, 2)
        else:
            st.warning("Missing 'filename' column in MFT or USN CSV for correlation.")
    else:
        st.info("Awaiting data from Evidence Intake tab...")

    c1,c2 = st.columns(2)
    c1.metric("AI Confidence", f"{ai_conf}%")
    c2.metric("Correlated Events (Sampled)", total)

# ======================================================
# TAB 3 — ANTI-FORENSICS
# ======================================================
with tabs[2]:
    st.subheader("🧪 Anti-Forensics Detection")

    art = st.file_uploader("Artifact CSV (Process/Execution Logs)", type="csv")
    if art:
        df_art = pd.read_csv(art)
        df_art.columns = df_art.columns.str.lower()
        tools = ["ccleaner.exe","sdelete.exe","bleachbit.exe","metasploit","mimikatz"]
        
        # Check first column or 'name' column
        search_col = 'name' if 'name' in df_art.columns else df_art.columns[0]
        hits = df_art[df_art[search_col].astype(str).str.lower().str.contains('|'.join(tools))]
        
        if not hits.empty:
            st.error(f"🚨 {len(hits)} Anti-Forensics Artifacts Detected")
            st.dataframe(hits, use_container_width=True)
        else:
            st.success("No common anti-forensic tools found in this artifact.")

# ======================================================
# TAB 4 — MITRE
# ======================================================
with tabs[3]:
    st.subheader("🧬 MITRE ATT&CK Mapping")
    mitre_data = [
        ["T1070.004", "Indicator Removal: File Deletion", "SDelete/CCleaner activity", "HIGH"],
        ["T1070.001", "Indicator Removal: Clear Windows Event Logs", "Event ID 1102 / 104", "CRITICAL"],
        ["T1099", "Timestomp", "MFT/USN Timestamp Mismatch", "MEDIUM"],
        ["T1204", "User Execution", "Malicious process spawning", "LOW"]
    ]
    st.table(pd.DataFrame(mitre_data, columns=["ID","Technique","Evidence Source","Severity"]))

# ======================================================
# TAB 5 — AUTO SOC ALERT FEED
# ======================================================
with tabs[4]:
    st.subheader("🚨 SOC Alert Feed (Live Simulation)")

    if "alerts" not in st.session_state:
        st.session_state.alerts = []

    # Generate random alerts if list is small
    if len(st.session_state.alerts) < 10:
        types = [("HIGH", "Log Cleared"), ("MEDIUM", "Timestamp Drift"), ("LOW", "New Process")]
        sev, msg = random.choice(types)
        ts = dt.now().strftime("%H:%M:%S")
        st.session_state.alerts.insert(0, (sev, f"[{ts}] {msg}"))

    for sev, msg in st.session_state.alerts[:8]:
        st.markdown(
            f"<div class='alert {sev.lower()}'><b>{sev}</b> — {msg}</div>",
            unsafe_allow_html=True
        )

# ======================================================
# TAB 6 — REAL-TIME MONITORING
# ======================================================
with tabs[5]:
    st.subheader("📡 Live System Monitoring")
    st_autorefresh(interval=3000, key="rt_refresh")

    if not PSUTIL_AVAILABLE:
        st.error("psutil module missing. Cannot perform real-time monitoring.")
    else:
        cpu_usage = psutil.cpu_percent()
        mem = psutil.virtual_memory()

        if "cpu_hist" not in st.session_state:
            st.session_state.cpu_hist = []
        st.session_state.cpu_hist.append(cpu_usage)
        st.session_state.cpu_hist = st.session_state.cpu_hist[-30:]

        anomaly_status = "NORMAL"
        if len(st.session_state.cpu_hist) >= 15:
            X_cpu = np.array(st.session_state.cpu_hist).reshape(-1,1)
            iso = IsolationForest(contamination=0.1, random_state=42)
            preds = iso.fit_predict(X_cpu)
            if preds[-1] == -1:
                anomaly_status = "ANOMALY"

        c1, c2, c3 = st.columns(3)
        c1.metric("System CPU", f"{cpu_usage}%", delta=anomaly_status, delta_color="inverse")
        c2.metric("Memory Usage", f"{mem.percent}%")
        c3.metric("AI Status", anomaly_status)
        
        st.line_chart(st.session_state.cpu_hist)

# ======================================================
# TAB 7 — EDR & THREAT INTEL
# ======================================================
with tabs[6]:
    st.subheader("🧩 EDR & Threat Intelligence Engine")

    if not PSUTIL_AVAILABLE:
        st.warning("EDR simulation requires psutil")
    else:
        # -------------------------------
        # PER-PROCESS ANOMALY SCORING
        # -------------------------------
        st.markdown("### 🔍 Process Behavior Analysis")
        proc_list = []
        for p in psutil.process_iter(["pid", "name", "cpu_percent", "ppid"]):
            try:
                proc_list.append(p.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        df_proc = pd.DataFrame(proc_list).fillna(0)

        if len(df_proc) > 5:
            model_edr = IsolationForest(contamination=0.1, random_state=42)
            df_proc["anomaly"] = model_edr.fit_predict(df_proc[["cpu_percent"]])
            df_proc["risk_score"] = df_proc["cpu_percent"] * (df_proc["anomaly"] == -1)
            
            suspicious = df_proc[df_proc["anomaly"] == -1].sort_values("risk_score", ascending=False)
            st.dataframe(suspicious[["pid","name","cpu_percent","risk_score"]].head(10), use_container_width=True)

        # -------------------------------
        # PROCESS TREE (ASCII)
        # -------------------------------
        st.markdown("### 🌳 Process Lineage (Parent-Child)")
        tree = defaultdict(list)
        for _, r in df_proc.head(20).iterrows():
            tree[int(r["ppid"])].append(f"{r['name']} ({int(r['pid'])})")

        for parent, children in list(tree.items())[:5]:
            st.text(f"PID {parent} └── {', '.join(children)}")

        # -------------------------------
        # EXPORT & SCORING
        # -------------------------------
        st.markdown("---")
        heat_score = int(df_proc["risk_score"].sum())
        
        c1, c2 = st.columns([2,1])
        with c1:
            if heat_score > 100:
                st.error(f"🔥 CRITICAL SYSTEM THREAT SCORE: {heat_score}")
            else:
                st.success(f"✅ SYSTEM HEALTH SCORE: {heat_score}")
        
        with c2:
            if st.button("📤 Export SOC Report"):
                report_name = f"soc_report_{int(time.time())}.csv"
                df_proc.to_csv(report_name, index=False)
                st.download_button("Download Now", data=df_proc.to_csv(), file_name=report_name)

# ======================================================
# FOOTER
# ======================================================
st.markdown("---")
st.caption(f"ForenSight AI v2.1 • Logged in at {dt.now().strftime('%Y-%m-%d %H:%M')}")
