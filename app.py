# ======================================================
# FORENSIGHT AI — SOC / DFIR DEMO PLATFORM
# ======================================================

import datetime
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
body { background:#020617;color:#e5e7eb }
.alert { padding:12px;border-radius:10px;margin-bottom:8px }
.high { background:#7f1d1d }
.medium { background:#78350f }
.low { background:#064e3b }
.metric { font-size:26px;font-weight:700 }
.box {
    padding:20px;
    border-radius:14px;
    background:#020617;
    border:1px solid #1f2933;
}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ ForenSight AI")
st.caption("DFIR • Anti-Forensics • SOC Intelligence Platform")
st.markdown("---")

# ======================================================
# HELPERS
# ======================================================
def load_csv_with_timestamp(file, candidates, label):
    df = pd.read_csv(file)
    df.columns = df.columns.str.lower().str.strip()
    col = next((c for c in candidates if c in df.columns), None)

    if not col:
        col = st.selectbox(f"Select timestamp for {label}", df.columns)

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

    mft_file = st.file_uploader("MFT CSV", type="csv")
    usn_file = st.file_uploader("USN CSV", type="csv")
    log_file = st.file_uploader("Security Log CSV", type="csv")

    if mft_file and usn_file and log_file:
        mft, mft_t = load_csv_with_timestamp(
            mft_file, ["modified","mtime","timestamp"], "MFT"
        )
        usn, usn_t = load_csv_with_timestamp(
            usn_file, ["usn_timestamp","timestamp"], "USN"
        )
        logs, log_t = load_csv_with_timestamp(
            log_file, ["timestamp","event_time"], "Logs"
        )
        st.success("✔ Evidence Loaded")

# ======================================================
# TAB 2 — AI CORRELATION
# ======================================================
with tabs[1]:
    st.subheader("🧠 AI Timeline Correlation")

    ai_conf = 0
    total = 0

    if "mft" in locals() and "usn" in locals():
        deltas = []

        if "filename" in mft.columns and "filename" in usn.columns:
            for _, m in mft.iterrows():
                match = usn[usn["filename"] == m["filename"]]
                for _, u in match.iterrows():
                    deltas.append(abs((u[usn_t]-m[mft_t]).total_seconds()))

        total = len(deltas)

        if total >= 10:
            X = np.array(deltas).reshape(-1,1)
            model = IsolationForest(contamination=0.2, random_state=42)
            model.fit(X)
            score = model.decision_function(X)
            ai_conf = round((1 - np.mean(score)) * 100, 2)

    c1,c2 = st.columns(2)
    c1.metric("AI Confidence", f"{ai_conf}%")
    c2.metric("Correlated Events", total)

# ======================================================
# TAB 3 — ANTI-FORENSICS
# ======================================================
with tabs[2]:
    st.subheader("🧪 Anti-Forensics Detection")

    art = st.file_uploader("Artifact CSV", type="csv")
    if art:
        df = pd.read_csv(art)
        df.columns = df.columns.str.lower()
        tools = ["ccleaner.exe","sdelete.exe","bleachbit.exe"]
        hits = df[df.iloc[:,0].astype(str).str.lower().isin(tools)]

        if not hits.empty:
            st.error("🚨 Anti-Forensics Detected")
            st.dataframe(hits)
        else:
            st.success("✔ Clean")

# ======================================================
# TAB 4 — MITRE
# ======================================================
with tabs[3]:
    st.subheader("🧬 MITRE ATT&CK")
    st.table(pd.DataFrame([
        ["T1070","Log Clear","Event 1102","HIGH"],
        ["T1564","Hidden Artifacts","Timestamp gaps","MEDIUM"]
    ], columns=["ID","Technique","Evidence","Confidence"]))

# ======================================================
# TAB 5 — SOC ALERT FEED
# ======================================================
with tabs[4]:
    st.subheader("🚨 SOC Alert Feed")

    if "alerts" not in st.session_state:
        st.session_state.alerts = []

    if len(st.session_state.alerts) < 6:
        sev = random.choice(["HIGH","MEDIUM","LOW"])
        st.session_state.alerts.insert(0, sev)

    for a in st.session_state.alerts[:6]:
        st.markdown(
            f"<div class='alert {a.lower()}'><b>{a}</b> — Suspicious activity</div>",
            unsafe_allow_html=True
        )

# ======================================================
# TAB 6 — REAL-TIME MONITORING (LIVE)
# ======================================================
with tabs[5]:
    st.subheader("📡 Live System Monitoring")

    st_autorefresh(interval=2000, key="live")

    if not PSUTIL_AVAILABLE:
        st.error("psutil not installed")
    else:
        # --- FORCE REAL SAMPLING ---
        cpu_per_core = psutil.cpu_percent(interval=0.5, percpu=True)
        total_cpu = round(sum(cpu_per_core) / len(cpu_per_core), 2)
        mem = psutil.virtual_memory()

        if "cpu_hist" not in st.session_state:
            st.session_state.cpu_hist = []

        st.session_state.cpu_hist.append(total_cpu)
        st.session_state.cpu_hist = st.session_state.cpu_hist[-20:]

        anomaly = "NORMAL"
        if len(st.session_state.cpu_hist) >= 8:
            X = np.array(st.session_state.cpu_hist).reshape(-1,1)
            model = IsolationForest(contamination=0.15, random_state=42)
            model.fit(X)
            if model.predict([[total_cpu]])[0] == -1:
                anomaly = "ANOMALY"

        c1,c2,c3 = st.columns(3)
        c1.metric("CPU Usage", f"{total_cpu}%")
        c2.metric("Memory Usage", f"{mem.percent}%")
        c3.metric("AI State", anomaly)

        st.markdown("### 🧠 Per-Core CPU")
        for i,v in enumerate(cpu_per_core):
            st.write(f"Core {i}: {v}%")

        if anomaly == "ANOMALY":
            st.error("🚨 CPU Spike Detected")

# ======================================================
# TAB 7 — EDR & THREAT INTEL
# ======================================================
with tabs[6]:
    st.subheader("🧩 EDR & Threat Intelligence")

    if not PSUTIL_AVAILABLE:
        st.warning("psutil required")
    else:
        proc_data = []
        for p in psutil.process_iter(["pid","name","cpu_percent","ppid"]):
            proc_data.append(p.info)

        df_proc = pd.DataFrame(proc_data).fillna(0)

        if len(df_proc) > 10:
            model = IsolationForest(contamination=0.15, random_state=42)
            df_proc["anomaly"] = model.fit_predict(df_proc[["cpu_percent"]])
            df_proc["risk"] = df_proc["cpu_percent"] * (df_proc["anomaly"] == -1)

        suspicious = df_proc[df_proc["anomaly"] == -1].sort_values("risk", ascending=False)

        st.dataframe(
            suspicious[["pid","name","cpu_percent","risk"]].head(5),
            use_container_width=True
        )

# ======================================================
# FOOTER
# ======================================================
st.markdown("---")
st.caption("ForenSight AI • SOC-Grade • Demo-Safe • Live Telemetry")
