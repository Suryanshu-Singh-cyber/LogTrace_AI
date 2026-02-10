import datetime
import time
import random
from collections import defaultdict

import streamlit as st
import pandas as pd
import numpy as np

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
# STYLE
# ======================================================
st.markdown("""
<style>
body { background:#020617;color:#e5e7eb }
.alert { padding:12px;border-radius:10px;margin-bottom:8px }
.high { background:#7f1d1d }
.medium { background:#78350f }
.low { background:#064e3b }
.metric { font-size:26px;font-weight:700 }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ ForenSight AI")
st.caption("DFIR • SOC Intelligence • Demo-Safe")
st.markdown("---")

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
# TAB 5 — SOC ALERT FEED
# ======================================================
with tabs[4]:
    st.subheader("🚨 SOC Alert Feed")

    if "alerts" not in st.session_state:
        st.session_state.alerts = []

    if len(st.session_state.alerts) < 6:
        sev = random.choice(["HIGH", "MEDIUM", "LOW"])
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

    st_autorefresh(interval=2000, key="live_refresh")

    if not PSUTIL_AVAILABLE:
        st.error("❌ psutil not installed")
        st.stop()

    # ---- PRIME CPU (REQUIRED) ----
    psutil.cpu_percent(interval=None)

    # ---- LIVE METRICS ----
    cpu_per_core = psutil.cpu_percent(interval=1, percpu=True)
    total_cpu = round(sum(cpu_per_core) / len(cpu_per_core), 2)
    mem = psutil.virtual_memory()

    # ---- STORE HISTORY ----
    if "cpu_hist" not in st.session_state:
        st.session_state.cpu_hist = []

    st.session_state.cpu_hist.append(total_cpu)
    st.session_state.cpu_hist = st.session_state.cpu_hist[-30:]

    # ---- AI CPU STATE ----
    anomaly = "NORMAL"
    if len(st.session_state.cpu_hist) >= 10:
        X = np.array(st.session_state.cpu_hist).reshape(-1, 1)
        model = IsolationForest(contamination=0.15, random_state=42)
        model.fit(X)
        if model.predict([[total_cpu]])[0] == -1:
            anomaly = "ANOMALY"

    # ---- DASHBOARD METRICS ----
    c1, c2, c3 = st.columns(3)
    c1.metric("CPU Usage", f"{total_cpu}%")
    c2.metric("Memory Usage", f"{mem.percent}%")
    c3.metric("AI CPU State", anomaly)

    st.markdown("### 🧠 Per-Core CPU Load")
    for i, v in enumerate(cpu_per_core):
        st.write(f"Core {i}: {v}%")

    if anomaly == "ANOMALY":
        st.error("🚨 SOC ALERT: Abnormal CPU Behavior")

# ======================================================
# TAB 7 — EDR & THREAT INTEL
# ======================================================
with tabs[6]:
    st.subheader("🧩 EDR & Threat Intelligence")

    if not PSUTIL_AVAILABLE:
        st.warning("psutil required")
        st.stop()

    # ---- PROCESS SNAPSHOT ----
    proc_data = []
    for p in psutil.process_iter(["pid", "name", "cpu_percent", "ppid"]):
        proc_data.append(p.info)

    df_proc = pd.DataFrame(proc_data).fillna(0)

    if len(df_proc) > 10:
        model = IsolationForest(contamination=0.15, random_state=42)
        df_proc["anomaly"] = model.fit_predict(df_proc[["cpu_percent"]])
        df_proc["risk"] = df_proc["cpu_percent"] * (df_proc["anomaly"] == -1)

    suspicious = df_proc[df_proc["anomaly"] == -1].sort_values("risk", ascending=False)

    st.markdown("### 🔍 Suspicious Processes")
    st.dataframe(
        suspicious[["pid", "name", "cpu_percent", "risk"]].head(5),
        use_container_width=True
    )

    heat = int(suspicious["risk"].sum()) if not suspicious.empty else 0

    st.markdown("### 🔥 SOC Heat Score")
    if heat > 150:
        st.error(f"CRITICAL: {heat}")
    elif heat > 70:
        st.warning(f"HIGH: {heat}")
    else:
        st.success(f"NORMAL: {heat}")

# ======================================================
# FOOTER
# ======================================================
st.markdown("---")
st.caption("ForenSight AI • Live • SOC-Grade • Demo-Safe")
