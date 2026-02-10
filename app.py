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
    page_title="ForenSight AI | SOC EDR",
    page_icon="🛡️",
    layout="wide"
)

# ======================================================
# STYLE
# ======================================================
st.markdown("""
<style>
body { background:#020617;color:#e5e7eb }
.alert { padding:10px;border-radius:10px;margin-bottom:6px }
.high { background:#7f1d1d }
.medium { background:#78350f }
.low { background:#064e3b }
.critical { background:#450a0a }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ ForenSight AI — SOC / EDR Console")
st.caption("Real-Time Threat Detection • DFIR • Demo-Safe")
st.markdown("---")

# ======================================================
# TABS
# ======================================================
tabs = st.tabs([
    "📥 Evidence",
    "🧠 AI Correlation",
    "🧪 Anti-Forensics",
    "🧬 MITRE",
    "🚨 SOC Alerts",
    "📡 Real-Time EDR"
])

# ======================================================
# TAB 6 — REAL-TIME EDR (ONLY AUTO-REFRESH TAB)
# ======================================================
with tabs[5]:
    st.subheader("📡 Live EDR Monitoring")

    # WebSocket-like refresh loop
    st_autorefresh(interval=2000, key="edr_refresh")

    if not PSUTIL_AVAILABLE:
        st.error("psutil missing")
    else:
        # ---------------- CPU ----------------
        cpu_total = psutil.cpu_percent()
        mem = psutil.virtual_memory()

        if "cpu_hist" not in st.session_state:
            st.session_state.cpu_hist = []

        st.session_state.cpu_hist.append(cpu_total)
        st.session_state.cpu_hist = st.session_state.cpu_hist[-40:]

        cpu_state = "NORMAL"
        if len(st.session_state.cpu_hist) >= 10:
            model = IsolationForest(contamination=0.15)
            X = np.array(st.session_state.cpu_hist).reshape(-1,1)
            model.fit(X)
            if model.predict([[cpu_total]])[0] == -1:
                cpu_state = "ANOMALY"

        # ---------------- PROCESS AI ----------------
        proc_data = []
        for p in psutil.process_iter(["name","cpu_percent"]):
            if p.info["cpu_percent"] is not None:
                proc_data.append(p.info)

        pdf = pd.DataFrame(proc_data)
        suspicious = pd.DataFrame()

        if len(pdf) >= 10:
            model_p = IsolationForest(contamination=0.1)
            Xp = pdf[["cpu_percent"]]
            model_p.fit(Xp)
            pdf["anomaly"] = model_p.predict(Xp)
            suspicious = pdf[pdf["anomaly"] == -1]

        # ---------------- SEVERITY ENGINE ----------------
        severity = "LOW"
        score = 0

        if cpu_state == "ANOMALY":
            score += 2
        if len(suspicious) > 0:
            score += 2

        if score >= 4:
            severity = "CRITICAL"
        elif score == 3:
            severity = "HIGH"
        elif score == 2:
            severity = "MEDIUM"

        # ---------------- METRICS ----------------
        c1,c2,c3,c4 = st.columns(4)
        c1.metric("CPU", f"{cpu_total}%")
        c2.metric("Memory", f"{mem.percent}%")
        c3.metric("CPU AI", cpu_state)
        c4.metric("SOC Severity", severity)

        st.markdown("---")

        # ---------------- PER CORE ----------------
        st.markdown("### 🧠 Per-Core CPU")
        for i,v in enumerate(psutil.cpu_percent(percpu=True)):
            st.write(f"Core {i}: {v}%")

        # ---------------- PROCESS ANOMALIES ----------------
        st.markdown("### 🧬 Process Anomaly Scoring")
        if not suspicious.empty:
            st.error("🚨 Suspicious Processes Detected")
            st.dataframe(
                suspicious[["name","cpu_percent"]]
                .sort_values("cpu_percent", ascending=False)
                .head(5),
                use_container_width=True
            )
        else:
            st.success("No anomalous processes")

        # ---------------- EDR TIMELINE ----------------
        st.markdown("### 📜 EDR Threat Timeline")

        if "timeline" not in st.session_state:
            st.session_state.timeline = []

        now = time.strftime("%H:%M:%S")

        if cpu_state == "ANOMALY":
            st.session_state.timeline.insert(0, f"{now} — CPU Spike Detected")

        if not suspicious.empty:
            st.session_state.timeline.insert(0, f"{now} — Process Anomaly")

        for event in st.session_state.timeline[:6]:
            st.write("•", event)

        # ---------------- SOC ALERT ----------------
        if severity in ["HIGH","CRITICAL"]:
            st.markdown(
                f"<div class='alert {severity.lower()}'><b>{severity}</b> — Immediate Attention Required</div>",
                unsafe_allow_html=True
            )

# ======================================================
# FOOTER
# ======================================================
st.markdown("---")
st.caption("ForenSight AI • SOC / EDR • IsolationForest • Real-Time")
