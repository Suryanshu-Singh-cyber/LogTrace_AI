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
    page_title="ForenSight AI | SOC + EDR",
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
</style>
""", unsafe_allow_html=True)

st.title("🛡️ ForenSight AI")
st.caption("SOC • EDR • DFIR Intelligence Platform")
st.markdown("---")

# ======================================================
# SESSION INIT
# ======================================================
for k in ["cpu_hist","proc_hist","timeline","alerts"]:
    if k not in st.session_state:
        st.session_state[k] = []

# ======================================================
# TABS
# ======================================================
tabs = st.tabs([
    "📥 Evidence",
    "🧠 AI Correlation",
    "🚨 SOC Alerts",
    "📡 EDR Live",
    "🧬 MITRE",
    "🌍 Multi-Host SOC"
])

# ======================================================
# TAB 1 — EVIDENCE
# ======================================================
with tabs[0]:
    st.subheader("📥 Evidence Intake")
    st.info("Offline DFIR artifacts ingestion")

# ======================================================
# TAB 2 — AI CORRELATION
# ======================================================
with tabs[1]:
    st.subheader("🧠 AI Confidence Engine")

    if len(st.session_state.timeline) >= 10:
        X = np.array([e["severity"] for e in st.session_state.timeline]).reshape(-1,1)
        model = IsolationForest(contamination=0.25)
        model.fit(X)
        conf = round((1 - np.mean(model.decision_function(X))) * 100, 2)
    else:
        conf = 0

    st.metric("AI Confidence", f"{conf}%")
    st.metric("Observed Threats", len(st.session_state.timeline))

# ======================================================
# TAB 3 — SOC ALERTS
# ======================================================
with tabs[2]:
    st.subheader("🚨 SOC Alert Feed")

    for a in st.session_state.alerts[-6:][::-1]:
        st.markdown(
            f"<div class='alert {a['sev'].lower()}'><b>{a['sev']}</b> — {a['msg']}</div>",
            unsafe_allow_html=True
        )

# ======================================================
# TAB 4 — EDR LIVE (AUTO REFRESH ONLY HERE)
# ======================================================
with tabs[3]:
    st.subheader("📡 Endpoint Detection & Response")

    st_autorefresh(interval=2000, key="edr_refresh")

    if not PSUTIL_AVAILABLE:
        st.error("psutil not available")
    else:
        # ================= CPU =================
        cpu = psutil.cpu_percent(percpu=True)
        total_cpu = round(np.mean(cpu),2)
        mem = psutil.virtual_memory()

        st.session_state.cpu_hist.append(total_cpu)
        st.session_state.cpu_hist = st.session_state.cpu_hist[-40:]

        # ================= CPU ANOMALY =================
        cpu_state = "NORMAL"
        if len(st.session_state.cpu_hist) >= 15:
            X = np.array(st.session_state.cpu_hist).reshape(-1,1)
            model = IsolationForest(contamination=0.15)
            model.fit(X)
            if model.predict([[total_cpu]])[0] == -1:
                cpu_state = "ANOMALY"

        c1,c2,c3 = st.columns(3)
        c1.metric("CPU", f"{total_cpu}%")
        c2.metric("Memory", f"{mem.percent}%")
        c3.metric("CPU AI", cpu_state)

        # ================= PROCESS SCORING =================
        st.markdown("### 🔍 Per-Process Anomaly Scoring")

        proc_rows = []
        for p in psutil.process_iter(["pid","ppid","name","cpu_percent"]):
            proc_rows.append(p.info)

        pdf = pd.DataFrame(proc_rows).fillna(0)
        if len(pdf) >= 10:
            model = IsolationForest(contamination=0.2)
            pdf["anomaly"] = model.fit_predict(pdf[["cpu_percent"]])
        else:
            pdf["anomaly"] = 1

        suspicious = pdf[pdf["anomaly"] == -1].head(5)

        st.dataframe(suspicious, use_container_width=True)

        # ================= TIMELINE =================
        if cpu_state == "ANOMALY" or not suspicious.empty:
            sev = "HIGH" if cpu_state == "ANOMALY" else "MEDIUM"
            event = {
                "time": time.strftime("%H:%M:%S"),
                "event": "CPU spike / suspicious process",
                "severity": 90 if sev=="HIGH" else 60
            }
            st.session_state.timeline.append(event)
            st.session_state.alerts.append({
                "sev": sev,
                "msg": event["event"]
            })

        st.markdown("### 🧭 EDR Threat Timeline")
        st.dataframe(pd.DataFrame(st.session_state.timeline[-10:]))

# ======================================================
# TAB 5 — MITRE AUTO MAP
# ======================================================
with tabs[4]:
    st.subheader("🧬 MITRE ATT&CK Auto-Mapping")

    mapped = []
    for e in st.session_state.timeline:
        mapped.append([
            "T1059" if e["severity"] > 80 else "T1046",
            "Suspicious Execution",
            e["event"]
        ])

    st.table(pd.DataFrame(mapped, columns=["Technique","Name","Evidence"]))

# ======================================================
# TAB 6 — MULTI-HOST SOC
# ======================================================
with tabs[5]:
    st.subheader("🌍 Multi-Host SOC View")

    hosts = []
    for i in range(3):
        hosts.append({
            "Host": f"Agent-{i+1}",
            "CPU": random.randint(10,95),
            "Threats": random.randint(0,5)
        })

    dfh = pd.DataFrame(hosts)
    st.dataframe(dfh, use_container_width=True)

    # ================= EXPORT =================
    st.download_button(
        "📤 Export SOC Report",
        data=dfh.to_csv(index=False),
        file_name="soc_report.csv",
        mime="text/csv"
    )

# ======================================================
# FOOTER
# ======================================================
st.markdown("---")
st.caption("ForenSight AI • SOC + EDR • Demo-Safe • Production-Style")
