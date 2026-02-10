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
        mft, mft_t = load_csv_with_timestamp(mft_file,
            ["modified","mtime","timestamp"], "MFT")
        usn, usn_t = load_csv_with_timestamp(usn_file,
            ["usn_timestamp","timestamp"], "USN")
        logs, log_t = load_csv_with_timestamp(log_file,
            ["timestamp","event_time"], "Logs")
        st.success("✔ Evidence Loaded")

# ======================================================
# TAB 2 — AI CORRELATION (FIXED)
# ======================================================
with tabs[1]:
    st.subheader("🧠 AI Timeline Correlation")

    ai_conf = 0
    total = 0

    if "filename" in locals():
        deltas = []
        for _, m in mft.iterrows():
            match = usn[usn["filename"] == m["filename"]]
            for _, u in match.iterrows():
                deltas.append(abs((u[usn_t]-m[mft_t]).total_seconds()))

        total = len(deltas)

        if total >= 10:
            X = np.array(deltas).reshape(-1,1)
            model = IsolationForest(contamination=0.2)
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
            st.success("Clean")

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
# TAB 5 — AUTO SOC ALERT FEED
# ======================================================
with tabs[4]:
    st.subheader("🚨 SOC Alert Feed (Auto)")

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
# TAB 6 — REAL-TIME MONITORING (ONLY TAB THAT REFRESHES)
# ======================================================
with tabs[5]:
    st.subheader("📡 Live System Monitoring")

    st_autorefresh(interval=2000, key="rt_refresh")

    if not PSUTIL_AVAILABLE:
        st.error("psutil missing")
    else:
        cpu = psutil.cpu_percent(percpu=True)
        total_cpu = round(sum(cpu)/len(cpu),2)
        mem = psutil.virtual_memory()

        # ---------- CPU ANOMALY AI ----------
        if "cpu_hist" not in st.session_state:
            st.session_state.cpu_hist = []

        st.session_state.cpu_hist.append(total_cpu)
        st.session_state.cpu_hist = st.session_state.cpu_hist[-30:]

        anomaly = "NORMAL"
        if len(st.session_state.cpu_hist) >= 10:
            X = np.array(st.session_state.cpu_hist).reshape(-1,1)
            model = IsolationForest(contamination=0.15)
            model.fit(X)
            pred = model.predict([[total_cpu]])
            if pred[0] == -1:
                anomaly = "ANOMALY"

with tabs[6]:
    st.subheader("🧩 EDR & Threat Intelligence Engine")

    if not PSUTIL_AVAILABLE:
        st.warning("EDR simulation requires psutil")
    else:
        # -------------------------------
        # PER-PROCESS ANOMALY SCORING
        # -------------------------------
        st.markdown("### 🔍 Per-Process Anomaly Scoring")

        proc_data = []
        for p in psutil.process_iter(["pid","name","cpu_percent","ppid"]):
            proc_data.append(p.info)

        df_proc = pd.DataFrame(proc_data).fillna(0)

        if len(df_proc) > 10:
            model = IsolationForest(contamination=0.15, random_state=42)
            X = df_proc[["cpu_percent"]]
            df_proc["anomaly"] = model.fit_predict(X)
            df_proc["risk_score"] = df_proc["cpu_percent"] * (df_proc["anomaly"] == -1)

        suspicious = df_proc[df_proc["anomaly"] == -1].sort_values("risk_score", ascending=False)

        st.dataframe(suspicious[["pid","name","cpu_percent","risk_score"]].head(5),
                     use_container_width=True)

        # -------------------------------
        # PROCESS TREE (SIMPLIFIED)
        # -------------------------------
        st.markdown("### 🌳 Process Parent-Child Tree")

        tree = defaultdict(list)
        for _, r in df_proc.iterrows():
            tree[int(r["ppid"])].append(int(r["pid"]))

        for parent, children in list(tree.items())[:5]:
            st.write(f"🧩 Parent PID {parent} → Children: {children}")

        # -------------------------------
        # ATT&CK AUTO-MAPPING
        # -------------------------------
        st.markdown("### 🧬 ATT&CK Auto-Mapping")

        attack_map = []
        for _, r in suspicious.head(5).iterrows():
            attack_map.append({
                "Process": r["name"],
                "Technique": "T1059 Command Execution",
                "Confidence": min(95, int(r["risk_score"] + 40))
            })

        df_attack = pd.DataFrame(attack_map)
        st.table(df_attack)

        # -------------------------------
        # KILL CHAIN VIEW
        # -------------------------------
        st.markdown("### ☠ SOC Kill-Chain View")

        kill_chain = [
            "Reconnaissance",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Impact"
        ]

        for step in kill_chain:
            st.write(f"➡ {step}")

        # -------------------------------
        # HEAT-BASED SEVERITY SCORE
        # -------------------------------
        st.markdown("### 🔥 SOC Severity Heat Score")

        heat_score = int(suspicious["risk_score"].sum()) if not suspicious.empty else 0

        if heat_score > 150:
            st.error(f"🔥 CRITICAL SOC SCORE: {heat_score}")
        elif heat_score > 70:
            st.warning(f"⚠ HIGH SOC SCORE: {heat_score}")
        else:
            st.success(f"✅ NORMAL SOC SCORE: {heat_score}")

        # -------------------------------
        # MULTI-HOST SIMULATION
        # -------------------------------
        st.markdown("### 🖥 Multi-Host SOC View")

        hosts = ["HOST-01","HOST-02","HOST-03"]
        host_data = []

        for h in hosts:
            host_data.append({
                "Host": h,
                "CPU": random.randint(10,95),
                "Alerts": random.randint(0,4)
            })

        st.dataframe(pd.DataFrame(host_data), use_container_width=True)

        # -------------------------------
        # AGENT → SERVER ARCHITECTURE
        # -------------------------------
        st.markdown("### 🛰 Agent → SOC Server Architecture")

        st.code("""
[Endpoint Agent]
     |
     |  (Process, Logs, Metrics)
     v
[Collector / Queue]
     |
     v
[SOC Correlation Engine]
     |
     v
[SIEM / Analyst Dashboard]
        """)

        # -------------------------------
        # EXPORT SOC REPORT
        # -------------------------------
        st.markdown("### 📤 Export SOC Report")

        if st.button("Generate SOC Report"):
            report = suspicious.copy()
            report["Generated"] = datetime.datetime.now()
            report.to_csv("soc_report.csv", index=False)
            st.success("SOC report generated (soc_report.csv)")


        # ---------- METRICS ----------
        c1,c2,c3 = st.columns(3)
        c1.metric("CPU", f"{total_cpu}%")
        c2.metric("Memory", f"{mem.percent}%")
        c3.metric("AI CPU State", anomaly)

        st.markdown("---")

        # ---------- PER CORE ----------
        st.markdown("### 🧠 Per-Core CPU")
        for i,v in enumerate(cpu):
            st.write(f"Core {i}: {v}%")

        # ---------- PROCESS LIST ----------
        st.markdown("### 📋 Top Processes (Read-Only)")
        procs = []
        for p in psutil.process_iter(["name","cpu_percent"]):
            procs.append(p.info)
        dfp = pd.DataFrame(procs).sort_values("cpu_percent", ascending=False).head(5)
        st.dataframe(dfp, use_container_width=True)

        # ---------- SOC CONDITION ----------
        if anomaly == "ANOMALY":
            st.error("🚨 SOC ALERT: CPU Spike Detected")

# ======================================================
# FOOTER
# ======================================================
st.markdown("---")
st.caption("ForenSight AI • SOC-Grade • Demo-Safe • Real-Time")
