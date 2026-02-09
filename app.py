import streamlit as st
import pandas as pd
import numpy as np
import random
import time

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
# SOC UI STYLE
# ======================================================
st.markdown("""
<style>
body { background-color: #020617; color: #e5e7eb; }
h1,h2,h3 { color: #ef4444; }
.alert { padding:12px;border-radius:10px;margin-bottom:10px; }
.high { background:#7f1d1d; }
.medium { background:#78350f; }
.low { background:#064e3b; }
.card {
 background:linear-gradient(145deg,#020617,#111827);
 padding:20px;border-radius:16px;border:1px solid #7f1d1d;
 box-shadow:0 0 25px rgba(239,68,68,.25)
}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ ForenSight AI")
st.caption("Anti-Forensics • DFIR • SOC Intelligence Platform")
st.markdown("---")

# ======================================================
# CSV LOADER
# ======================================================
def load_csv_with_timestamp(file, possible_time_cols, label):
    df = pd.read_csv(file)
    df.columns = df.columns.str.lower().str.strip()

    time_col = next((c for c in possible_time_cols if c in df.columns), None)

    if not time_col:
        st.warning(f"⚠ Timestamp column missing in {label}")
        time_col = st.selectbox(
            f"Select timestamp column for {label}",
            options=df.columns,
            key=f"{label}_time"
        )

    df[time_col] = pd.to_datetime(df[time_col], errors="coerce")
    df = df.dropna(subset=[time_col])

    st.success(f"✔ Using '{time_col}' for {label}")
    return df, time_col

# ======================================================
# TABS
# ======================================================
tabs = st.tabs([
    "📥 Evidence Intake",
    "🧠 AI Correlation",
    "🧪 Anti-Forensics Scanner",
    "🧬 MITRE ATT&CK",
    "🚨 Live SOC Alerts",
    "📡 Real-Time Monitoring"
])

# ======================================================
# TAB 1 — EVIDENCE INTAKE
# ======================================================
with tabs[0]:
    st.subheader("📥 Evidence Intake")

    mft_file = st.file_uploader("Upload MFT CSV", type="csv")
    usn_file = st.file_uploader("Upload USN Journal CSV", type="csv")
    log_file = st.file_uploader("Upload Windows Logs CSV", type="csv")

    if mft_file and usn_file and log_file:
        mft, mft_t = load_csv_with_timestamp(
            mft_file,
            ["modified", "modified_time", "mtime", "last_modified", "timestamp"],
            "MFT"
        )
        usn, usn_t = load_csv_with_timestamp(
            usn_file,
            ["usn_timestamp", "timestamp", "event_time"],
            "USN Journal"
        )
        logs, log_t = load_csv_with_timestamp(
            log_file,
            ["timestamp", "event_time", "logged_at"],
            "Security Logs"
        )
        st.success("✔ Evidence ingested successfully")
    else:
        st.info("Upload all artifacts to continue.")

# ======================================================
# TAB 2 — AI CORRELATION
# ======================================================
with tabs[1]:
    st.subheader("🧠 AI Timeline Correlation")

    deltas = []
    if "filename" in mft.columns and "filename" in usn.columns:
        for _, m in mft.iterrows():
            match = usn[usn["filename"] == m["filename"]]
            for _, u in match.iterrows():
                deltas.append(abs((u[usn_t] - m[mft_t]).total_seconds()))

    ai_conf = 0
    if len(deltas) >= 3:
        model = IsolationForest(contamination=0.25, random_state=42)
        X = np.array(deltas).reshape(-1, 1)
        model.fit(X)
        ai_conf = round((1 - np.mean(model.decision_function(X))) * 100, 2)

    c1, c2 = st.columns(2)
    c1.metric("AI Confidence", f"{ai_conf}%")
    c2.metric("Correlated Events", len(deltas))

# ======================================================
# TAB 3 — ANTI-FORENSICS SCANNER
# ======================================================
with tabs[2]:
    st.subheader("🧪 Anti-Forensics Scanner")

    art_file = st.file_uploader("Upload Artifact Evidence CSV", type="csv")

    if art_file:
        df = pd.read_csv(art_file)
        df.columns = df.columns.str.lower()

        col = next((c for c in ["artifact", "process", "name"] if c in df.columns), None)

        if col:
            tools = ["ccleaner.exe", "sdelete.exe", "bleachbit.exe", "veracrypt.exe"]
            hits = df[df[col].astype(str).str.lower().isin(tools)]
            if not hits.empty:
                st.error("🚨 Anti-Forensics Detected")
                st.dataframe(hits)
            else:
                st.success("No anti-forensics tools found")
        else:
            st.error("Artifact name column not found")

# ======================================================
# TAB 4 — MITRE
# ======================================================
with tabs[3]:
    st.subheader("🧬 MITRE ATT&CK Mapping")
    st.dataframe(pd.DataFrame([
        ["T1070.004", "File Deletion", "CCleaner", "HIGH"],
        ["T1070.001", "Log Clearing", "Event 1102", "HIGH"],
        ["T1564.001", "Hidden Files", "Timestamp gaps", "MEDIUM"]
    ], columns=["ID", "Technique", "Evidence", "Confidence"]))

# ======================================================
# TAB 5 — SOC ALERTS
# ======================================================
with tabs[4]:
    st.subheader("🚨 Live SOC Alert Feed")
    if st.button("▶ Start SOC Simulation"):
        for _ in range(5):
            sev = random.choice(["HIGH", "MEDIUM", "LOW"])
            st.markdown(
                f"<div class='alert {sev.lower()}'><b>{sev}</b> — Suspicious activity</div>",
                unsafe_allow_html=True
            )
            time.sleep(0.7)

# ======================================================
# TAB 6 — REAL-TIME MONITORING (TASK MANAGER STYLE)
# ======================================================
with tabs[5]:
    st.subheader("📡 Live System Monitoring (Task Manager View)")

    # 🔁 Auto refresh every 2 seconds
    st_autorefresh(interval=2000, limit=None, key="soc_refresh")

    if not PSUTIL_AVAILABLE:
        st.warning("psutil not installed — live monitoring disabled.")
    else:
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        net = psutil.net_io_counters()
        uptime = int(time.time() - psutil.boot_time())

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("CPU", f"{cpu}%")
        c2.metric("Memory", f"{mem.percent}%")
        c3.metric("Disk", f"{disk.percent}%")
        c4.metric("Uptime", f"{uptime//60} min")

        st.markdown("---")

        a, b = st.columns(2)
        with a:
            st.markdown("### 🧠 CPU")
            st.write(f"Cores: {psutil.cpu_count(logical=True)}")
            st.write(f"Frequency: {int(psutil.cpu_freq().current)} MHz")

        with b:
            st.markdown("### 💾 Memory")
            st.write(f"Total: {round(mem.total/1e9,2)} GB")
            st.write(f"Available: {round(mem.available/1e9,2)} GB")

        st.markdown("### 🌐 Network")
        st.write(f"Sent: {round(net.bytes_sent/1e6,2)} MB")
        st.write(f"Received: {round(net.bytes_recv/1e6,2)} MB")

        if cpu > 80 or mem.percent > 80:
            st.error("🚨 High System Load")
        elif cpu > 50:
            st.warning("⚠ Moderate Load")
        else:
            st.success("✅ System Normal")

# ======================================================
# FOOTER
# ======================================================
st.markdown("---")
st.caption("ForenSight AI • SOC-Grade DFIR • MITRE Aligned • Demo-Safe")
