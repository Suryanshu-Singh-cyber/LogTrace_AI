import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
import random
import time
import psutil

# ======================================================
# PAGE CONFIG
# ======================================================
st.set_page_config(
    page_title="ForenSight AI | DFIR Platform",
    page_icon="🛡️",
    layout="wide"
)

# ======================================================
# CYBER / SOC UI STYLE
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
        st.warning(f"⚠ No standard timestamp column detected in {label}")
        time_col = st.selectbox(
            f"🕒 Select timestamp column for {label}",
            options=df.columns,
            key=f"{label}_time_select"
        )

    df[time_col] = pd.to_datetime(df[time_col], errors="coerce")
    df = df.dropna(subset=[time_col])

    st.success(f"✔ Using '{time_col}' as timestamp for {label}")
    return df, time_col

# ======================================================
# TABS (NEW TAB ADDED)
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

    if not (mft_file and usn_file and log_file):
        st.info("Upload all forensic artifacts to proceed.")
    else:
        mft, mft_time_col = load_csv_with_timestamp(
            mft_file,
            ["modified", "modified_time", "mtime", "last_modified", "timestamp"],
            "MFT"
        )

        usn, usn_time_col = load_csv_with_timestamp(
            usn_file,
            ["usn_timestamp", "timestamp", "event_time", "timecreated"],
            "USN Journal"
        )

        logs, log_time_col = load_csv_with_timestamp(
            log_file,
            ["timestamp", "time_created", "event_time", "logged_at"],
            "Security Logs"
        )

        st.success("✔ Evidence successfully ingested and normalized")

# ======================================================
# TAB 2 — AI CORRELATION
# ======================================================
with tabs[1]:
    st.subheader("🧠 AI Timeline Correlation")

    deltas = []

    if "filename" in mft.columns and "filename" in usn.columns:
        for _, m in mft.iterrows():
            related = usn[usn["filename"] == m["filename"]]
            for _, u in related.iterrows():
                delta = abs(
                    (u[usn_time_col] - m[mft_time_col]).total_seconds()
                ) / 3600
                deltas.append(delta)

    ai_conf = 0.0
    if len(deltas) >= 3:
        X = np.array(deltas).reshape(-1, 1)
        model = IsolationForest(contamination=0.25, random_state=42)
        model.fit(X)
        ai_conf = round((1 - np.mean(model.decision_function(X))) * 100, 2)

    log_clear = logs[logs.get("event_id", -1).isin([1102, 104])]

    c1, c2, c3 = st.columns(3)
    c1.metric("AI Confidence", f"{ai_conf}%")
    c2.metric("Timestamp Correlations", len(deltas))
    c3.metric("Log Clear Events", len(log_clear))

# ======================================================
# TAB 3 — ANTI-FORENSICS SCANNER
# ======================================================
with tabs[2]:
    st.subheader("🧪 Anti-Forensics Tool Scanner")

    art_file = st.file_uploader("Upload Artifact Evidence CSV", type="csv")

    if art_file:
        artifacts = pd.read_csv(art_file)
        artifacts.columns = artifacts.columns.str.lower().str.strip()

        name_col = next(
            (c for c in ["artifact_name", "process", "name", "artifact"] if c in artifacts.columns),
            None
        )

        if not name_col:
            st.error("❌ No artifact name column found.")
        else:
            tools = [
                "ccleaner.exe", "sdelete.exe",
                "veracrypt.exe", "bleachbit.exe", "cipher.exe"
            ]

            detected = artifacts[
                artifacts[name_col].astype(str).str.lower().isin(tools)
            ]

            if not detected.empty:
                st.error("🚨 Anti-Forensics Tools Detected")
                st.dataframe(detected)
            else:
                st.success("No anti-forensics artifacts found")

# ======================================================
# TAB 4 — MITRE ATT&CK
# ======================================================
with tabs[3]:
    st.subheader("🧬 MITRE ATT&CK Mapping")

    mitre = pd.DataFrame([
        ["T1070.004", "File Deletion", "CCleaner / SDelete", "HIGH"],
        ["T1070.001", "Clear Event Logs", "Event ID 1102", "HIGH"],
        ["T1564.001", "Hidden Files", "MFT timestamp gaps", "MEDIUM"],
        ["T1027", "Obfuscated Files", "Cipher.exe usage", "MEDIUM"]
    ], columns=["Technique ID", "Technique", "Evidence", "Confidence"])

    st.dataframe(mitre)

# ======================================================
# TAB 5 — LIVE SOC ALERTS
# ======================================================
with tabs[4]:
    st.subheader("🚨 Live SOC Alert Feed")

    if st.button("▶ Start SOC Simulation"):
        for _ in range(5):
            sev = random.choice(["HIGH", "MEDIUM", "LOW"])
            st.markdown(
                f"<div class='alert {sev.lower()}'>"
                f"<b>{sev} ALERT</b> — Suspicious anti-forensic activity detected"
                f"</div>",
                unsafe_allow_html=True
            )
            time.sleep(0.8)

# ======================================================
# TAB 6 — REAL-TIME MONITORING (NEW)
# ======================================================
with tabs[5]:
    st.subheader("📡 Live System Monitoring (SOC View)")

    col1, col2, col3, col4 = st.columns(4)

    cpu = psutil.cpu_percent()
    mem = psutil.virtual_memory().percent
    disk = psutil.disk_usage("/").percent
    uptime = int(time.time() - psutil.boot_time()) // 60

    col1.metric("CPU Usage", f"{cpu}%")
    col2.metric("Memory Usage", f"{mem}%")
    col3.metric("Disk Usage", f"{disk}%")
    col4.metric("Uptime", f"{uptime} mins")

    # Live charts
    cpu_hist = [psutil.cpu_percent(interval=0.5) for _ in range(10)]
    mem_hist = [psutil.virtual_memory().percent for _ in range(10)]

    fig, ax = plt.subplots()
    ax.plot(cpu_hist, label="CPU %")
    ax.plot(mem_hist, label="Memory %")
    ax.set_title("Live Resource Usage")
    ax.legend()
    st.pyplot(fig)

# ======================================================
# FOOTER
# ======================================================
st.markdown("---")
st.caption("ForenSight AI • SOC-Grade DFIR • MITRE Aligned • Court-Safe Evidence")
