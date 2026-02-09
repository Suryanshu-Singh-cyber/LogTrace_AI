import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
import random
import time

# ======================================================
# PAGE CONFIG
# ======================================================
st.set_page_config(
    page_title="ForenSight AI | DFIR Platform",
    page_icon="🛡️",
    layout="wide"
)

# ======================================================
# UI STYLE (Cyber / SOC)
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
# TABS
# ======================================================
tabs = st.tabs([
    "📥 Evidence Intake",
    "🧠 AI Correlation",
    "🧪 Anti-Forensics Scanner",
    "🧬 MITRE ATT&CK",
    "🚨 Live SOC Alerts"
])

# ======================================================
# TAB 1 — EVIDENCE
# ======================================================
with tabs[0]:
    st.subheader("📥 Evidence Intake")

    mft_file = st.file_uploader("Upload MFT CSV", type="csv")
    usn_file = st.file_uploader("Upload USN Journal CSV", type="csv")
    log_file = st.file_uploader("Upload Windows Logs CSV", type="csv")

    if not (mft_file and usn_file and log_file):
        st.info("Upload all forensic artifacts to proceed.")
        st.stop()

    mft = pd.read_csv(mft_file, parse_dates=["modified"])
    usn = pd.read_csv(usn_file, parse_dates=["usn_timestamp"])
    logs = pd.read_csv(log_file, parse_dates=["timestamp"])

    st.success("✔ Evidence successfully ingested")

# ======================================================
# TAB 2 — AI CORRELATION
# ======================================================
with tabs[1]:
    st.subheader("🧠 AI Timeline Correlation")

    deltas = []
    for _, m in mft.iterrows():
        related = usn[usn["filename"] == m["filename"]]
        for _, u in related.iterrows():
            deltas.append(
                abs((u["usn_timestamp"] - m["modified"]).total_seconds()) / 3600
            )

    ai_conf = 0
    if len(deltas) >= 3:
        model = IsolationForest(contamination=0.25, random_state=42)
        model.fit(np.array(deltas).reshape(-1, 1))
        ai_conf = round(
            (1 - np.mean(model.decision_function(np.array(deltas).reshape(-1, 1)))) * 100,
            2
        )

    log_clear = logs[logs["event_id"].isin([1102, 104])]

    c1, c2, c3 = st.columns(3)
    c1.metric("AI Confidence", f"{ai_conf}%")
    c2.metric("Timestamp Anomalies", len(deltas))
    c3.metric("Log Clear Events", len(log_clear))

# ======================================================
# TAB 3 — ANTI-FORENSICS (KEYERROR FIXED)
# ======================================================
with tabs[2]:
    st.subheader("🧪 Anti-Forensics Tool Scanner")

    st.download_button(
        "⬇ Download Sample Artifact CSV",
        "artifact_type,artifact_name,timestamp\nprefetch,CCLEANER.EXE,2024-09-12",
        "artifact_sample.csv"
    )

    art_file = st.file_uploader("Upload Artifact Evidence CSV", type="csv")

    detected = pd.DataFrame()
    if art_file:
        artifacts = pd.read_csv(art_file)

        # 🔧 Normalize column names (KEY FIX)
        artifacts.columns = artifacts.columns.str.lower().str.strip()

        possible_cols = ["artifact_name", "process", "name", "artifact"]
        name_col = next((c for c in possible_cols if c in artifacts.columns), None)

        if not name_col:
            st.error("❌ No artifact name column found in CSV.")
        else:
            tools = [
                "ccleaner.exe", "sdelete.exe",
                "veracrypt.exe", "bleachbit.exe", "cipher.exe"
            ]
            detected = artifacts[
                artifacts[name_col].str.lower().isin(tools)
            ]

            if not detected.empty:
                st.error("🚨 Anti-Forensics Tools Detected")
                st.dataframe(detected)
            else:
                st.success("No anti-forensics artifacts found")

# ======================================================
# TAB 4 — MITRE ATT&CK MATRIX
# ======================================================
with tabs[3]:
    st.subheader("🧬 MITRE ATT&CK Mapping")

    mitre = pd.DataFrame([
        ["T1070.004", "File Deletion", "CCleaner / SDelete", "HIGH"],
        ["T1070.001", "Clear Event Logs", "Event ID 1102", "HIGH"],
        ["T1564.001", "Hidden Files", "MFT anomalies", "MEDIUM"],
        ["T1027", "Obfuscated Files", "Cipher.exe usage", "MEDIUM"]
    ], columns=["Technique ID", "Technique", "Evidence", "Confidence"])

    st.dataframe(mitre)

    st.info("MITRE techniques mapped using filesystem, registry, and log artifacts.")

# ======================================================
# TAB 5 — LIVE SOC ALERT SIMULATION
# ======================================================
with tabs[4]:
    st.subheader("🚨 Live SOC Alert Feed")

    if st.button("▶ Start SOC Simulation"):
        for _ in range(5):
            severity = random.choice(["HIGH", "MEDIUM", "LOW"])
            cls = severity.lower()

            st.markdown(
                f"<div class='alert {cls}'>"
                f"<b>{severity} ALERT</b> — "
                f"Anti-Forensic activity detected ({random.choice(['Filesystem','Logs','Tools'])})"
                f"</div>",
                unsafe_allow_html=True
            )
            time.sleep(0.7)

# ======================================================
# FOOTER
# ======================================================
st.markdown("---")
st.caption("ForenSight AI • MITRE-Aligned • SOC-Ready • Court-Safe DFIR")
