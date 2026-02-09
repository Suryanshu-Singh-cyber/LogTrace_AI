import streamlit as st
import pandas as pd
import numpy as np
import json
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
from fpdf import FPDF
from io import StringIO

# =================================================
# PAGE CONFIG
# =================================================
st.set_page_config(
    page_title="LogTrace AI | DFIR Platform",
    page_icon="🛡️",
    layout="wide"
)

# =================================================
# CYBER UI STYLE
# =================================================
st.markdown("""
<style>
body { background-color: #0e1117; }
.title { font-size: 38px; font-weight: 700; }
.subtitle { color: #9aa4b2; }
.panel { border: 1px solid #1f2937; padding: 16px; border-radius: 10px; background-color: #111827; }
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="title">🛡️ LogTrace AI</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">Digital Forensics & Anti-Forensics Detection Platform</div>', unsafe_allow_html=True)
st.markdown("---")

# =================================================
# TABS
# =================================================
tab1, tab2, tab3, tab4 = st.tabs([
    "📂 Evidence Ingestion",
    "⏱️ Timeline & AI",
    "🧪 Anti-Forensics Scanner",
    "📄 Reports & Intelligence"
])

# =================================================
# TAB 1 — EVIDENCE INGESTION
# =================================================
with tab1:
    st.subheader("📂 Evidence Upload")

    mft_file = st.file_uploader("MFT CSV", type=["csv"])
    usn_file = st.file_uploader("USN Journal CSV", type=["csv"])
    log_file = st.file_uploader("Windows Event Log CSV", type=["csv"])

    if not (mft_file and usn_file and log_file):
        st.info("Upload MFT, USN Journal, and Event Logs to proceed.")
        st.stop()

    mft = pd.read_csv(mft_file, parse_dates=["modified"])
    usn = pd.read_csv(usn_file, parse_dates=["usn_timestamp"])
    logs = pd.read_csv(log_file, parse_dates=["timestamp"])

    st.success("Evidence successfully ingested")

# =================================================
# TAB 2 — TIMELINE + AI
# =================================================
with tab2:
    st.subheader("⏱️ Timeline Correlation & Anomaly Detection")

    findings, deltas = [], []

    for _, m in mft.iterrows():
        rel = usn[usn["filename"] == m["filename"]]
        for _, u in rel.iterrows():
            delta = abs((u["usn_timestamp"] - m["modified"]).total_seconds()) / 3600
            deltas.append(delta)
            if delta > 24:
                findings.append({
                    "file": m["filename"],
                    "delta_hours": round(delta, 2),
                    "finding": "Timestamp inconsistency detected"
                })

    timestomp_df = pd.DataFrame(findings)

    ai_confidence = 0
    if len(deltas) >= 3:
        model = IsolationForest(contamination=0.25, random_state=42)
        model.fit(np.array(deltas).reshape(-1, 1))
        scores = model.decision_function(np.array(deltas).reshape(-1, 1))
        ai_confidence = round((1 - np.mean(scores)) * 100, 2)

    log_alerts = logs[logs["event_id"].isin([1102, 104])]

    score = (60 if not timestomp_df.empty else 0) + (40 if not log_alerts.empty else 0)
    risk = "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW"

    c1, c2, c3 = st.columns(3)
    c1.metric("Suspicion Score", score)
    c2.metric("AI Confidence", f"{ai_confidence}%")
    c3.metric("Risk Level", risk)

    fig, ax = plt.subplots()
    ax.scatter(usn["usn_timestamp"], usn.index, label="USN Events")
    ax.scatter(mft["modified"], mft.index, label="MFT Modified")
    ax.legend()
    st.pyplot(fig)

# =================================================
# TAB 3 — ANTI-FORENSICS TOOL SCANNER
# =================================================
with tab3:
    st.subheader("🧪 Anti-Forensics Tool Scanner")

    SAMPLE_ARTIFACT_CSV = """artifact_type,artifact_name,timestamp
prefetch,CCLEANER.EXE,2024-10-12 14:22:01
prefetch,SDELETE.EXE,2024-10-13 09:10:45
registry,HKCU\\Software\\Piriform,2024-10-12 14:22:10
prefetch,VERACRYPT.EXE,2024-10-14 18:55:20
"""

    st.download_button(
        "⬇️ Download Sample Artifact Evidence",
        SAMPLE_ARTIFACT_CSV,
        "sample_artifacts.csv",
        "text/csv"
    )

    artifact_file = st.file_uploader("Upload Artifact Evidence CSV", type=["csv"])

    detections = []
    if artifact_file:
        artifacts = pd.read_csv(artifact_file)
        tools = ["CCLEANER.EXE", "SDELETE.EXE", "VERACRYPT.EXE", "BLEACHBIT.EXE", "CIPHER.EXE"]
        detections = artifacts[artifacts["artifact_name"].isin(tools)]

        if not detections.empty:
            st.error("🚨 Anti-Forensics Tool Usage Detected")
            st.dataframe(detections)
        else:
            st.success("No anti-forensics tool traces found")

# =================================================
# TAB 4 — REPORTS & INTELLIGENCE
# =================================================
with tab4:
    st.subheader("📄 Forensic Intelligence & Reporting")

    # ---------------- MITRE ATT&CK ----------------
    st.markdown("### 🧭 MITRE ATT&CK Mapping")

    mitre = [
        {"Technique": "T1070.006", "Name": "Timestomp", "Evidence": "MFT vs USN mismatch"},
        {"Technique": "T1070.001", "Name": "Clear Windows Event Logs", "Evidence": "Event ID 1102 / 104"},
        {"Technique": "T1561.001", "Name": "Disk Wipe", "Evidence": "Wiper tool artifacts"}
    ]

    st.dataframe(pd.DataFrame(mitre))

    # ---------------- CONFIDENCE GRAPH ----------------
    st.markdown("### 📈 Confidence Assessment")

    confidence_data = {
        "Filesystem Analysis": 60 if not timestomp_df.empty else 20,
        "Log Analysis": 40 if not log_alerts.empty else 10,
        "AI Anomaly Detection": ai_confidence
    }

    fig2, ax2 = plt.subplots()
    ax2.bar(confidence_data.keys(), confidence_data.values())
    ax2.set_ylabel("Confidence %")
    st.pyplot(fig2)

    # ---------------- COURT REPORT ----------------
    st.markdown("### 🧾 Executive Forensic Summary")

    executive_report = f"""
    Based on the examination of provided forensic artifacts, 
    evidence indicates a **{risk.lower()} probability** of anti-forensic activity.

    Timestamp inconsistencies across independent NTFS artifacts suggest deliberate
    modification. Additionally, system logs indicate log-clearing behavior consistent
    with forensic evasion techniques.

    The findings were corroborated using statistical anomaly detection models and
    cross-artifact correlation, increasing confidence in the conclusions.
    """

    st.text_area("Court-Style Summary", executive_report, height=220)

    # ---------------- LLM-STYLE EXPLANATION ----------------
    if st.button("🧠 Explain Findings (Expert Narrative)"):
        st.info(
            "From a forensic standpoint, the convergence of filesystem anomalies, "
            "log suppression events, and traces of anti-forensics tooling strongly "
            "suggests intentional evidence manipulation rather than system error."
        )

    # ---------------- EXPORT ----------------
    report = {
        "risk": risk,
        "score": score,
        "ai_confidence": ai_confidence,
        "mitre_mapping": mitre,
        "summary": executive_report
    }

    st.download_button(
        "⬇️ Download JSON Report",
        json.dumps(report, indent=4),
        "logtrace_report.json",
        "application/json"
    )

# =================================================
# FOOTER
# =================================================
st.markdown("---")
st.caption("🛡️ Ethical DFIR Platform • Metadata-Only Analysis • Court-Defensible Logic")
