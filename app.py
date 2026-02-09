import streamlit as st
import pandas as pd
import numpy as np
import json
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
from fpdf import FPDF

# -------------------------------------------------
# CONFIG
# -------------------------------------------------
st.set_page_config(
    page_title="LogTrace AI",
    page_icon="🔍",
    layout="wide"
)

st.title("🔍 LogTrace AI")
st.caption("Automated Detection of Anti-Forensic Techniques (DFIR Framework)")
st.markdown("---")

# -------------------------------------------------
# TABS
# -------------------------------------------------
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📂 Evidence Ingestion",
    "⏱️ Timeline & AI Analysis",
    "🧪 Anti-Forensics Tool Scanner",
    "📊 Confidence & MITRE Mapping",
    "📄 Court-Ready Reports"
])

# =================================================
# TAB 1 — EVIDENCE INGESTION
# =================================================
with tab1:
    st.subheader("📂 Upload Core Forensic Evidence")

    mft_file = st.file_uploader("Upload MFT CSV", type=["csv"])
    usn_file = st.file_uploader("Upload USN Journal CSV", type=["csv"])
    log_file = st.file_uploader("Upload Windows Event Logs CSV", type=["csv"])

    if not (mft_file and usn_file and log_file):
        st.info("Upload all required artifacts to begin analysis.")
        st.stop()

    mft = pd.read_csv(mft_file, parse_dates=["modified"])
    usn = pd.read_csv(usn_file, parse_dates=["usn_timestamp"])
    logs = pd.read_csv(log_file, parse_dates=["timestamp"])

    st.success("Evidence successfully ingested.")

# =================================================
# TAB 2 — TIMELINE + AI
# =================================================
with tab2:
    st.subheader("⏱️ Timeline Correlation & AI Anomaly Detection")

    findings = []
    delta_features = []

    for _, m in mft.iterrows():
        related = usn[usn["filename"] == m["filename"]]
        for _, u in related.iterrows():
            delta = abs((u["usn_timestamp"] - m["modified"]).total_seconds()) / 3600
            delta_features.append(float(delta))

            if delta > 24:
                findings.append({
                    "file": m["filename"],
                    "delta_hours": round(delta, 2),
                    "finding": "Possible NTFS Timestomping"
                })

    timestomp_df = pd.DataFrame(findings)

    log_alerts = logs[logs["event_id"].isin([1102, 104])].copy()
    log_alerts["timestamp"] = log_alerts["timestamp"].astype(str)

    ai_confidence = 0.0
    if len(delta_features) >= 3:
        X = np.array(delta_features).reshape(-1, 1)
        model = IsolationForest(contamination=0.25, random_state=42)
        model.fit(X)
        scores = model.decision_function(X)
        ai_confidence = round(float((1 - np.mean(scores)) * 100), 2)

    score = 0
    if not timestomp_df.empty:
        score += 60
    if not log_alerts.empty:
        score += 40

    risk = "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW"

    c1, c2, c3 = st.columns(3)
    c1.metric("Suspicion Score", f"{score}/100")
    c2.metric("AI Confidence", f"{ai_confidence}%")
    c3.metric("Risk Level", risk)

    fig, ax = plt.subplots()
    ax.hist(delta_features, bins=20)
    ax.set_title("Timestamp Deviation Distribution")
    ax.set_xlabel("Delta (Hours)")
    ax.set_ylabel("Frequency")
    st.pyplot(fig)

# =================================================
# TAB 3 — ANTI-FORENSICS TOOL SCANNER
# =================================================
with tab3:
    st.subheader("🧪 Anti-Forensics Tool Detection")

    ANTI_FORENSIC_TOOLS = {
        "CCleaner": "T1070.004",
        "SDelete": "T1070.004",
        "BleachBit": "T1070.004",
        "Cipher.exe": "T1070.004",
        "VeraCrypt": "T1564.001"
    }

    artifact_file = st.file_uploader("Upload Artifact Evidence CSV", type=["csv"])

    detections = []

    if artifact_file:
        artifacts = pd.read_csv(artifact_file)

        for tool in ANTI_FORENSIC_TOOLS:
            if tool.upper() in artifacts["artifact_name"].str.upper().values:
                detections.append({
                    "Tool": tool,
                    "MITRE_Technique": ANTI_FORENSIC_TOOLS[tool],
                    "Risk": "HIGH"
                })

        if detections:
            st.error("🚨 Anti-Forensics Tools Detected")
            st.dataframe(pd.DataFrame(detections))
        else:
            st.success("No anti-forensics tools detected.")

    tool_score = min(len(detections) * 30, 100)
    st.metric("Tool Usage Confidence", f"{tool_score}%")

# =================================================
# TAB 4 — MITRE + CONFIDENCE GRAPH
# =================================================
with tab4:
    st.subheader("📊 MITRE ATT&CK Mapping & Confidence Graph")

    mitre_df = pd.DataFrame([
        {"Technique": "T1070.004", "Name": "File Deletion"},
        {"Technique": "T1564.001", "Name": "Hidden Files & Directories"}
    ])

    st.table(mitre_df)

    confidence_df = pd.DataFrame({
        "Component": ["Filesystem", "Logs", "Tool Artifacts", "AI"],
        "Confidence": [
            60 if not timestomp_df.empty else 10,
            40 if not log_alerts.empty else 10,
            tool_score,
            ai_confidence
        ]
    })

    fig2, ax2 = plt.subplots()
    ax2.bar(confidence_df["Component"], confidence_df["Confidence"])
    ax2.set_ylim(0, 100)
    ax2.set_ylabel("Confidence (%)")
    st.pyplot(fig2)

# =================================================
# TAB 5 — COURT REPORT + LLM EXPLANATION
# =================================================
with tab5:
    st.subheader("🧾 Court-Style Executive Report")

    executive_summary = f"""
    Based on forensic analysis of NTFS metadata, USN Journal entries,
    Windows Event Logs, and artifact indicators, the system identified
    a {risk} probability of deliberate anti-forensic activity.

    The correlation of timestamp manipulation, log clearing events,
    and traces of forensic-evasion tools significantly increases
    evidentiary confidence.

    This analysis examined metadata only. No file contents were accessed.
    """

    st.text_area("Executive Summary (Court-Ready)", executive_summary, height=200)

    st.subheader("🧠 AI Forensic Explanation (LLM-Style)")

    llm_explanation = f"""
    The AI model evaluated temporal inconsistencies between filesystem
    artifacts and journaling mechanisms. Deviations exceeding normal
    operational thresholds were flagged as anomalous.

    The presence of known anti-forensics utilities further strengthens
    the hypothesis of intentional evidence manipulation rather than
    system error or benign user behavior.
    """

    st.info(llm_explanation)

    report = {
        "risk_level": risk,
        "suspicion_score": score,
        "ai_confidence": ai_confidence,
        "mitre_mapping": ANTI_FORENSIC_TOOLS,
        "summary": executive_summary
    }

    st.download_button(
        "⬇️ Download JSON Court Report",
        json.dumps(report, indent=4),
        "logtrace_court_report.json",
        "application/json"
    )

    def generate_pdf(text):
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.multi_cell(0, 8, text)
        return pdf.output(dest="S").encode("latin-1")

    st.download_button(
        "⬇️ Download Court PDF",
        generate_pdf(executive_summary + "\n\n" + llm_explanation),
        "logtrace_court_report.pdf",
        "application/pdf"
    )

# -------------------------------------------------
# FOOTER
# -------------------------------------------------
st.markdown("---")
st.caption("LogTrace AI • Ethical DFIR • Metadata-Only • MITRE-Aligned")
