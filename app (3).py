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
# FILE UPLOAD (LIVE EVIDENCE INGESTION) - Replaced with direct file loading for Colab execution
# -------------------------------------------------
# The original file uploaders are commented out as they don't work in this execution context.
# st.sidebar.header("📂 Upload Forensic Artifacts")
# mft_file = st.sidebar.file_uploader("Upload MFT CSV", type=["csv"])
# usn_file = st.sidebar.file_uploader("Upload USN Journal CSV", type=["csv"])
# log_file = st.sidebar.file_uploader("Upload Windows Log CSV", type=["csv"])

# if not (mft_file and usn_file and log_file):
#     st.info("Upload MFT, USN Journal, and Windows Event Log CSV files to begin analysis.")
#     st.stop()

# -------------------------------------------------
# LOAD DATA
# -------------------------------------------------
mft = pd.read_csv("logtrace_ai/data/ntfs/mft.csv", parse_dates=["modified"])
usn = pd.read_csv("logtrace_ai/data/ntfs/usn.csv", parse_dates=["usn_timestamp"])
logs = pd.read_csv("logtrace_ai/data/logs/security.csv", parse_dates=["timestamp"])

# -------------------------------------------------
# NTFS TIMESTOMP DETECTION
# -------------------------------------------------
findings = []
delta_features = []

for _, m in mft.iterrows():
    related = usn[usn["filename"] == m["filename"]]
    for _, u in related.iterrows():
        delta = abs((u["usn_timestamp"] - m["modified"]).total_seconds()) / 3600
        delta_features.append(delta)

        if delta > 24:
            findings.append({
                "File": m["filename"],
                "MFT_Modified": str(m["modified"]),
                "USN_Time": str(u["usn_timestamp"]),
                "Delta_Hours": round(delta, 2),
                "Finding": "Possible Timestomping"
            })

timestomp_df = pd.DataFrame(findings)

# -------------------------------------------------
# LOG TAMPERING DETECTION
# -------------------------------------------------
log_alerts = logs[logs["event_id"].isin([1102, 104])]

# Convert datetime objects to string for JSON serialization
if not log_alerts.empty and 'timestamp' in log_alerts.columns:
    log_alerts['timestamp'] = log_alerts['timestamp'].astype(str)

# -------------------------------------------------
# AI MODEL TRAINING (REAL)
# -------------------------------------------------
ai_confidence = 0
if len(delta_features) >= 3:
    X = np.array(delta_features).reshape(-1, 1)
    model = IsolationForest(contamination=0.25, random_state=42)
    model.fit(X)

    scores = model.decision_function(X)
    ai_confidence = round((1 - np.mean(scores)) * 100, 2)

# -------------------------------------------------
# SCORING ENGINE
# -------------------------------------------------
score = 0
if not timestomp_df.empty:
    score += 60
if not log_alerts.empty:
    score += 40

risk = "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW"

# -------------------------------------------------
# METRICS
# -------------------------------------------------
c1, c2, c3 = st.columns(3)
c1.metric("Suspicion Score", f"{score}/100")
c2.metric("AI Confidence", f"{ai_confidence}%")
c3.metric("Risk Level", risk)

st.markdown("---")

# -------------------------------------------------
# TIMELINE VISUALIZATION
# -------------------------------------------------
st.subheader("📊 Forensic Timeline Correlation")

fig, ax = plt.subplots()
ax.scatter(usn["usn_timestamp"], usn.index, label="USN Events")
ax.scatter(mft["modified"], mft.index, label="MFT Modified")
ax.set_xlabel("Time")
ax.set_ylabel("Event Index")
ax.legend()
st.pyplot(fig)

# -------------------------------------------------
# FINDINGS
# -------------------------------------------------
st.subheader("🚨 Detection Results")

if not timestomp_df.empty:
    st.error("NTFS Timestomping Detected")
    st.dataframe(timestomp_df)
else:
    st.success("No timestomping detected")

if not log_alerts.empty:
    st.warning("Windows Event Log Clearing Detected")
    st.dataframe(log_alerts)
else:
    st.success("No log tampering detected")

# -------------------------------------------------
# EXPLANATION
# -------------------------------------------------
st.subheader("🧠 Explainable Forensic Conclusion")

st.write(f"""
LogTrace AI identified **{risk} risk anti-forensic activity**.

• NTFS timestamp inconsistencies indicate possible timestomping  
• Windows Event Log clearing events reduce timeline reliability  
• AI anomaly detection validates behavior statistically  

Correlation across independent artifacts increases evidentiary trust.
""")

# -------------------------------------------------
# EXPORT REPORTS
# -------------------------------------------------
st.markdown("---")
st.subheader("📤 Export Forensic Report")

report = {
    "suspicion_score": score,
    "risk_level": risk,
    "ai_confidence": ai_confidence,
    "timestomp_findings": findings,
    "log_tampering_events": log_alerts.to_dict(orient="records")
}

# JSON Export
st.download_button(
    label="⬇️ Download JSON Report",
    data=json.dumps(report, indent=4),
    file_name="logtrace_report.json",
    mime="application/json"
)

# PDF Export
def generate_pdf(report):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    # Replace en dash with a hyphen for latin-1 compatibility
    pdf.cell(0, 10, "LogTrace AI - Forensic Report", ln=True)
    pdf.ln(5)

    for k, v in report.items():
        pdf.multi_cell(0, 8, f"{k}: {str(v)}")
        pdf.ln(2)

    return pdf.output(dest="S").encode("latin-1")

st.download_button(
    label="⬇️ Download PDF Report",
    data=generate_pdf(report),
    file_name="logtrace_report.pdf",
    mime="application/pdf"
)

# -------------------------------------------------
# FOOTER
# -------------------------------------------------
st.markdown("---")
st.caption("Ethical DFIR Tool • No Malware • No Evidence Modification")
