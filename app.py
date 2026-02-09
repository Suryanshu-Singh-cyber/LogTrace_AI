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
# FILE UPLOAD
# -------------------------------------------------
st.sidebar.header("📂 Upload Forensic Artifacts")

mft_file = st.sidebar.file_uploader("Upload MFT CSV", type=["csv"])
usn_file = st.sidebar.file_uploader("Upload USN Journal CSV", type=["csv"])
log_file = st.sidebar.file_uploader("Upload Windows Log CSV", type=["csv"])

if not (mft_file and usn_file and log_file):
    st.info("Upload MFT, USN Journal, and Windows Event Log CSV files to begin analysis.")
    st.stop()

# -------------------------------------------------
# LOAD DATA
# -------------------------------------------------
mft = pd.read_csv(mft_file, parse_dates=["modified"])
usn = pd.read_csv(usn_file, parse_dates=["usn_timestamp"])
logs = pd.read_csv(log_file, parse_dates=["timestamp"])

# -------------------------------------------------
# NTFS TIMESTOMP DETECTION
# -------------------------------------------------
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
                "mft_modified": str(m["modified"]),
                "usn_time": str(u["usn_timestamp"]),
                "delta_hours": round(float(delta), 2),
                "finding": "Possible Timestomping"
            })

timestomp_df = pd.DataFrame(findings)

# -------------------------------------------------
# LOG TAMPERING DETECTION
# -------------------------------------------------
log_alerts = logs[logs["event_id"].isin([1102, 104])].copy()
log_alerts["timestamp"] = log_alerts["timestamp"].astype(str)

# -------------------------------------------------
# AI MODEL
# -------------------------------------------------
ai_confidence = 0.0
if len(delta_features) >= 3:
    X = np.array(delta_features).reshape(-1, 1)
    model = IsolationForest(contamination=0.25, random_state=42)
    model.fit(X)

    scores = model.decision_function(X)
    ai_confidence = round(float((1 - np.mean(scores)) * 100), 2)

# -------------------------------------------------
# SCORING
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
# TIMELINE
# -------------------------------------------------
st.subheader("📊 Forensic Timeline Correlation")

fig, ax = plt.subplots()
ax.scatter(usn["usn_timestamp"], usn.index, label="USN Events")
ax.scatter(mft["modified"], mft.index, label="MFT Modified")
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
# REPORT OBJECT (SAFE)
# -------------------------------------------------
report = {
    "suspicion_score": int(score),
    "risk_level": risk,
    "ai_confidence": float(ai_confidence),
    "timestomp_findings": findings,
    "log_tampering_events": log_alerts.to_dict(orient="records")
}

# -------------------------------------------------
# EXPORT JSON
# -------------------------------------------------
st.download_button(
    label="⬇️ Download JSON Report",
    data=json.dumps(report, indent=4),
    file_name="logtrace_report.json",
    mime="application/json"
)

# -------------------------------------------------
# EXPORT PDF
# -------------------------------------------------
def generate_pdf(report):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(0, 10, "LogTrace AI – Forensic Report", ln=True)
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
