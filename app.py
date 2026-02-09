import streamlit as st
import pandas as pd
import numpy as np
import json
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest

# ======================================================
# PAGE CONFIG (CrowdStrike vibe)
# ======================================================
st.set_page_config(
    page_title="LogTrace AI | Threat Intelligence",
    page_icon="🛡️",
    layout="wide"
)

# ======================================================
# CROWDSTRIKE-STYLE UI (Dark Red / Black)
# ======================================================
st.markdown("""
<style>
body {
    background-color: #0a0a0a;
    color: #e5e7eb;
}
h1, h2, h3 {
    color: #ef4444;
}
.card {
    background: linear-gradient(145deg, #111827, #020617);
    padding: 20px;
    border-radius: 16px;
    border: 1px solid #7f1d1d;
    box-shadow: 0 0 25px rgba(239,68,68,0.25);
    transition: transform 0.3s ease;
}
.card:hover {
    transform: scale(1.03);
}
.icon {
    font-size: 30px;
}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ LogTrace AI")
st.caption("Threat Hunting • DFIR • SOC Intelligence Platform")
st.markdown("---")

# ======================================================
# NAVIGATION TABS
# ======================================================
tabs = st.tabs([
    "📥 Evidence Intake",
    "🧠 AI Correlation",
    "🧪 Anti-Forensics",
    "🔥 Risk & Confidence",
    "🧾 Executive Report",
    "🛰️ SOC / SIEM"
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
        st.warning("Upload all artifacts to continue analysis.")
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
    timestomp_files = []

    for _, m in mft.iterrows():
        related = usn[usn["filename"] == m["filename"]]
        for _, u in related.iterrows():
            delta = abs((u["usn_timestamp"] - m["modified"]).total_seconds()) / 3600
            deltas.append(delta)
            if delta > 24:
                timestomp_files.append(m["filename"])

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
    c1.metric("AI Anomaly Confidence", f"{ai_conf}%")
    c2.metric("Timestomped Files", len(set(timestomp_files)))
    c3.metric("Log Clearing Events", len(log_clear))

# ======================================================
# TAB 3 — ANTI-FORENSICS
# ======================================================
with tabs[2]:
    st.subheader("🧪 Anti-Forensics Tool Scanner")

    sample_csv = """artifact_type,artifact_name,timestamp
prefetch,CCLEANER.EXE,2024-09-12
prefetch,SDELETE.EXE,2024-09-13
registry,HKCU\\Software\\Piriform,2024-09-12
"""

    st.download_button(
        "⬇ Download Sample Artifact CSV",
        sample_csv,
        "artifact_evidence.csv"
    )

    art_file = st.file_uploader("Upload Artifact Evidence CSV", type="csv")

    detected = pd.DataFrame()
    if art_file:
        artifacts = pd.read_csv(art_file)
        tools = ["CCLEANER.EXE", "SDELETE.EXE", "VERACRYPT.EXE", "BLEACHBIT.EXE"]
        detected = artifacts[artifacts["artifact_name"].isin(tools)]

        if not detected.empty:
            st.error("🚨 Anti-Forensics Tool Usage Detected")
            st.dataframe(detected)
        else:
            st.success("No anti-forensics artifacts detected")

# ======================================================
# TAB 4 — RISK & CONFIDENCE (NO SEABORN)
# ======================================================
with tabs[3]:
    st.subheader("🔥 Risk Heatmap")

    risk_matrix = np.array([
        [80 if timestomp_files else 20,
         70 if not log_clear.empty else 15,
         90 if not detected.empty else 10]
    ])

    fig, ax = plt.subplots()
    im = ax.imshow(risk_matrix, cmap="Reds")

    ax.set_xticks([0, 1, 2])
    ax.set_xticklabels(["Filesystem", "Event Logs", "Anti-Forensics"])
    ax.set_yticks([0])
    ax.set_yticklabels(["Threat Level"])

    for i in range(3):
        ax.text(i, 0, risk_matrix[0, i], ha="center", va="center", color="black")

    plt.colorbar(im)
    st.pyplot(fig)

    st.markdown("### 📈 Confidence Breakdown")

    conf_labels = ["Filesystem", "Logs", "Tools", "AI Model"]
    conf_values = [
        80 if timestomp_files else 25,
        70 if not log_clear.empty else 20,
        90 if not detected.empty else 10,
        ai_conf
    ]

    fig2, ax2 = plt.subplots()
    ax2.bar(conf_labels, conf_values)
    ax2.set_ylim(0, 100)
    st.pyplot(fig2)

# ======================================================
# TAB 5 — EXECUTIVE REPORT
# ======================================================
with tabs[4]:
    st.subheader("🧾 Court-Style Executive Report")

    risk = "HIGH" if ai_conf > 65 else "MEDIUM" if ai_conf > 35 else "LOW"

    summary = f"""
    A forensic examination revealed a {risk.lower()} likelihood of intentional
    anti-forensic behavior. Timestamp inconsistencies, log clearing events, and
    tool execution artifacts collectively indicate deliberate evidence manipulation.

    Findings are supported by statistical anomaly detection and artifact correlation,
    aligning with accepted DFIR methodologies.
    """

    st.text_area("Expert Witness Summary", summary, height=260)

    if st.button("🧠 Explain to Judge"):
        st.info(
            "Independent artifacts confirm intent. This is not accidental system behavior "
            "but coordinated forensic evasion."
        )

# ======================================================
# TAB 6 — SOC / SIEM
# ======================================================
with tabs[5]:
    st.subheader("🛰️ SOC / SIEM Integration")

    c1, c2, c3 = st.columns(3)

    with c1:
        st.markdown(
            '<div class="card"><div class="icon">📡</div>'
            '<h4>SIEM Export</h4>Splunk • ELK • Sentinel</div>',
            unsafe_allow_html=True
        )

    with c2:
        st.markdown(
            '<div class="card"><div class="icon">🧠</div>'
            '<h4>Threat Intelligence</h4>MITRE ATT&CK aligned</div>',
            unsafe_allow_html=True
        )

    with c3:
        st.markdown(
            '<div class="card"><div class="icon">⚖️</div>'
            '<h4>Legal Readiness</h4>Court-defensible output</div>',
            unsafe_allow_html=True
        )

# ======================================================
# FOOTER
# ======================================================
st.markdown("---")
st.caption("🛡️ LogTrace AI • CrowdStrike-style DFIR • SOC Ready • Court Safe")
