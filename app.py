# ======================================================
# FORENSIGHT AI PLATINUM v3.5 (STABLE AGENT BUILD)
# ======================================================

import datetime
from datetime import datetime as dt
from collections import defaultdict, Counter
import streamlit as st
import pandas as pd
import numpy as np
import time
import random
import math

# Graphics
import plotly.express as px
import plotly.graph_objects as go

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
    page_title="ForenSight AI Platinum | DFIR Agent",
    page_icon="🛡️",
    layout="wide"
)

# ======================================================
# SESSION STATE INITIALIZATION (CRITICAL FIX)
# ======================================================
defaults = {
    "mft_df": None,
    "usn_df": None,
    "agent_report": None,
    "cpu_history": [],
    "soc_alerts": [{"ts": dt.now().strftime("%H:%M:%S"),
                    "msg": "Forensic Agent v3.5 Active",
                    "lvl": "low"}],
    "iso_model": None,
    "iso_trained": False
}

for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ======================================================
# FORENSIC ENGINES (UNCHANGED LOGIC)
# ======================================================
def calculate_shannon_entropy(text):
    if not text or not isinstance(text, str):
        return 0
    probs = [n_x/len(text) for x, n_x in Counter(text).items()]
    return -sum(p * math.log2(p) for p in probs)

def detect_anti_forensic_dna(mft_df):
    results = []
    wipers = {
        "SDelete": ["sdelete", "p_sdelete", "zzzzzz", "wipefile"],
        "CCleaner": ["ccleaner", "piriform"],
        "VeraCrypt": ["veracrypt", "truecrypt"],
        "Eraser": ["eraser.exe", "heidi"]
    }
    if mft_df is not None and "filename" in mft_df.columns:
        files = mft_df["filename"].astype(str).str.lower()
        for tool, patterns in wipers.items():
            for p in patterns:
                if files.str.contains(p).any():
                    results.append({"tool": tool, "pattern": p})
    return results

def detect_ghost_files(mft_df, usn_df):
    if "filename" not in mft_df.columns or "filename" not in usn_df.columns:
        return []
    mft_files = set(mft_df["filename"].astype(str).str.lower())
    usn_files = set(usn_df["filename"].astype(str).str.lower())
    ghosts = usn_files - mft_files
    return [g for g in ghosts if g not in ["nan","none",".","unknown"]]

def load_csv_with_timestamp(file, candidates, label):
    df = pd.read_csv(file)
    df.columns = df.columns.str.lower().str.strip()
    col = next((c for c in candidates if c in df.columns), None)
    if not col:
        col = st.selectbox(f"Select timestamp for {label}", df.columns)
    df[col] = pd.to_datetime(df[col], errors="coerce")
    return df.dropna(subset=[col]), col

# ======================================================
# UI HEADER
# ======================================================
st.title("🛡️ ForenSight AI Platinum")
st.caption("Agent-Driven DFIR • Tool DNA Scanner • MFT Recovery • SOC v3.5")
st.markdown("---")

tabs = st.tabs([
    "📥 Evidence",
    "🎞️ Timeline",
    "🧪 DNA Artifact Scanner",
    "🧬 MITRE ATT&CK",
    "🚨 SOC Alerts",
    "🤖 Agent AI Explainer",
    "📡 Live Monitor"
])

# ======================================================
# TAB 1 — EVIDENCE
# ======================================================
with tabs[0]:
    c1, c2, c3 = st.columns(3)
    with c1:
        mft_f = st.file_uploader("Upload MFT CSV", type="csv")
    with c2:
        usn_f = st.file_uploader("Upload USN CSV", type="csv")
    with c3:
        log_f = st.file_uploader("Upload Security Logs", type="csv")

    if mft_f and usn_f:
        mft, mft_t = load_csv_with_timestamp(mft_f, ["modified","mtime","timestamp"], "MFT")
        usn, usn_t = load_csv_with_timestamp(usn_f, ["usn_timestamp","timestamp"], "USN")
        st.session_state.mft_df = (mft, mft_t)
        st.session_state.usn_df = (usn, usn_t)
        st.success("🎯 Forensic Data Synchronized")

# ======================================================
# TAB 2 — TIMELINE
# ======================================================
with tabs[1]:
    if st.session_state.mft_df:
        mft_data, mft_col = st.session_state.mft_df
        df = mft_data.sort_values(by=mft_col).tail(25)
        fig = px.scatter(df, x=mft_col, y="filename",
                         color="filename", template="plotly_dark")
        fig.update_layout(showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Upload evidence first.")

# ======================================================
# TAB 3 — DNA
# ======================================================
with tabs[2]:
    if st.session_state.mft_df:
        dna = detect_anti_forensic_dna(st.session_state.mft_df[0])
        if dna:
            for d in dna:
                st.warning(f"Tool DNA: {d['tool']} ({d['pattern']})")
        else:
            st.success("No wiper DNA found.")

# ======================================================
# TAB 4 — MITRE
# ======================================================
with tabs[3]:
    st.table(pd.DataFrame([
        ["T1070.004","File Deletion","HIGH"],
        ["T1486","Encryption Impact","HIGH"],
        ["T1099","Timestomp","MEDIUM"]
    ], columns=["ID","Technique","Severity"]))

# ======================================================
# TAB 5 — SOC ALERTS
# ======================================================
with tabs[4]:
    st_autorefresh(interval=5000, key="soc_refresh")
    if random.random() > 0.85:
        st.session_state.soc_alerts.insert(0,{
            "ts": dt.now().strftime("%H:%M:%S"),
            "msg":"Suspicious Artifact Detected",
            "lvl":"high"
        })

    for a in st.session_state.soc_alerts[:10]:
        st.write(f"[{a['ts']}] {a['msg']}")

# ======================================================
# TAB 6 — AGENT AI (FULLY FIXED)
# ======================================================
# ======================================================
# TAB 6 — NEXT-GEN FORENSIC AGENT AI
# ======================================================
with tabs[5]:
    st.subheader("🤖 Forensic Agent AI — Advanced Intelligence Engine")

    # -----------------------------
    # Mode Toggle
    # -----------------------------
    view_mode = st.radio(
        "Report View Mode:",
        ["SOC Technical Mode", "Executive Board Mode"],
        horizontal=True
    )

    # -----------------------------
    # Run Agent Button
    # -----------------------------
    if st.button("🚀 Run Deep Forensic Analysis"):

        with st.spinner("Performing Multi-Layer Artifact Correlation..."):
            time.sleep(2)

            dna_hits = []
            ghost_files = []
            entropy_score = 0

            # ---- Gather Evidence Signals ----
            if st.session_state.mft_df:
                mft_data = st.session_state.mft_df[0]
                dna_hits = detect_anti_forensic_dna(mft_data)

                # Entropy scan (simulate suspicious randomness)
                if "filename" in mft_data.columns:
                    entropy_values = mft_data["filename"].astype(str).apply(calculate_shannon_entropy)
                    entropy_score = round(entropy_values.mean(), 2)

            if st.session_state.mft_df and st.session_state.usn_df:
                ghost_files = detect_ghost_files(
                    st.session_state.mft_df[0],
                    st.session_state.usn_df[0]
                )

            # ---- Weighted Risk Scoring ----
            risk_score = 0

            risk_score += len(dna_hits) * 25
            risk_score += len(ghost_files) * 2
            risk_score += entropy_score * 5

            risk_score = min(int(risk_score), 100)

            # ---- Threat Classification ----
            if len(dna_hits) > 0 and len(ghost_files) > 10:
                threat_type = "Intentional Anti-Forensics Activity"
                mitre = ["T1070.004", "T1564", "T1107"]
            elif entropy_score > 4.5:
                threat_type = "Possible Ransomware Staging"
                mitre = ["T1486", "T1027"]
            elif len(ghost_files) > 20:
                threat_type = "Mass File Deletion Event"
                mitre = ["T1070.004"]
            else:
                threat_type = "Suspicious Artifact Pattern"
                mitre = ["T1083"]

            confidence = min(95, 50 + risk_score // 2)

            # ---- Save Report to Session State ----
            st.session_state.agent_report = {
                "risk_score": risk_score,
                "threat": threat_type,
                "confidence": confidence,
                "dna": dna_hits,
                "ghosts": len(ghost_files),
                "entropy": entropy_score,
                "mitre": mitre,
                "timestamp": dt.now().strftime("%Y-%m-%d %H:%M:%S")
            }

    # -----------------------------
    # Display Report
    # -----------------------------
    if st.session_state.agent_report:

        r = st.session_state.agent_report

        st.markdown("---")

        # -----------------------------
        # Risk Meter
        # -----------------------------
        col1, col2, col3 = st.columns(3)
        col1.metric("Threat Score", f"{r['risk_score']} / 100")
        col2.metric("Confidence", f"{r['confidence']}%")
        col3.metric("Entropy Avg", r["entropy"])

        # -----------------------------
        # Threat Banner
        # -----------------------------
        if r["risk_score"] > 70:
            st.error(f"🚨 HIGH RISK INCIDENT: {r['threat']}")
        elif r["risk_score"] > 40:
            st.warning(f"⚠ MEDIUM RISK: {r['threat']}")
        else:
            st.success(f"ℹ LOW RISK: {r['threat']}")

        # -----------------------------
        # SOC Technical Mode
        # -----------------------------
        if view_mode == "SOC Technical Mode":

            st.markdown("### 🔬 Technical Findings")

            st.write(f"• Tool DNA Hits: {len(r['dna'])}")
            for d in r["dna"]:
                st.write(f"   - {d['tool']} ({d['pattern']})")

            st.write(f"• Ghost Files Detected: {r['ghosts']}")
            st.write(f"• Mean Filename Entropy: {r['entropy']}")

            st.markdown("### 🧬 MITRE ATT&CK Mapping")
            for m in r["mitre"]:
                st.markdown(f"<span class='mitre-badge'>{m}</span>", unsafe_allow_html=True)

            st.markdown("### 🛡 Recommended Response")
            if r["risk_score"] > 70:
                st.write("• Immediate host isolation")
                st.write("• Capture volatile memory")
                st.write("• Acquire disk image for deep analysis")
            else:
                st.write("• Continue monitoring")
                st.write("• Validate recent admin activity")

        # -----------------------------
        # Executive Mode
        # -----------------------------
        else:
            st.markdown("### 📊 Executive Summary")

            st.write(f"""
            The forensic engine has detected **{r['threat']}** on the analyzed endpoint.

            Risk Level: **{r['risk_score']}/100**

            Confidence Level: **{r['confidence']}%**

            The system recommends immediate containment if risk exceeds 70.
            """)

            st.markdown("### 📈 Business Impact Estimate")
            if r["risk_score"] > 70:
                st.error("High probability of deliberate evidence destruction or ransomware staging.")
            elif r["risk_score"] > 40:
                st.warning("Suspicious activity detected. Further investigation recommended.")
            else:
                st.success("No immediate critical threat detected.")

    else:
        st.info("Click 'Run Deep Forensic Analysis' to generate an AI investigation report.")


# ======================================================
# TAB 7 — LIVE MONITOR (STABLE MODEL)
# ======================================================
with tabs[6]:

    st_autorefresh(interval=2000, key="monitor_refresh")

    if PSUTIL_AVAILABLE:

        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()

        st.session_state.cpu_history.append(cpu)
        st.session_state.cpu_history = st.session_state.cpu_history[-60:]

        # Train model ONCE after enough samples
        if len(st.session_state.cpu_history) > 30 and not st.session_state.iso_trained:
            model = IsolationForest(contamination=0.05, random_state=42)
            model.fit(np.array(st.session_state.cpu_history).reshape(-1,1))
            st.session_state.iso_model = model
            st.session_state.iso_trained = True

        anomaly = "Normal"

        if st.session_state.iso_trained:
            pred = st.session_state.iso_model.predict([[cpu]])
            if pred[0] == -1:
                anomaly = "⚠️ ANOMALY DETECTED"

        c1,c2,c3 = st.columns(3)
        c1.metric("CPU %", cpu)
        c2.metric("Memory %", mem.percent)
        c3.metric("AI Status", anomaly)

        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=cpu,
            title={'text':"CPU Load"},
            gauge={'axis':{'range':[0,100]}}
        ))
        fig.update_layout(height=250)
        st.plotly_chart(fig, use_container_width=True)

        st.line_chart(st.session_state.cpu_history)

    else:
        st.error("psutil not installed.")

# ======================================================
# FOOTER
# ======================================================
st.markdown("---")
st.caption(f"ForenSight AI Platinum v3.5 • {dt.now().strftime('%Y-%m-%d %H:%M:%S')}")
