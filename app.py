# TRINETRA AI v3.7 (FULLY FIXED STABLE BUILD)

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
    page_title="Trinetra AI | DFIR Agent",
    page_icon="🛡️",
    layout="wide"
)

# ======================================================
# SESSION STATE INITIALIZATION
# ======================================================
defaults = {
    "mft_df": None,
    "usn_df": None,
    "security_df": None,
    "agent_report": None,
    "cpu_history": [],
    "soc_alerts": [{"ts": dt.now().strftime("%H:%M:%S"),
                    "msg": "Forensic Agent v3.7 Active",
                    "lvl": "low"}],
    "iso_model": None,
    "iso_trained": False
}

for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ======================================================
# FORENSIC ENGINES
# ======================================================
def calculate_shannon_entropy(text):
    """Calculate Shannon Entropy of a string"""
    if not text or not isinstance(text, str):
        return 0
    probs = [n_x / len(text) for x, n_x in Counter(text).items()]
    return -sum(p * math.log2(p) for p in probs)


def detect_anti_forensic_dna(mft_df):
    """Detect known anti-forensic tools by filename patterns"""
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
    """Detect files present in USN but missing in MFT"""
    if "filename" not in mft_df.columns or "filename" not in usn_df.columns:
        return []
    mft_files = set(mft_df["filename"].astype(str).str.lower())
    usn_files = set(usn_df["filename"].astype(str).str.lower())
    ghosts = usn_files - mft_files
    return [g for g in ghosts if g not in ["nan", "none", ".", "unknown", ""]]


def load_csv_with_timestamp(file, candidates, label):
    """Load CSV and auto-detect timestamp column"""
    df = pd.read_csv(file)
    df.columns = df.columns.str.lower().str.strip()
    col = next((c for c in candidates if c in df.columns), None)
    if not col:
        col = st.selectbox(f"Select timestamp for {label}", df.columns)
    df[col] = pd.to_datetime(df[col], errors="coerce")
    return df.dropna(subset=[col]), col


def get_df(key):
    """Safely get DataFrame from session state (handles tuple storage)"""
    data = st.session_state.get(key)
    if data is None:
        return None
    if isinstance(data, tuple):
        return data[0] if len(data) > 0 else None
    if isinstance(data, list):
        return data[0] if len(data) > 0 else None
    return data


# ======================================================
# UI HEADER
# ======================================================
st.markdown("""
<div style="background-color:#111111;
            padding:15px;
            border-radius:10px;
            border-left:5px solid #00FFC6;
            margin-bottom:15px;">

<b>Trinetra AI</b> is an intelligent DFIR (Digital Forensics & Incident Response) platform 
that analyzes MFT, USN, and Security logs to detect anti-forensic activity, 
behavioral anomalies, ransomware indicators, and suspicious execution patterns 
using AI-powered risk scoring and real-time system monitoring.

</div>
""", unsafe_allow_html=True)

st.title("🔱 Trinetra AI")
st.caption("Agent-Driven DFIR • Tool DNA Scanner • MFT Recovery • SOC v3.7")

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
        mft_f = st.file_uploader("Upload MFT CSV", type="csv", key="mft_upload")
    with c2:
        usn_f = st.file_uploader("Upload USN CSV", type="csv", key="usn_upload")
    with c3:
        log_f = st.file_uploader("Upload Security Logs", type="csv", key="log_upload")

    if mft_f and usn_f:
        try:
            mft, mft_t = load_csv_with_timestamp(
                mft_f, ["modified", "mtime", "timestamp", "created"], "MFT"
            )
            usn, usn_t = load_csv_with_timestamp(
                usn_f, ["usn_timestamp", "timestamp", "modified"], "USN"
            )
            st.session_state.mft_df = (mft, mft_t)
            st.session_state.usn_df = (usn, usn_t)
            st.success(f"🎯 MFT + USN Data Synchronized ({len(mft)} + {len(usn)} records)")
        except Exception as e:
            st.error(f"Error loading MFT/USN: {e}")

    if log_f:
        try:
            sec = pd.read_csv(log_f)
            sec.columns = sec.columns.str.lower().str.strip()
            st.session_state.security_df = sec
            st.success(f"🎯 Security Logs Loaded ({len(sec)} records)")
        except Exception as e:
            st.error(f"Error loading Security Logs: {e}")

# ======================================================
# TAB 2 — TIMELINE
# ======================================================
with tabs[1]:
    mft_data = get_df("mft_df")
    if mft_data is not None and "filename" in mft_data.columns:
        mft_col = st.session_state.mft_df[1] if isinstance(st.session_state.mft_df, tuple) else "timestamp"
        if mft_col in mft_data.columns:
            df = mft_data.sort_values(by=mft_col).tail(25)
            fig = px.scatter(
                df, x=mft_col, y="filename",
                color="filename", template="plotly_dark"
            )
            fig.update_layout(showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Timestamp column not found.")
    else:
        st.info("Upload evidence first.")

# ======================================================
# TAB 3 — DNA
# ======================================================
with tabs[2]:
    mft_data = get_df("mft_df")
    if mft_data is not None:
        dna = detect_anti_forensic_dna(mft_data)
        if dna:
            for d in dna:
                st.warning(f"Tool DNA: {d['tool']} ({d['pattern']})")
        else:
            st.success("No wiper DNA found.")
    else:
        st.info("Upload MFT first.")

# ======================================================
# TAB 4 — MITRE
# ======================================================
with tabs[3]:
    st.table(pd.DataFrame([
        ["T1070.004", "File Deletion", "HIGH"],
        ["T1486", "Encryption Impact", "HIGH"],
        ["T1099", "Timestomp", "MEDIUM"]
    ], columns=["ID", "Technique", "Severity"]))

# ======================================================
# TAB 5 — SOC ALERTS
# ======================================================
with tabs[4]:
    st_autorefresh(interval=5000, key="soc_refresh")
    if random.random() > 0.85:
        st.session_state.soc_alerts.insert(0, {
            "ts": dt.now().strftime("%H:%M:%S"),
            "msg": "Trinetra AI v3.7 Active",
            "lvl": "high"
        })

    for a in st.session_state.soc_alerts[:10]:
        st.write(f"[{a['ts']}] {a['msg']}")

# ======================================================
# TAB 6 — AGENT AI (FULLY FIXED + NORMALIZED RISK)
# ======================================================
with tabs[5]:
    st.subheader("🤖 Forensic Agent AI — Behavioral Intelligence Engine")

    if "agent_report" not in st.session_state:
        st.session_state.agent_report = None

    view_mode = st.radio(
        "Report View Mode:",
        ["SOC Technical Mode", "Executive Board Mode"],
        horizontal=True,
        key="view_mode_radio"
    )

    if st.button("🚀 Run Deep Forensic Analysis", key="run_agent_btn"):

        with st.spinner("Correlating Artifacts + Behavioral Signals..."):
            time.sleep(0.5)

            mft_data = get_df("mft_df")
            usn_data = get_df("usn_df")
            sec_data = get_df("security_df")

            if mft_data is None and usn_data is None and sec_data is None:
                st.error("⚠ No data loaded. Please upload MFT, USN, or Security Logs first.")
            else:
                dna_hits = []
                ghost_files = []
                entropy_score = 0
                anomaly_users = []
                suspicious_exec = 0

                # -------------------------
                # MFT Analysis
                # -------------------------
                if mft_data is not None and not mft_data.empty:
                    suspicious_keywords = ["wipe", "delete", "clean", "cipher", "encrypt"]
                    if "filename" in mft_data.columns:
                        for file in mft_data["filename"].astype(str).head(5000):
                            for word in suspicious_keywords:
                                if word in file.lower():
                                    dna_hits.append({
                                        "tool": word.upper(),
                                        "pattern": "Filename Pattern Match"
                                    })

                        sample = mft_data["filename"].astype(str).head(1000)
                        entropy_values = sample.apply(calculate_shannon_entropy)
                        entropy_score = round(entropy_values.mean(), 2)

                # -------------------------
                # Ghost File Detection
                # -------------------------
                if mft_data is not None and usn_data is not None:
                    try:
                        ghost_files = detect_ghost_files(mft_data, usn_data)
                    except Exception:
                        ghost_files = []

                # -------------------------
                # Security Log Behavior
                # -------------------------
                if sec_data is not None and not sec_data.empty:
                    if "user" in sec_data.columns:
                        user_counts = sec_data["user"].value_counts()
                        if len(user_counts) > 0:
                            anomaly_users = user_counts[
                                user_counts > user_counts.mean() * 2
                            ].index.tolist()

                    if "event_id" in sec_data.columns:
                        suspicious_exec = sec_data[
                            sec_data["event_id"].isin([4688, 1102])
                        ].shape[0]

                # -------------------------
                # NORMALIZED WEIGHTED RISK ENGINE
                # -------------------------
                
                # 1. DNA Score (0-100): each hit = 10 points, max 100
                dna_score = min(len(dna_hits) * 10, 100)
                
                # 2. Ghost Score (0-100): ratio of ghosts to total USN entries
                ghost_ratio = 0
                if usn_data is not None and len(usn_data) > 0:
                    ghost_ratio = len(ghost_files) / len(usn_data)
                ghost_score = min(ghost_ratio * 100, 100)
                
                # 3. Entropy Score (0-100): normalized (8.0 = max randomness)
                entropy_score_norm = min((entropy_score / 8.0) * 100, 100)
                
                # 4. User Score (0-100): each anomalous user = 20 points
                user_score = min(len(anomaly_users) * 20, 100)
                
                # 5. Exec Score (0-100): ratio of suspicious events to total
                exec_ratio = 0
                if sec_data is not None and len(sec_data) > 0:
                    exec_ratio = suspicious_exec / len(sec_data)
                exec_score = min(exec_ratio * 100, 100)
                
                # Weighted combination (weights sum to 1.0)
                risk_score = (
                    dna_score * 0.35 +           # 35% - tool indicators
                    ghost_score * 0.15 +         # 15% - ghost file ratio
                    entropy_score_norm * 0.20 +  # 20% - encryption
                    user_score * 0.10 +          # 10% - user behavior
                    exec_score * 0.20            # 20% - process execution
                )
                
                risk_score = min(int(risk_score), 100)

                # -------------------------
                # Threat Classification
                # -------------------------
                if entropy_score > 5 and ghost_ratio > 0.3:
                    threat_type = "Ransomware Pre-Encryption Activity"
                    mitre = ["T1486", "T1070.004", "T1027"]
                elif exec_ratio > 0.3:
                    threat_type = "Suspicious Process Execution Spike"
                    mitre = ["T1059", "T1106"]
                elif len(anomaly_users) > 0:
                    threat_type = "Abnormal User Behavior Detected"
                    mitre = ["T1078"]
                elif len(dna_hits) > 0:
                    threat_type = "Anti-Forensic Tool Indicators"
                    mitre = ["T1070"]
                else:
                    threat_type = "Low-Level Suspicious Artifact Pattern"
                    mitre = ["T1083"]

                confidence = min(95, 55 + (risk_score // 2))

                st.session_state.agent_report = {
                    "risk_score": risk_score,
                    "threat": threat_type,
                    "confidence": confidence,
                    "dna": dna_hits,
                    "ghosts": len(ghost_files) if isinstance(ghost_files, list) else 0,
                    "ghost_ratio": round(ghost_ratio * 100, 1),
                    "entropy": entropy_score,
                    "anomaly_users": anomaly_users,
                    "suspicious_exec": suspicious_exec,
                    "exec_ratio": round(exec_ratio * 100, 1),
                    "mitre": mitre,
                    "timestamp": dt.now().strftime("%Y-%m-%d %H:%M:%S")
                }

                st.success("✅ Analysis complete!")

    # -----------------------------
    # Display Report
    # -----------------------------
    report = st.session_state.get("agent_report")

    if report:
        st.markdown("---")

        col1, col2, col3 = st.columns(3)
        col1.metric("Threat Score", f"{report['risk_score']} / 100")
        col2.metric("Confidence", f"{report['confidence']}%")
        col3.metric("Entropy Avg", report["entropy"])

        if report["risk_score"] > 75:
            st.error(f"🚨 CRITICAL INCIDENT: {report['threat']}")
        elif report["risk_score"] > 45:
            st.warning(f"⚠ MODERATE RISK: {report['threat']}")
        else:
            st.success(f"✅ LOW RISK: {report['threat']}")

        # SOC Technical Mode
        if view_mode == "SOC Technical Mode":
            st.markdown("### 🔬 Technical Breakdown")
            st.write(f"• Tool Pattern Hits: {len(report['dna'])}")
            st.write(f"• Ghost Files: {report['ghosts']} ({report.get('ghost_ratio', 0)}% of USN)")
            st.write(f"• High-Frequency Users: {len(report['anomaly_users'])}")
            st.write(f"• Suspicious Process Events: {report['suspicious_exec']} ({report.get('exec_ratio', 0)}% of logs)")
            st.write(f"• Mean Filename Entropy: {report['entropy']}")

            st.markdown("### 🧬 MITRE ATT&CK Mapping")
            for m in report["mitre"]:
                st.markdown(
                    f"<span class='mitre-badge'>{m}</span>",
                    unsafe_allow_html=True
                )

            st.markdown("### 🛡 Recommended Actions")
            if report["risk_score"] > 75:
                st.write("• Immediately isolate affected endpoint")
                st.write("• Trigger memory acquisition")
                st.write("• Block suspicious users in IAM")
                st.write("• Escalate to Incident Response Team")
            elif report["risk_score"] > 45:
                st.write("• Increase monitoring level")
                st.write("• Audit suspicious users")
            else:
                st.write("• Continue baseline monitoring")

        # Executive Mode
        else:
            st.markdown("### 📊 Executive Summary")
            st.write(f"""
            The forensic AI engine has detected **{report['threat']}**.

            Risk Level: **{report['risk_score']}/100**

            Confidence Level: **{report['confidence']}%**
            """)

            if report["risk_score"] > 75:
                st.error("High probability of malicious activity impacting system integrity.")
            elif report["risk_score"] > 45:
                st.warning("Potential risk detected. Investigation recommended.")
            else:
                st.success("System operating within acceptable behavioral thresholds.")

    else:
        st.info("Click 'Run Deep Forensic Analysis' to generate an AI-powered investigation report.")

# ======================================================
# TAB 7 — LIVE MONITOR
# ======================================================
with tabs[6]:
    st_autorefresh(interval=2000, key="monitor_refresh")

    if PSUTIL_AVAILABLE:
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()

        st.session_state.cpu_history.append(cpu)
        st.session_state.cpu_history = st.session_state.cpu_history[-60:]

        if len(st.session_state.cpu_history) > 30 and not st.session_state.iso_trained:
            model = IsolationForest(contamination=0.05, random_state=42)
            model.fit(np.array(st.session_state.cpu_history).reshape(-1, 1))
            st.session_state.iso_model = model
            st.session_state.iso_trained = True

        anomaly = "Normal"
        if st.session_state.iso_trained:
            pred = st.session_state.iso_model.predict([[cpu]])
            if pred[0] == -1:
                anomaly = "⚠️ ANOMALY DETECTED"

        c1, c2, c3 = st.columns(3)
        c1.metric("CPU %", cpu)
        c2.metric("Memory %", mem.percent)
        c3.metric("AI Status", anomaly)

        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=cpu,
            title={'text': "CPU Load"},
            gauge={'axis': {'range': [0, 100]}}
        ))
        fig.update_layout(height=250)
        st.plotly_chart(fig, use_container_width=True)

        st.line_chart(st.session_state.cpu_history)
    else:
        st.error("psutil not installed. Run: pip install psutil")

# ======================================================
# FOOTER
# ======================================================
st.markdown("---")
st.caption(f"Trinetra AI v3.7 • {dt.now().strftime('%Y-%m-%d %H:%M:%S')}")
