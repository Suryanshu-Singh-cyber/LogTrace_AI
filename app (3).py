st.sidebar.header("📂 Upload Forensic Artifacts")

mft_file = st.sidebar.file_uploader("Upload MFT CSV", type=["csv"])
usn_file = st.sidebar.file_uploader("Upload USN Journal CSV", type=["csv"])
log_file = st.sidebar.file_uploader("Upload Windows Log CSV", type=["csv"])

use_sample = st.sidebar.checkbox("Use sample dataset (demo mode)", value=True)

if use_sample:
    mft = pd.read_csv("data/ntfs/mft.csv", parse_dates=["modified"])
    usn = pd.read_csv("data/ntfs/usn.csv", parse_dates=["usn_timestamp"])
    logs = pd.read_csv("data/logs/security.csv", parse_dates=["timestamp"])
else:
    if not (mft_file and usn_file and log_file):
        st.info("Please upload all forensic artifacts")
        st.stop()

    mft = pd.read_csv(mft_file, parse_dates=["modified"])
    usn = pd.read_csv(usn_file, parse_dates=["usn_timestamp"])
    logs = pd.read_csv(log_file, parse_dates=["timestamp"])
