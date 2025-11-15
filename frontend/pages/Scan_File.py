import streamlit as st
import requests

BACKEND_FILE_URL = "http://127.0.0.1:8000/scan_file"
SAFE_COLOR = "#44e3a6"
SUSPICIOUS_COLOR = "#ffe066"
MALICIOUS_COLOR = "#fc5c65"
ACCENT = "#4affef"

st.markdown("""
<div class="section-title" style="font-size:2.1em;text-align:center;font-weight:900;margin-top:10px;">
🧪 File Malware Scanner
</div>
""", unsafe_allow_html=True)

token = st.session_state.get("token")

if not token:
    st.warning("🔐 Please log in to use the File Scanner.")
    st.stop()

st.write("Upload a file below to check for malware and suspicious behavior using advanced AI engines:")

uploaded_file = st.file_uploader("Upload a file (any type)", type=None)

if st.button("Scan File for Malware"):
    if uploaded_file is None:
        st.error("Please upload a file before scanning.")
    else:
        with st.spinner("Scanning your file for threats..."):
            try:
                res = requests.post(
                    BACKEND_FILE_URL,
                    files={"file": uploaded_file.getvalue()},
                    headers={"token": token}
                )
                data = res.json()
                if data.get("error") and "timed out" in data.get("error",""):
                    st.warning("⏳ File scan queued on VirusTotal. Please try again in a minute using the same file.")
                file_name = data.get("file_name", "?")
                label = "unknown"
                score = 1
                if "ai_explanation" in data:
                    label = "safe" if "SAFE" in data["ai_explanation"].upper() else "harmful" if "HARMFUL" in data["ai_explanation"].upper() else "risky" if "RISKY" in data["ai_explanation"].upper() else "unknown"
                if "malicious" in data:
                    score = min(10, int(data["malicious"]) * 3 + int(data.get("suspicious",0)) * 1.5)
                st.success(f"Scan complete for: {file_name}")
                st.markdown('<div class="section-title">🧪 Combined Threat Status</div>', unsafe_allow_html=True)
                st.progress(score / 10)
                if label == "safe":
                    st.markdown(f"<div style='text-align:center;font-size:2em;color:{SAFE_COLOR}'>🟢 SAFE</div>", unsafe_allow_html=True)
                elif label == "risky":
                    st.markdown(f"<div style='text-align:center;font-size:2em;color:{SUSPICIOUS_COLOR}'>🟠 RISKY</div>", unsafe_allow_html=True)
                elif label == "harmful":
                    st.markdown(f"<div style='text-align:center;font-size:2em;color:{MALICIOUS_COLOR}'>🔴 HARMFUL</div>", unsafe_allow_html=True)
                else:
                    st.markdown("<div style='text-align:center;font-size:2em;color:#ffe066'>❓ UNKNOWN</div>", unsafe_allow_html=True)
                st.markdown('<div class="section-title">🤖 AI Explanation & Summary</div>', unsafe_allow_html=True)
                st.markdown(data.get("ai_explanation", ""), unsafe_allow_html=True)
                st.markdown('<div class="section-title">🔍 Raw Result JSON</div>', unsafe_allow_html=True)
                st.json(data)
            except Exception as e:
                st.error(f"Error: {e}")

st.markdown("""
<div style='margin-top:2.4em;text-align:center;color:#aeb8c2'>
Regular file scans protect your data from unknown malware.<br>
Cyber Sentinel AI – effortless protection for all users.
</div>
""", unsafe_allow_html=True)
