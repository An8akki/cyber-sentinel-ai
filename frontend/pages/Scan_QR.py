import streamlit as st
import requests

BACKEND_URL_QR = "http://127.0.0.1:8000/scan_qr"
SAFE_COLOR = "#44e3a6"
SUSPICIOUS_COLOR = "#ffe066"
MALICIOUS_COLOR = "#fc5c65"
ACCENT = "#4affef"

st.markdown("""
<div class="section-title" style="font-size:2.1em;text-align:center;font-weight:900;margin-top:10px;">
📸 QR Code Phishing Detector
</div>
""", unsafe_allow_html=True)

token = st.session_state.get("token")

if not token:
    st.warning("🔐 Please log in to use the QR Scanner.")
    st.stop()

st.write("Upload a QR code image to check if it hides malware or phishing links.")

qr_file = st.file_uploader("Upload QR Code Image", type=["png", "jpg", "jpeg"])

if st.button("Scan QR Code"):
    if qr_file is None:
        st.error("Please upload a QR code image before scanning.")
    else:
        with st.spinner("Scanning QR Code for threats..."):
            try:
                res = requests.post(
                    BACKEND_URL_QR,
                    files={"file": qr_file.getvalue()},
                    headers={"token": token}
                )
                data = res.json()
                if "error" in data:
                    st.error(data["error"])
                else:
                    st.success(f"QR Code decoded! URL found: {data.get('decoded_url','[No URL]')}")
                    label = data.get("threat_label","unknown")
                    score = data.get("threat_score",1)
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
                    st.markdown(data.get("ai_explanation",""), unsafe_allow_html=True)
                    st.markdown('<div class="section-title">🔍 Detailed Engine Output</div>', unsafe_allow_html=True)
                    st.json(data)
            except Exception as e:
                st.error(f"Error: {e}")

st.markdown("""
<div style='margin-top:2.4em;text-align:center;color:#aeb8c2'>
Scanning QR codes helps prevent phishing scams and malicious redirects.<br>
Cyber Sentinel AI keeps your devices and data secure.
</div>
""", unsafe_allow_html=True)
