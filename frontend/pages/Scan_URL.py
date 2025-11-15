import streamlit as st
import requests

BACKEND_URL = "http://127.0.0.1:8000/scan_url"
SAFE_COLOR = "#44e3a6"
SUSPICIOUS_COLOR = "#ffe066"
MALICIOUS_COLOR = "#fc5c65"
ACCENT = "#4affef"

st.markdown("""
<div class="section-title" style="font-size:2.1em;text-align:center;font-weight:900;margin-top:10px;">
🔗 AI-powered URL Scanner
</div>
""", unsafe_allow_html=True)

token = st.session_state.get("token")

if not token:
    st.warning("🔐 Please log in to use the URL Scanner.")
    st.stop()

st.write("Enter a URL below to check for malware, phishing, and suspicious content:")

url = st.text_input("URL to scan", placeholder="https://example.com/suspicious-login")

if st.button("Scan URL"):
    if not url or not url.startswith(("http://", "https://")):
        st.error("Please enter a valid URL starting with http:// or https://")
    else:
        with st.spinner("Scanning..."):
            try:
                res = requests.post(BACKEND_URL, json={"url": url}, headers={"token": token})
                data = res.json()
                
                score = data.get("threat_score", 1)
                label = data.get("threat_label","unknown")
                explanation = data.get("ai_explanation","")
                
                st.markdown('<div class="section-title">🧪 Combined Threat Status</div>', unsafe_allow_html=True)
                st.progress(score / 10)
                st.markdown(f"<div style='text-align:center;font-size:2em;color:#ffe066'>SCORE: <b>{score}/10</b></div>", unsafe_allow_html=True)
                if label == "safe":
                    st.markdown(f"<div style='text-align:center;font-size:2em;color:{SAFE_COLOR}'>🟢 SAFE</div>", unsafe_allow_html=True)
                elif label == "risky":
                    st.markdown(f"<div style='text-align:center;font-size:2em;color:{SUSPICIOUS_COLOR}'>🟠 RISKY</div>", unsafe_allow_html=True)
                elif label == "harmful":
                    st.markdown(f"<div style='text-align:center;font-size:2em;color:{MALICIOUS_COLOR}'>🔴 HARMFUL</div>", unsafe_allow_html=True)
                else:
                    st.markdown("<div style='text-align:center;font-size:2em;color:#ffe066'>❓ UNKNOWN</div>", unsafe_allow_html=True)
                
                st.markdown('<div class="section-title">🤖 AI Explanation & Summary</div>', unsafe_allow_html=True)
                st.markdown(explanation, unsafe_allow_html=True)
                
                st.markdown('<div class="section-title">🔍 Detailed Engine Output</div>', unsafe_allow_html=True)
                st.json(data)
            except Exception as e:
                st.error(f"Error: {e}")

st.markdown("""
<div style='margin-top:2.4em;text-align:center;color:#aeb8c2'>
Your scan data is private and visible only to you.<br>
Cyber Sentinel AI helps keep your browsing secure.
</div>
""", unsafe_allow_html=True)
