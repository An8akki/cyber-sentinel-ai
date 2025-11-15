import streamlit as st
import requests

SAFE_COLOR = "#44e3a6"
SUSPICIOUS_COLOR = "#ffe066"
MALICIOUS_COLOR = "#fc5c65"
ACCENT = "#4affef"

BACKEND_TEXT_URL = "http://127.0.0.1:8000/scan_text"

st.markdown("""
<div class="section-title" style="font-size:2.1em;text-align:center;font-weight:900;margin-top:10px;">
📧 Suspicious Mail/Text Analyzer
</div>
""", unsafe_allow_html=True)

token = st.session_state.get("token")

if not token:
    st.warning("🔐 Please log in to use the Email/Text Analyzer.")
    st.stop()

st.write("Paste the content of an email or suspicious message below, or upload a .txt file. Our AI engine will scan for phishing, scams, or risky wording.")

text_mode = st.radio("Input source:", ["Paste text/email", "Upload .txt file"], horizontal=True)

user_text = ""
if text_mode == "Paste text/email":
    user_text = st.text_area("Paste suspicious mail/content here", height=200, max_chars=6000)
elif text_mode == "Upload .txt file":
    uploaded_file = st.file_uploader("Upload a .txt file", type="txt")
    if uploaded_file is not None:
        uploaded_text = uploaded_file.read().decode("utf-8", errors="ignore")
        st.markdown("#### File Preview")
        st.code(uploaded_text[:4000])
        user_text = uploaded_text

if st.button("Analyze Text / Email"):
    if not user_text or len(user_text.strip()) < 20:
        st.error("Please enter or upload at least 20 characters of email or message content.")
    else:
        with st.spinner("Analyzing message for risks..."):
            try:
                res = requests.post(
                    BACKEND_TEXT_URL,
                    json={"text": user_text},
                    headers={"token": token}
                )
                data = res.json()
                label = data.get("threat_label", "unknown")
                score = data.get("threat_score", 1)
                explanation = data.get("ai_explanation", "No details.")
                st.markdown('<div class="section-title">🧪 Threat Analysis Result</div>', unsafe_allow_html=True)
                st.progress(score / 10)
                if label == "safe":
                    st.markdown(f"<div style='text-align:center;font-size:2em;color:{SAFE_COLOR};'>🟢 SAFE</div>", unsafe_allow_html=True)
                elif label == "risky":
                    st.markdown(f"<div style='text-align:center;font-size:2em;color:{SUSPICIOUS_COLOR};'>🟠 RISKY</div>", unsafe_allow_html=True)
                elif label == "harmful":
                    st.markdown(f"<div style='text-align:center;font-size:2em;color:{MALICIOUS_COLOR};'>🔴 HARMFUL</div>", unsafe_allow_html=True)
                else:
                    st.markdown("<div style='text-align:center;font-size:2em;color:#ffe066'>❓ UNKNOWN</div>", unsafe_allow_html=True)
                st.markdown(f"""
                <div style='background:#222a;padding:1.1em 1.6em;border-radius:13px;margin:1.5em auto;max-width:600px;color:#f0f6fc;'>
                    <b>AI Analysis Explanation:</b>
                    <p style='margin:0.9em 0em;'>{explanation}</p>
                </div>
                """, unsafe_allow_html=True)
                st.markdown('<div class="section-title">🔍 Input Preview</div>', unsafe_allow_html=True)
                st.code(data.get("input_preview", user_text)[:1500])
            except Exception as e:
                st.error(f"Error: {e}")

st.markdown("""
<div style='margin-top:2.4em;text-align:center;color:#aeb8c2;'>
Never trust links, files, or offers in unexpected emails.<br>
Cyber Sentinel AI lets you check suspicious messages with privacy.
</div>
""", unsafe_allow_html=True)
