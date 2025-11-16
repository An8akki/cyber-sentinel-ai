import streamlit as st
import requests
import time
from pathlib import Path
import base64

st.set_page_config(page_title="Cyber Sentinel AI", page_icon="🛡️", layout="wide")
THEME_PATH = Path(__file__).parent / "theme.css"
if THEME_PATH.exists():
    with open(THEME_PATH) as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# --- Background image CSS with fallback dark color ---
bg_path = Path(__file__).parent / "bg.jpg"
if bg_path.exists():
    with open(bg_path, "rb") as bg_file:
        b64_bg = base64.b64encode(bg_file.read()).decode()
    st.markdown(
        f"""
        <style>
        body {{
            background: #181b23 !important;
            background-image: url('data:image/jpeg;base64,{b64_bg}');
            background-repeat: no-repeat;
            background-position: center center;
            background-size: cover;
        }}
        [data-testid="stSidebar"], header, footer {{ display:none !important; }}
        </style>
        """, unsafe_allow_html=True
    )
else:
    st.markdown("""
        <style>
        body { background: #181b23 !important; }
        [data-testid="stSidebar"], header, footer { display:none !important; }
        </style>
    """, unsafe_allow_html=True)

# ====== SET YOUR BACKEND URL HERE FOR DEPLOY ======
# When using Streamlit Cloud or Render, set this to the deployed backend service, e.g.:
# BACKEND_API = "https://your-backend-service.onrender.com"
BACKEND_API = "https://cyber-sentinel-backend-q5j6.onrender.com"

st.title("🛡️ Cyber Sentinel AI")
st.write("Securing Tomorrow, Today")

token = st.text_input("Demo Auth Token (enter anything)", value="demo")

tabs = st.tabs(["Scan URL", "Scan File", "Scan Text"])

with tabs[0]:
    url = st.text_input("Enter URL to scan")
    if st.button("Scan URL"):
        if url:
            resp = requests.post(f"{BACKEND_API}/scan_url", json={"url": url}, headers={"token": token})
            result = resp.json()
            st.json(result)
        else:
            st.warning("Enter a URL.")

with tabs[1]:
    file = st.file_uploader("Upload file to scan")
    if st.button("Scan File"):
        if file:
            files = {"file": (file.name, file)}
            resp = requests.post(f"{BACKEND_API}/scan_file", files=files, headers={"token": token})
            result = resp.json()
            st.json(result)
        else:
            st.warning("Choose a file first.")

with tabs[2]:
    txt = st.text_area("Enter text/email to analyze", height=140)
    if st.button("Scan Text"):
        if txt:
            resp = requests.post(f"{BACKEND_API}/scan_text", json={"text": txt}, headers={"token": token})
            result = resp.json()
            st.json(result)
        else:
            st.warning("Paste some text to analyze.")

st.markdown("""
<br><hr>
<div style="color:#aaa;font-weight:600;font-size:0.95em;">
    Made with ❤️ by AZE | Powered by FastAPI &amp; Streamlit
</div>
""", unsafe_allow_html=True)
