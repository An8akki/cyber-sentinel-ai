import streamlit as st
from pathlib import Path

# Correct path for bg.jpg in parent (frontend) directory
bg_path = Path(__file__).parent.parent / "bg.jpg"
if bg_path.exists():
    st.image(str(bg_path), width=180)
else:
    st.warning("Background image bg.jpg not found.")

st.markdown("""
<div style='display:flex;flex-direction:column;align-items:center;justify-content:center;margin-top:1.5em;margin-bottom:2em;'>
    <h1 style='font-size:3.5em; font-weight:900; background: linear-gradient(90deg,#26c6da 0%, #283e51 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom:0.2em; margin-top:0em;'>Cyber Sentinel AI</h1>
    <h2 style='color:#ffe066;font-weight:800;padding-top:0.9em;font-size:1.32em;text-shadow:0px 0px 9px #222a,0px 0px 19px #3331;'>Securing Tomorrow, Today</h2>
</div>
""", unsafe_allow_html=True)

st.markdown("""
<br>
<div style='text-align:center; font-size:1.19em; color:#aeb8c2; max-width:700px; margin: 0 auto 2em auto;'>
Cyber Sentinel AI is your trusted partner in digital threat intelligence, offering real-time protection and analysis for URLs, files, and QR codes.<br>
Stay one step ahead. Simple, secure, and smart — for every user, every organization.
</div>
""", unsafe_allow_html=True)
