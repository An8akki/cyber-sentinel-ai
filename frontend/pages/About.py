import streamlit as st
from pathlib import Path
import base64

bg_path = Path(__file__).parent.parent / "bg.jpg"
if bg_path.exists():
    img_bytes = bg_path.read_bytes()
    img_b64 = base64.b64encode(img_bytes).decode('utf-8')
    img_src = f"data:image/jpeg;base64,{img_b64}"
else:
    # Fallback to external icon if missing
    img_src = "https://img.icons8.com/fluency/96/shield-with-stars.png"

st.markdown(f"""
<div style='text-align:center; margin-top:2.2em;'>
    <img src='{img_src}' width='66' style='margin-bottom:1.5em;'/>
    <h1 style='font-size:2.6em; font-weight:900; background: linear-gradient(90deg,#26c6da 0%, #283e51 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom:0.7em; margin-top:0.3em;'>Cyber Sentinel AI</h1>
    <h2 style='color:#ffe066;font-weight:700;padding-top:0.29em;font-size:1.18em;'>Transforming Threat Detection for Everyone</h2>
</div>

<div style='margin:2em auto 2.1em auto;max-width:680px;font-size:1.11em;color:#e4eaf3;background:#232739ba;padding:1.3em 2em 1.5em 2em;border-radius:15px;box-shadow:0 6px 28px 0 rgba(0,0,0,0.09);'>
<b>Problem:</b><br>
Modern internet users and organizations face constant risk from malicious URLs, infected files, and hidden phishing attempts — especially in emails, QR codes, and downloads. Most existing solutions are slow, limited to single formats, or require complex setup, leaving people vulnerable and business data exposed.<br><br>

<b>Our Solution:</b><br>
Cyber Sentinel AI brings real-time, multi-format threat scanning to everyone.<br>
- Scan links, files, and QR codes with AI-powered verdicts, automated threat scoring, and detailed explanations.<br>
- The dashboard visualizes your scan history, trends, and status in a clean interface.<br>
- All data is processed securely, with instant results and actionable feedback — no prior expertise required.<br>
- Extensible, robust, and user-centric — Cyber Sentinel AI adapts for personal, team, or enterprise use.<br>
</div>

<div style='margin-top:3em;text-align:center;'>
    <h3 style='font-size:1.42em; font-weight:750; color:#44e3a6; margin-top:0.5em;'>Team AZE</h3>
</div>

<div style='margin:2.1em auto 2.7em auto; background:#232739ba; padding:1.1em 2em; border-radius:15px; max-width:480px;'>
<b>Contact Lead: Anagesh R J</b><br>
📧 <a href='mailto:anu8akkirj@gmail.com' style='color:#44e3a6;'>anu8akkirj@gmail.com</a><br>
📱 <span style='color:#44e3a6;'>+91 72004 30365</span><br>
<a href='https://www.linkedin.com/in/anagesh-r-j-881823329/' target='_blank' style='font-size:1em; color:#44e3a6; font-weight:700;'>LinkedIn Profile</a>
</div>
""", unsafe_allow_html=True)
