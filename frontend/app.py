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
# When using Streamlit Cloud, set to your deployed backend service location, e.g.:
# BACKEND_API = "https://your-backend-service.onrender.com"
BACKEND_API = "http://127.0.0.1:8000"
BACKEND_LOGIN_URL = f"{BACKEND_API}/login"
BACKEND_SIGNUP_URL = f"{BACKEND_API}/signup"

PAGES = [
    "Home",
    "Scan URL",
    "Scan QR",
    "Scan File",
    "Text Analyzer",
    "Dashboard",
    "About"
]
PAGE_FILES = {
    "Home": "Home.py",
    "Scan URL": "Scan_URL.py",
    "Scan QR": "Scan_QR.py",
    "Scan File": "Scan_File.py",
    "Text Analyzer": "Text_Analyzer.py",
    "Dashboard": "Dashboard.py",
    "About": "About.py"
}

def reset_auth_state():
    for key in ["token", "username", "show_signup", "current_page"]:
        if key in st.session_state:
            del st.session_state[key]

if "token" not in st.session_state:
    st.session_state["token"] = None
if "username" not in st.session_state:
    st.session_state["username"] = None
if "show_signup" not in st.session_state:
    st.session_state["show_signup"] = False
if "current_page" not in st.session_state:
    st.session_state["current_page"] = "Home"

# ==== LOGIN/SIGNUP PAGE ====
if not st.session_state["token"]:
    colspacer1, colmain, colspacer2 = st.columns([2,3,2])
    with colmain:
        if bg_path.exists():
            st.image(str(bg_path), width=80)
        else:
            st.image("https://img.icons8.com/fluency/96/shield-with-stars.png", width=80)
        st.markdown("<h1 style='text-align:center;font-size:2.4em;font-weight:900;background: linear-gradient(90deg,#26c6da,#283e51);-webkit-background-clip: text;-webkit-text-fill-color: transparent;'>Cyber Sentinel AI</h1>", unsafe_allow_html=True)
        st.markdown("<h2 style='color:#ffe066;font-weight:800;text-align:center;font-size:1.11em;margin-bottom:1.4em;'>Securing Tomorrow, Today</h2>", unsafe_allow_html=True)
        if not st.session_state["show_signup"]:
            st.markdown("### Login")
            login_user = st.text_input("Username", key="login_user_centered")
            login_pass = st.text_input("Password", type="password", key="login_pass_centered")
            cols = st.columns([2,1])
            if cols[0].button("Login"):
                try:
                    res = requests.post(BACKEND_LOGIN_URL, json={"username": login_user, "password": login_pass})
                    data = res.json()
                    if "token" in data:
                        st.session_state["token"] = data["token"]
                        st.session_state["username"] = login_user
                        st.success("Login successful!")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error(data.get("error", "Invalid credentials."))
                except Exception as e:
                    st.error(f"Error: {e}")
            if cols[1].button("Sign Up"):
                st.session_state.show_signup = True
                st.rerun()
        else:
            st.markdown("### Sign Up")
            signup_user = st.text_input("New username", key="signup_user_ctr")
            signup_email = st.text_input("Email address", key="signup_email_ctr")
            signup_pass = st.text_input("New password", type="password", key="signup_pass_ctr")
            signup_conf = st.text_input("Confirm password", type="password", key="signup_conf_ctr")
            row_signup = st.columns([2,1])
            if row_signup[0].button("Create Account"):
                if not signup_user or not signup_email or not signup_pass or not signup_conf:
                    st.error("All fields required.")
                elif signup_pass != signup_conf:
                    st.error("Passwords do not match.")
                elif len(signup_pass) < 4:
                    st.error("Password must be at least 4 characters.")
                elif "@" not in signup_email or "." not in signup_email:
                    st.error("Enter a valid email address.")
                else:
                    try:
                        res = requests.post(BACKEND_SIGNUP_URL, json={
                            "username": signup_user, "email": signup_email, "password": signup_pass
                        })
                        data = res.json()
                        if data.get("status") == "success":
                            st.success("Signup successful! You can now log in.")
                            st.session_state.show_signup = False
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error(data.get("message", "Signup failed."))
                    except Exception as e:
                        st.error(f"Error: {e}")
            if row_signup[1].button("Back to Login"):
                st.session_state.show_signup = False
                st.rerun()
    st.stop()

# ==== AFTER LOGIN: NAVBAR ====
st.markdown("""
    <style>
        .stButton>button {
            font-size:1.17em; font-weight:700; border-radius:2em;
            padding: 0.6em 2.1em; margin:0.1em 0.18em 0.33em 0.18em;
            background: linear-gradient(90deg,#26c6da,#283e51);
            color: #fff; transition: all 0.14s; border: none;
            box-shadow: 0 3px 12px 0 rgba(40,62,81,0.10);
            min-width: 130px !important; white-space: nowrap;
        }
        .stButton>button:focus, .stButton>button:active {
            background: #232739 !important; color: #4affef !important;
            outline: none !important;
        }
        .active-nav {
            background: #232739 !important; color: #4affef !important;
            outline: none !important; font-weight:999 !important;
        }
        .logout-btn {
            background: linear-gradient(90deg, #fc5c65 0%, #232739 90%) !important;
            color: #fff !important;
        }
    </style>
""", unsafe_allow_html=True)

st.markdown("<div style='height:3.3em;'></div>", unsafe_allow_html=True)
spacer, nav, spacer2 = st.columns([1,10,1])
with nav:
    nav_cols = st.columns(len(PAGES) + 2)
    for i, label in enumerate(PAGES):
        btn = nav_cols[i].button(label, key=f"mainnav_{label}")
        if btn:
            st.session_state["current_page"] = label
        if st.session_state["current_page"] == label:
            nav_cols[i].markdown(
                "<div class='active-nav' style='margin-top:-2.7em;height:38px; border-radius:2em;line-height:38px;'></div>",
                unsafe_allow_html=True)
    if nav_cols[-2].button("Logout", key="mainnav_logout"):
        reset_auth_state()
        st.rerun()
    nav_cols[-1].markdown(f'<div style="margin-top:0.6em;color:#aaa;font-weight:600;">{st.session_state.get("username","")}</div>', unsafe_allow_html=True)

# Draw page content
import importlib.util, sys
page_path = Path(__file__).parent / "pages" / PAGE_FILES[st.session_state["current_page"]]
if page_path.exists():
    spec = importlib.util.spec_from_file_location(st.session_state["current_page"], str(page_path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[st.session_state["current_page"]] = module
    spec.loader.exec_module(module)
else:
    st.error(f"Page file not found: {page_path}")

st.markdown("""
<br><hr>
<div class='footer-note'>
    Made with ❤️ by AZE | Powered by FastAPI &amp; Streamlit multipage
</div>
""", unsafe_allow_html=True)
