import os
import time
import re
import socket
from datetime import datetime, timedelta
from fastapi import FastAPI, UploadFile, File, Header, HTTPException, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt
from dotenv import load_dotenv
from pyzbar.pyzbar import decode
from PIL import Image
import requests

# ENVIRONMENT, API KEYS
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
GOOGLE_SAFEBROWSING_API_KEY = os.getenv("GOOGLE_SAFEBROWSING_API_KEY")
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY")

# PASSWORD + JWT AUTH
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "your-strong-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

def hash_password(password):
    if len(password) > 72:
        raise ValueError("Password too long for bcrypt (max 72 characters)")
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def create_token(username):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    data = {"sub": username, "exp": expire}
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str = Header(None)):
    if token is None:
        raise HTTPException(status_code=401, detail="Auth token missing")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload["sub"]
    except:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

# FASTAPI APP
app = FastAPI()

# === HISTORY, SIGNUP, LOGIN === #
def save_history(entry):
    pass

def get_history():
    return []

@app.get("/history")
def history(user: str = Depends(verify_token)):
    return JSONResponse(get_history())

class SignUp(BaseModel):
    username: str
    email: str
    password: str

@app.post("/signup")
def signup(user: SignUp):
    return {"status": "error", "message": "Signup disabled for web/demo deploy"}

class Login(BaseModel):
    username: str
    password: str

@app.post("/login")
def login(data: Login):
    return {"error": "Login disabled for web/demo deploy"}

# ==== URL SCAN ENDPOINT ==== #
class URLInput(BaseModel):
    url: str

def validate_url(url):
    regex = re.compile(r"^(http|https)://([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}")
    if not re.match(regex, url):
        return False, "Invalid URL format"
    try:
        domain = url.split("//")[1].split("/")[0]
        socket.gethostbyname(domain)
    except:
        return False, "Domain does not exist or cannot be resolved"
    return True, "OK"

def scan_url_vt(url):
    try:
        submit_url = "https://www.virustotal.com/api/v3/urls"
        res = requests.post(
            submit_url,
            headers={"x-apikey": VT_API_KEY},
            data={"url": url}
        )
        data = res.json()
        if "data" not in data:
            return {"error": "VirusTotal refused the URL", "raw": data}
        analysis_id = data["data"]["id"]
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        for _ in range(12):  # up to 1 min
            result = requests.get(analysis_url, headers={"x-apikey": VT_API_KEY})
            final_json = result.json()
            if final_json["data"]["attributes"]["status"] == "completed":
                return final_json
            time.sleep(5)
        return {"error": "VirusTotal scan timed out", "last": final_json}
    except Exception as e:
        return {"error": f"VirusTotal error: {str(e)}"}

def extract_vt_summary(vt_json, url):
    if "error" in vt_json:
        return {"error": vt_json["error"]}
    try:
        attr = vt_json["data"]["attributes"]
        stats = attr.get("stats", {})
        results = attr.get("results", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        mal_eng = []
        susp_eng = []
        for engine, info in results.items():
            if info.get("category") == "malicious":
                mal_eng.append(engine)
            elif info.get("category") == "suspicious":
                susp_eng.append(engine)
        return {
            "url": url,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "malicious_engines": mal_eng,
            "suspicious_engines": susp_eng,
        }
    except Exception as e:
        return {"error": f"VT Summary Extraction Error: {str(e)}"}

def check_google_safe_browsing(url):
    key = GOOGLE_SAFEBROWSING_API_KEY
    if not key:
        return {"error": "Google Safe Browsing API key missing"}
    gsb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}"
    body = {
        "client": {"clientId": "cybersentinel", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        res = requests.post(gsb_url, json=body)
        data = res.json()
        if "matches" in data:
            return {"dangerous": True, "details": data["matches"]}
        return {"dangerous": False}
    except Exception as e:
        return {"error": f"GSB error: {str(e)}"}

def check_phishtank(url):
    phish_url = "https://checkurl.phishtank.com/checkurl/"
    data = {"url": url, "format": "json"}
    headers = {"User-Agent": "cybersentinel/1.0"}
    try:
        res = requests.post(phish_url, data=data, headers=headers)
        txt = res.text.strip()
        if txt and txt.startswith("{"):
            return res.json()
        else:
            return {"error": f"PhishTank error: Unparseable/no response (content={repr(txt)[:100]})"}
    except Exception as e:
        return {"error": f"PhishTank error: {str(e)}"}

def calculate_full_threat_score(vt_summary, gsb_result, phish_result):
    error_flags = [
        "error" in vt_summary,
        isinstance(gsb_result, dict) and gsb_result.get("error"),
        isinstance(phish_result, dict) and phish_result.get("error"),
    ]
    if all(error_flags):
        return 1, "unknown"
    score = 0
    if "error" not in vt_summary:
        score += vt_summary.get("malicious", 0) * 3
        score += vt_summary.get("suspicious", 0) * 1.5
    if isinstance(gsb_result, dict) and not gsb_result.get("error") and gsb_result.get("dangerous"):
        score += 4
    if isinstance(phish_result, dict) and not phish_result.get("error") and phish_result.get("dangerous"):
        score += 3
    score = max(1, min(10, round(score, 1)))
    if score >= 7:
        label = "harmful"
    elif score >= 3:
        label = "risky"
    else:
        label = "safe"
    return score, label

def custom_ai_explanation(vt_summary, gsb_result, phish_result):
    lines = []
    url = vt_summary.get("url", "this link")
    lines.append(f"## 🛡️ Security Report for: {url}\n")
    if "error" in vt_summary:
        lines.append(f"- [VirusTotal] <span style='color:#f36666;'>ERROR</span>: {vt_summary['error']}")
    else:
        mal = vt_summary.get("malicious", 0)
        susp = vt_summary.get("suspicious", 0)
        harmless = vt_summary.get("harmless", 0)
        undetected = vt_summary.get("undetected", 0)
        lines.append(f"- [VirusTotal] <b>Malicious:</b> {mal}, <b>Suspicious:</b> {susp}, <b>Harmless:</b> {harmless}, <b>Undetected:</b> {undetected}")
    if gsb_result.get("error"):
        lines.append(f"- [Safe Browsing] <span style='color:#f36666;'>ERROR</span>: {gsb_result['error']}")
    elif gsb_result.get("dangerous"):
        matches = gsb_result.get("details", [])
        threat_types = set(m.get("threatType", "?") for m in matches)
        display_types = ", ".join(threat_types)
        lines.append(f"- [Safe Browsing] 🚨 <b>Flagged as dangerous by Google! Types: {display_types}</b>")
    else:
        lines.append("- [Safe Browsing] ✅ No threats found by Google Safe Browsing.")
    if phish_result.get("error"):
        lines.append(f"- [PhishTank] <span style='color:#f36666;'>ERROR</span>: {phish_result['error']}")
    elif phish_result.get("dangerous"):
        lines.append("- [PhishTank] 🚨 <b>Listed as an active phishing site!</b>")
    else:
        lines.append("- [PhishTank] ✅ Not on the PhishTank list.")
    if any([
        vt_summary.get("malicious", 0) > 0 if "error" not in vt_summary else False,
        gsb_result.get("dangerous") if gsb_result and not gsb_result.get("error") else False,
        phish_result.get("dangerous") if phish_result and not phish_result.get("error") else False
    ]):
        lines.append("""
**Final verdict:**
- <span style='color:#fc5c65;font-weight:600;'>HARMFUL!</span>  
- <b>Do NOT open this link. It is dangerous.</b>
""")
    elif (
        vt_summary.get("suspicious", 0) > 0 if "error" not in vt_summary else False
    ):
        lines.append("""
**Final verdict:**  
- <span style='color:#ffe066;font-weight:600;'>RISKY.</span>  
- Caution advised. This link is suspicious.
""")
    elif all([
        "error" in vt_summary,
        gsb_result.get("error") if gsb_result else True,
        phish_result.get("error") if phish_result else True,
    ]):
        lines.append("""
**Final verdict:**  
- <span style='color:#ffe066;font-weight:600;'>UNKNOWN — all engines failed.</span>
- Unable to verify safety. Try again later.
""")
    else:
        lines.append("""
**Final verdict:**  
- <span style='color:#44e3a6;font-weight:600;'>This link appears safe.</span>  
- No dangerous content detected by available security engines.
""")
    return "\n".join(lines)

@app.post("/scan_url")
def scan_url_api(data: URLInput, user: str = Depends(verify_token)):
    valid, reason = validate_url(data.url)
    if not valid:
        return {
            "url": data.url,
            "vt_summary": {"error": reason},
            "google_safebrowsing": None,
            "phishtank": None,
            "ai_explanation": f"⚠️ Cannot scan URL: {reason}",
            "threat_score": 1,
            "threat_label": "unknown"
        }
    vt_raw = scan_url_vt(data.url)
    vt_summary = extract_vt_summary(vt_raw, data.url)
    gsb_result = check_google_safe_browsing(data.url)
    phish_result = check_phishtank(data.url)
    explanation = custom_ai_explanation(vt_summary, gsb_result, phish_result)
    score, label = calculate_full_threat_score(vt_summary, gsb_result, phish_result)
    entry = {
        "type": "url",
        "input": data.url,
        "label": label,
        "score": score
    }
    save_history(entry)
    return {
        "url": data.url,
        "vt_summary": vt_summary,
        "google_safebrowsing": gsb_result,
        "phishtank": phish_result,
        "ai_explanation": explanation,
        "threat_score": score,
        "threat_label": label,
        "raw_vt": vt_raw
    }

def decode_qr_image(image_path):
    try:
        img = Image.open(image_path)
        results = decode(img)
        for result in results:
            url = result.data.decode("utf-8")
            if url.startswith(("http://", "https://")):
                return url
        return None
    except Exception as e:
        return None

@app.post("/scan_qr")
async def scan_qr(file: UploadFile = File(...), user: str = Depends(verify_token)):
    file_location = f"temp_{file.filename}"
    with open(file_location, "wb") as f:
        f.write(await file.read())
    decoded_url = decode_qr_image(file_location)
    try: os.remove(file_location)
    except: pass
    if not decoded_url:
        return {"error": "No QR code or URL found in the image"}
    valid, reason = validate_url(decoded_url)
    if not valid:
        return {
            "decoded_url": decoded_url,
            "summary": {"error": reason},
            "ai_explanation": f"⚠️ Cannot scan URL: {reason}",
            "threat_score": 1,
            "threat_label": "unknown"
        }
    vt_raw = scan_url_vt(decoded_url)
    vt_summary = extract_vt_summary(vt_raw, decoded_url)
    gsb = check_google_safe_browsing(decoded_url)
    phish = check_phishtank(decoded_url)
    explanation = custom_ai_explanation(vt_summary, gsb, phish)
    score, label = calculate_full_threat_score(vt_summary, gsb, phish)
    entry = {
        "type": "qr",
        "input": decoded_url,
        "label": label,
        "score": score
    }
    save_history(entry)
    return {
        "decoded_url": decoded_url,
        "vt_summary": vt_summary,
        "google_safebrowsing": gsb,
        "phishtank": phish,
        "ai_explanation": explanation,
        "threat_score": score,
        "threat_label": label,
        "raw_vt": vt_raw
    }

def file_scan_ai_explanation(stats, file_name, raw):
    total_engines = sum(int(stats.get(k, 0)) for k in ("malicious", "suspicious", "undetected", "harmless", "timeout", "confirmed-timeout", "failure", "type-unsupported"))
    mal = stats.get("malicious", 0)
    susp = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    type_unsupported = stats.get("type-unsupported", 0)
    verdict = ""
    if mal > 0:
        verdict = f"⚠️ Multiple engines labelled this file as **MALICIOUS**."
    elif susp > 0:
        verdict = f"⚠️ Several engines labelled this file as **suspicious**."
    elif undetected + type_unsupported == total_engines:
        verdict = "No major AV engine flagged this file as malicious or suspicious. Most engines report it as 'undetected' (either new, uncommon, or type unsupported)."
    elif int(stats.get("harmless", 0)) > 0:
        verdict = "✅ Most engines report this file as harmless."
    else:
        verdict = "No definite result. The file was not recognized as malicious or suspicious by any major engine."
    supported = total_engines - type_unsupported
    if type_unsupported > 0:
        verdict += f" ⚠️ {type_unsupported} engines could not scan this file type and were ignored."
    verdict += f"\n\n**File scanned:** `{file_name}`\n- Malicious: `{mal}`\n- Suspicious: `{susp}`\n- Harmless: `{stats.get('harmless', 0)}`\n- Undetected: `{undetected}`"
    vt_url = raw["data"]["links"]["item"] if "data" in raw and "links" in raw["data"] else None
    if vt_url:
        verdict += f"\n\n[View full VirusTotal report]({vt_url})"
    return verdict

@app.post("/scan_file")
async def scan_file(file: UploadFile = File(...), user: str = Depends(verify_token)):
    file_bytes = await file.read()
    vt_url = "https://www.virustotal.com/api/v3/files"
    files = {"file": (file.filename, file_bytes)}
    try:
        response = requests.post(
            vt_url,
            headers={"x-apikey": VT_API_KEY},
            files=files
        )
        data = response.json()
        if "data" not in data:
            return {"error": "Could not upload file to VirusTotal", "raw": data}
        analysis_id = data["data"]["id"]
        poll_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        for _ in range(12):
            r = requests.get(poll_url, headers={"x-apikey": VT_API_KEY})
            result = r.json()
            if result["data"]["attributes"]["status"] == "completed":
                stats = result["data"]["attributes"]["stats"]
                explanation = file_scan_ai_explanation(stats, file.filename, result)
                label = "malicious" if stats.get("malicious", 0) > 0 else "risky" if stats.get("suspicious", 0) > 0 else "safe"
                entry = {
                    "type": "file",
                    "input": file.filename,
                    "label": label,
                    "score": stats.get("malicious", 0) * 3 + stats.get("suspicious", 0) * 1.5
                }
                save_history(entry)
                return {
                    "file_name": file.filename,
                    "stats": stats,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "ai_explanation": explanation,
                    "raw": result,
                }
            time.sleep(5)
        return {"error": "File scan timed out"}
    except Exception as e:
        return {"error": str(e)}

# ==== TEXT ANALYZER (EMAIL SCANNER) ENDPOINT ==== #
class TextInput(BaseModel):
    text: str

@app.post("/scan_text")
def scan_text(data: TextInput, user: str = Depends(verify_token)):
    suspicious_keywords = [
        "urgent", "immediately", "click here", "verify your account", "reset your password",
        "limited time", "risk", "account suspended", "login details", "bank account", "verify",
        "reward", "prize", "selected", "claim", "security alert", "payment", "update your info",
        "expire", "sensitive", "confirm", "free gift", "action required", "respond within"
    ]
    score = 1
    label = "safe"
    explanation = "No threats detected in your message. It appears safe."
    txt_lc = data.text.lower()
    if not data.text or len(data.text) < 20:
        return {
            "ai_explanation": "Please enter at least 20 characters of text to analyze.",
            "threat_score": 1,
            "threat_label": "unknown",
            "input_preview": data.text
        }
    keyword_hits = [kw for kw in suspicious_keywords if kw in txt_lc]
    if len(keyword_hits) >= 2:
        score = 5
        label = "suspicious"
        explanation = (
            "**Suspicious pattern detected!**\n"
            f"Keywords found: {', '.join(keyword_hits)}\n"
            "- This message contains vocabulary and urgency/tactics like scam, phishing, or social engineering."
        )
    elif any(kw in txt_lc for kw in suspicious_keywords):
        score = 3
        label = "risky"
        explanation = (
            "**Potentially risky content found!**\n"
            "At least one suspicious keyword or urgency tactic is present. Be cautious."
        )
    return {
        "ai_explanation": explanation,
        "threat_score": score,
        "threat_label": label,
        "input_preview": data.text[:1500]
    }
