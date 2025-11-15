import streamlit as st
import matplotlib.pyplot as plt
import pandas as pd
import requests

BACKEND_HISTORY_URL = "http://127.0.0.1:8000/history"
SAFE_COLOR = "#44e3a6"
SUSPICIOUS_COLOR = "#ffe066"
MALICIOUS_COLOR = "#fc5c65"
ACCENT = "#4affef"

st.markdown("""
<div class="section-title" style="font-size:2.1em;text-align:center;font-weight:900;margin-top:10px;">
📊 Threat Analytics Dashboard
</div>
""", unsafe_allow_html=True)

token = st.session_state.get("token")

if not token:
    st.warning("🔐 Please log in to view the dashboard.")
    st.stop()

with st.spinner("Loading threat analytics..."):
    try:
        hist = requests.get(BACKEND_HISTORY_URL, headers={"token": token}).json() or []
    except Exception:
        hist = []
        st.error("Could not load dashboard. Check your backend/login.")

total = len(hist)
safe = sum(1 for x in hist if x["label"] == "safe")
suspicious = sum(1 for x in hist if x["label"] in ("risky", "suspicious"))
malicious = sum(1 for x in hist if x["label"] in ("harmful", "malicious"))

st.write("### Summary")
stat_cols = st.columns(4)
stat_cols[0].metric("Total Scans", total)
stat_cols[1].metric("Safe", safe)
stat_cols[2].metric("Suspicious", suspicious)
stat_cols[3].metric("Malicious", malicious)

labels = ['Safe', 'Suspicious', 'Malicious']
sizes = [safe, suspicious, malicious]
colors = [SAFE_COLOR, SUSPICIOUS_COLOR, MALICIOUS_COLOR]
display_labels = [lbl if val > 0 else "" for lbl, val in zip(labels, sizes)]

if total == 0:
    st.info("No scans yet! Start scanning to visualize data.")
else:
    df = pd.DataFrame(hist)
    st.write("### Scan Outcome Distribution")
    fig, ax = plt.subplots(figsize=(4, 4))
    ax.pie(sizes, labels=display_labels, colors=colors, autopct=lambda pct: f'{pct:.1f}%' if pct > 0 else '',
           startangle=140, wedgeprops={'edgecolor': 'white'}, textprops={'fontsize': 12})
    ax.axis('equal')
    plt.tight_layout()
    st.pyplot(fig, use_container_width=False)

    if "timestamp" in df and not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        daily_trend = df.groupby(df["timestamp"].dt.date).size()
        if not daily_trend.empty:
            st.write("### Daily Scan Trend")
            fig2, ax2 = plt.subplots(figsize=(5.4, 2.2))
            daily_trend.plot(kind="line", marker='o', ax=ax2, color=ACCENT, linewidth=2)
            ax2.set_ylabel("Scan Count")
            ax2.set_xlabel("Date")
            ax2.set_title("Scan Trend per Day", fontsize=12)
            plt.tight_layout()
            st.pyplot(fig2, use_container_width=False)

    status_bar = pd.Series(sizes, index=labels)
    if status_bar.sum() > 0:
        st.write("### Scan Status Bar Chart")
        fig3, ax3 = plt.subplots(figsize=(4.8, 2.4))
        status_bar.plot(kind="bar", color=colors, ax=ax3)
        ax3.set_ylabel("Scan Count")
        ax3.set_title("Scan Outcome Distribution", fontsize=12)
        plt.tight_layout()
        st.pyplot(fig3, use_container_width=False)

st.markdown(
    "<small style='color:#aeb8c2'>Charts are compact and optimized for modern dashboards.<br>Cyber Sentinel AI by Team AZE.</small>",
    unsafe_allow_html=True
)
