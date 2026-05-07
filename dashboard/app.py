"""
Honeypot Intelligence Dashboard — Streamlit App
Author: Abdul Ahad
Run: streamlit run dashboard/app.py
"""

import streamlit as st
import pandas as pd
import numpy as np
import os
import json
import joblib
from collections import Counter
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Honeypot Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .main { background-color: #0d1117; }
    .block-container { padding-top: 1.5rem; }
    .metric-card {
        background: linear-gradient(135deg, #1a1f2e, #252b3b);
        border: 1px solid #30363d;
        border-radius: 12px;
        padding: 1.2rem 1.5rem;
        text-align: center;
    }
    .metric-value { font-size: 2.2rem; font-weight: 700; color: #58a6ff; }
    .metric-label { font-size: 0.85rem; color: #8b949e; margin-top: 4px; }
    .alert-high   { color: #ff4d4f; font-weight: 600; }
    .alert-medium { color: #faad14; font-weight: 600; }
    .alert-low    { color: #52c41a; font-weight: 600; }
    h1, h2, h3 { color: #e6edf3 !important; }
    .stDataFrame { border-radius: 8px; }
</style>
""", unsafe_allow_html=True)

# ── Data loading ──────────────────────────────────────────────────────────────
@st.cache_data
def load_data():
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    labelled = os.path.join(base, "data", "labelled_sessions.csv")
    raw_log  = os.path.join(base, "logs", "cowrie.json")

    if not os.path.exists(labelled):
        st.error("❌ labelled_sessions.csv not found. Run the ML pipeline first:\n\n`python scripts/ml_pipeline.py`")
        st.stop()

    df = pd.read_csv(labelled)

    # Parse timestamps from raw log for timeline
    timestamps = []
    if os.path.exists(raw_log):
        with open(raw_log) as f:
            for line in f:
                try:
                    ev = json.loads(line)
                    if ev.get("eventid") == "cowrie.session.connect":
                        timestamps.append(ev.get("timestamp","")[:10])
                except:
                    pass

    return df, timestamps

df, timestamps = load_data()

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/2092/2092757.png", width=60)
    st.title("🛡️ Honeypot IDS")
    st.caption("Abdul Ahad — AI-Enabled Honeypot")
    st.markdown("---")

    attack_types = ["All"] + sorted(df["attack_type"].dropna().unique().tolist())
    selected_type = st.selectbox("Filter by Attack Type", attack_types)

    countries = ["All"] + sorted(df["country"].dropna().unique().tolist())
    selected_country = st.selectbox("Filter by Country", countries)

    min_attempts = st.slider("Min Login Attempts", 0, int(df["login_attempts"].max()), 0)
    st.markdown("---")
    st.markdown("**Data Summary**")
    st.metric("Total Sessions", len(df))
    st.metric("Unique IPs", df["src_ip"].nunique())
    st.metric("Successful Logins", int(df["login_success"].sum()))

# ── Filter ────────────────────────────────────────────────────────────────────
dff = df.copy()
if selected_type != "All":
    dff = dff[dff["attack_type"] == selected_type]
if selected_country != "All":
    dff = dff[dff["country"] == selected_country]
dff = dff[dff["login_attempts"] >= min_attempts]

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("# 🛡️ Honeypot Intelligence Dashboard")
st.markdown(f"*Showing **{len(dff)}** sessions · AI-classified attack behaviour · Abdul Ahad*")
st.markdown("---")

# ── KPI row ───────────────────────────────────────────────────────────────────
c1, c2, c3, c4, c5 = st.columns(5)

with c1:
    st.markdown(f"""<div class="metric-card">
        <div class="metric-value">{len(dff)}</div>
        <div class="metric-label">Total Sessions</div>
    </div>""", unsafe_allow_html=True)

with c2:
    st.markdown(f"""<div class="metric-card">
        <div class="metric-value">{dff['src_ip'].nunique()}</div>
        <div class="metric-label">Unique IPs</div>
    </div>""", unsafe_allow_html=True)

with c3:
    st.markdown(f"""<div class="metric-card">
        <div class="metric-value">{int(dff['login_success'].sum())}</div>
        <div class="metric-label">Successful Logins</div>
    </div>""", unsafe_allow_html=True)

with c4:
    st.markdown(f"""<div class="metric-card">
        <div class="metric-value">{dff['country'].nunique()}</div>
        <div class="metric-label">Countries</div>
    </div>""", unsafe_allow_html=True)

with c5:
    avg_cmds = round(dff["num_commands"].mean(), 1)
    st.markdown(f"""<div class="metric-card">
        <div class="metric-value">{avg_cmds}</div>
        <div class="metric-label">Avg Commands/Session</div>
    </div>""", unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ── Row 1: Attack distribution + Country map ──────────────────────────────────
col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("🎯 Attack Type Distribution")
    atk_counts = dff["attack_type"].value_counts().reset_index()
    atk_counts.columns = ["Attack Type", "Count"]
    color_map = {
        "Scanner": "#ef5350", "Recon": "#ff9800",
        "Persistence": "#ab47bc", "Cryptominer": "#26c6da",
        "Lateral Movement": "#66bb6a", "Data Exfiltration": "#ec407a",
        "Unknown": "#78909c"
    }
    fig = px.bar(atk_counts, x="Attack Type", y="Count",
                 color="Attack Type", color_discrete_map=color_map,
                 template="plotly_dark")
    fig.update_layout(showlegend=False, plot_bgcolor="#1a1f2e",
                      paper_bgcolor="#1a1f2e", margin=dict(t=20, b=10))
    st.plotly_chart(fig, use_container_width=True)

with col2:
    st.subheader("🌍 Top Attacking Countries")
    country_counts = dff["country"].value_counts().head(12).reset_index()
    country_counts.columns = ["Country", "Count"]
    fig2 = px.bar(country_counts, x="Count", y="Country", orientation="h",
                  color="Count", color_continuous_scale="Reds",
                  template="plotly_dark")
    fig2.update_layout(plot_bgcolor="#1a1f2e", paper_bgcolor="#1a1f2e",
                       margin=dict(t=20, b=10), yaxis=dict(autorange="reversed"))
    st.plotly_chart(fig2, use_container_width=True)

# ── Row 2: Timeline + Behaviour heatmap ──────────────────────────────────────
col3, col4 = st.columns([1.3, 1])

with col3:
    st.subheader("📅 Attack Timeline (Last 7 Days)")
    if timestamps:
        ts_counts = Counter(timestamps)
        ts_df = pd.DataFrame(sorted(ts_counts.items()), columns=["Date", "Sessions"])
        fig3 = px.area(ts_df, x="Date", y="Sessions",
                       template="plotly_dark", color_discrete_sequence=["#58a6ff"])
        fig3.update_layout(plot_bgcolor="#1a1f2e", paper_bgcolor="#1a1f2e",
                           margin=dict(t=20, b=10))
        st.plotly_chart(fig3, use_container_width=True)
    else:
        st.info("Timeline data unavailable (logs/cowrie.json not found)")

with col4:
    st.subheader("🔥 Behaviour Score Heatmap")
    score_cols = ["recon_score","persistence_score","mining_score","lateral_score","exfil_score"]
    heatmap_df = dff.groupby("attack_type")[score_cols].mean().round(2)
    heatmap_df.columns = ["Recon","Persist","Mining","Lateral","Exfil"]
    fig4 = px.imshow(heatmap_df, color_continuous_scale="Reds",
                     template="plotly_dark", aspect="auto")
    fig4.update_layout(plot_bgcolor="#1a1f2e", paper_bgcolor="#1a1f2e",
                       margin=dict(t=20, b=10))
    st.plotly_chart(fig4, use_container_width=True)

# ── Row 3: Top IPs + Login attempts distribution ──────────────────────────────
col5, col6 = st.columns([1, 1])

with col5:
    st.subheader("💻 Top 10 Attacking IPs")
    top_ips = dff["src_ip"].value_counts().head(10).reset_index()
    top_ips.columns = ["IP Address", "Sessions"]
    top_ips["Country"] = top_ips["IP Address"].map(
        dff.set_index("src_ip")["country"].to_dict()
    )
    fig5 = px.bar(top_ips, x="Sessions", y="IP Address", orientation="h",
                  color="Sessions", color_continuous_scale="Blues",
                  template="plotly_dark", hover_data=["Country"])
    fig5.update_layout(plot_bgcolor="#1a1f2e", paper_bgcolor="#1a1f2e",
                       margin=dict(t=20, b=10), yaxis=dict(autorange="reversed"))
    st.plotly_chart(fig5, use_container_width=True)

with col6:
    st.subheader("🔐 Login Attempts Distribution")
    fig6 = px.histogram(dff, x="login_attempts", nbins=20,
                        color_discrete_sequence=["#f39c12"],
                        template="plotly_dark")
    fig6.update_layout(plot_bgcolor="#1a1f2e", paper_bgcolor="#1a1f2e",
                       margin=dict(t=20, b=10))
    st.plotly_chart(fig6, use_container_width=True)

# ── Row 4: Scatter + Pie ──────────────────────────────────────────────────────
col7, col8 = st.columns([1.2, 1])

with col7:
    st.subheader("📊 Commands vs Session Duration (by Attack Type)")
    fig7 = px.scatter(dff, x="session_duration", y="num_commands",
                      color="attack_type", color_discrete_map=color_map,
                      hover_data=["src_ip","country"],
                      template="plotly_dark", opacity=0.7)
    fig7.update_layout(plot_bgcolor="#1a1f2e", paper_bgcolor="#1a1f2e",
                       margin=dict(t=20, b=10))
    st.plotly_chart(fig7, use_container_width=True)

with col8:
    st.subheader("🥧 Attack Type Share")
    fig8 = px.pie(atk_counts, names="Attack Type", values="Count",
                  color="Attack Type", color_discrete_map=color_map,
                  template="plotly_dark", hole=0.4)
    fig8.update_layout(plot_bgcolor="#1a1f2e", paper_bgcolor="#1a1f2e",
                       margin=dict(t=20, b=10))
    st.plotly_chart(fig8, use_container_width=True)

# ── Session table ─────────────────────────────────────────────────────────────
st.markdown("---")
st.subheader("📋 Session Log")

display_cols = ["session_id","src_ip","country","attack_type",
                "login_attempts","login_success","num_commands","session_duration"]
table_df = dff[display_cols].sort_values("login_attempts", ascending=False).head(200)

def highlight_row(row):
    color = ""
    if row["attack_type"] in ["Data Exfiltration","Lateral Movement"]:
        color = "background-color: #2d1f1f"
    elif row["attack_type"] in ["Persistence","Cryptominer"]:
        color = "background-color: #2d2a1a"
    return [color] * len(row)

st.dataframe(
    table_df.style.apply(highlight_row, axis=1),
    use_container_width=True,
    height=400,
)

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("---")
st.caption("🛡️ AI-Enabled Honeypot Environment · Abdul Ahad · Built with Cowrie + scikit-learn + Streamlit")
