import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timezone
from collectors.virustotal import check_virustotal
from collectors.abuseipdb import check_abuseipdb
from collectors.urlhaus import check_urlhaus, fetch_urlhaus_recent
from collectors.otx import check_otx
from core.risk_scoring import calculate_risk
from core.ioc_correlation import correlate_ioc
from core.normalizer import normalize_indicator
from database.db import init_db, save_investigation, get_history, save_feed, get_feeds
from core.config import load_config

st.set_page_config(page_title="Threat Intelligence Aggregator", page_icon="🛡️", layout="wide")
init_db()
cfg = load_config()

st.markdown("""
<style>
.main {background-color:#0e1117}
[data-testid="stMetric"] {background:#171d29;padding:16px;border:1px solid #283448;border-radius:12px}
.block-container {padding-top:1.6rem}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Threat Intelligence Aggregator")
st.caption("A centralized platform for collecting, correlating and analyzing cyber threat intelligence.")

with st.sidebar:
    st.header("Configuration")
    st.success("Sample mode is always available")
    st.write("API status")
    for label, key in [("VirusTotal","VIRUSTOTAL_API_KEY"),("AbuseIPDB","ABUSEIPDB_API_KEY"),("AlienVault OTX","OTX_API_KEY")]:
        st.write(f"{'🟢' if cfg.get(key) else '⚪'} {label}")
    st.divider()
    st.caption("Only investigate indicators you are authorized to analyze.")

dashboard, investigate, feeds, history, about = st.tabs(
    ["📊 Dashboard", "🔎 Investigate", "📡 Threat Feeds", "🗂️ History", "ℹ️ About"]
)

with dashboard:
    records = get_history()
    df = pd.DataFrame(records)
    total = len(df)
    high = int(df["risk_score"].ge(70).sum()) if total else 0
    medium = int(df["risk_score"].between(40,69).sum()) if total else 0
    low = int(df["risk_score"].lt(40).sum()) if total else 0
    c1,c2,c3,c4 = st.columns(4)
    c1.metric("Investigations", total)
    c2.metric("High / Critical", high)
    c3.metric("Medium", medium)
    c4.metric("Low", low)
    if total:
        left,right = st.columns(2)
        with left:
            st.subheader("Risk distribution")
            counts = df["severity"].value_counts().rename_axis("Severity").reset_index(name="Count")
            st.plotly_chart(px.pie(counts, names="Severity", values="Count", hole=.55), use_container_width=True)
        with right:
            st.subheader("Indicator types")
            types = df["indicator_type"].value_counts().rename_axis("Type").reset_index(name="Count")
            st.plotly_chart(px.bar(types, x="Type", y="Count"), use_container_width=True)
        st.subheader("Recent investigations")
        st.dataframe(df[["created_at","indicator","indicator_type","risk_score","severity","sources"]].head(10), use_container_width=True)
    else:
        st.info("No investigations yet. Open Investigate and analyze an IP, URL, domain or file hash.")

with investigate:
    st.subheader("Investigate an indicator")
    col1,col2 = st.columns([1,2])
    with col1:
        kind = st.selectbox("Indicator type", ["IP Address","URL","Domain","File Hash"])
        indicator = st.text_input("Indicator", placeholder="e.g. 8.8.8.8 or https://example.com")
        sample = st.checkbox("Use demonstration data", value=not any(cfg.values()))
        run = st.button("Analyze indicator", type="primary", use_container_width=True)
    with col2:
        st.info("The aggregator queries configured intelligence providers, normalizes their responses and calculates a transparent risk score.")
        st.caption("No API keys? Enable demonstration data to test the complete workflow.")

    if run:
        try:
            normalized = normalize_indicator(indicator, kind)
            results = {}
            if sample:
                results = {
                    "Demo Intelligence": {
                        "malicious": 3, "suspicious": 1, "total": 5,
                        "details": "Demonstration response. Not a real reputation verdict."
                    }
                }
            else:
                if kind == "IP Address":
                    if cfg.get("VIRUSTOTAL_API_KEY"):
                        results["VirusTotal"] = check_virustotal(normalized, "ip", cfg["VIRUSTOTAL_API_KEY"])
                    if cfg.get("ABUSEIPDB_API_KEY"):
                        results["AbuseIPDB"] = check_abuseipdb(normalized, cfg["ABUSEIPDB_API_KEY"])
                elif kind == "URL":
                    if cfg.get("VIRUSTOTAL_API_KEY"):
                        results["VirusTotal"] = check_virustotal(normalized, "url", cfg["VIRUSTOTAL_API_KEY"])
                    results["URLhaus"] = check_urlhaus(normalized)
                elif kind == "Domain":
                    if cfg.get("VIRUSTOTAL_API_KEY"):
                        results["VirusTotal"] = check_virustotal(normalized, "domain", cfg["VIRUSTOTAL_API_KEY"])
                    if cfg.get("OTX_API_KEY"):
                        results["AlienVault OTX"] = check_otx(normalized, "domain", cfg["OTX_API_KEY"])
                elif kind == "File Hash":
                    if cfg.get("VIRUSTOTAL_API_KEY"):
                        results["VirusTotal"] = check_virustotal(normalized, "file", cfg["VIRUSTOTAL_API_KEY"])
                if not results:
                    st.warning("No provider is configured for this indicator. Add API keys in the .env file or use demonstration data.")
                    st.stop()

            correlation = correlate_ioc(normalized, results, get_feeds(), get_history())
            score, severity, explanation = calculate_risk(results, correlation)
            sources = ", ".join(results.keys())
            save_investigation(normalized, kind, score, severity, sources, results)
            st.divider()
            a,b,c = st.columns(3)
            a.metric("Risk score", f"{score}/100")
            b.metric("Severity", severity)
            c.metric("Sources queried", len(results))
            st.progress(score/100)
            st.write("**Risk rationale:**", explanation)
            st.subheader("IOC correlation")
            st.write(f"Positive provider signals: {correlation['provider_agreement']} — " +
                     (", ".join(correlation["positive_providers"]) or "none"))
            st.write(f"Stored URLhaus feed matches: {len(correlation['feed_matches'])}")
            st.write(f"Prior investigations of this IOC: {len(correlation['prior_investigations'])}")
            if correlation["feed_matches"]:
                st.dataframe(pd.DataFrame(correlation["feed_matches"]), use_container_width=True)
            if correlation["prior_investigations"]:
                st.dataframe(pd.DataFrame(correlation["prior_investigations"]), use_container_width=True)
            st.subheader("Provider results")
            for source, data in results.items():
                with st.expander(source, expanded=True):
                    st.json(data)
        except Exception as e:
            st.error(str(e))

with feeds:
    st.subheader("Threat feed collection")
    st.write("Fetch recent malicious URLs from URLhaus. This feed is public and does not require an API key.")
    limit = st.slider("Number of records to fetch", 10, 100, 25, step=5)
    if st.button("Fetch URLhaus feed", type="primary"):
        try:
            items = fetch_urlhaus_recent(limit)
            for item in items:
                save_feed(item.get("url",""), item.get("threat","unknown"), item.get("date_added",""), "URLhaus")
            st.success(f"Collected {len(items)} records.")
        except Exception as e:
            st.error(f"Feed collection failed: {e}")
    feed_rows = get_feeds()
    if feed_rows:
        feed_df = pd.DataFrame(feed_rows)
        st.dataframe(feed_df, use_container_width=True)
        st.download_button("Download feed CSV", feed_df.to_csv(index=False), "threat_feed.csv", "text/csv")
    else:
        st.info("No feed records stored yet.")

with history:
    st.subheader("Investigation history")
    rows = get_history()
    if rows:
        hist_df = pd.DataFrame(rows)
        st.dataframe(hist_df, use_container_width=True)
        st.download_button("Export investigations CSV", hist_df.to_csv(index=False), "investigation_history.csv", "text/csv")
    else:
        st.info("Investigation history will appear here.")

with about:
    st.subheader("Project overview")
    st.markdown("""
**Threat Intelligence Aggregator** demonstrates a defensive security workflow:

1. Collect intelligence from multiple external providers.
2. Normalize indicators into a consistent format.
3. Correlate provider findings and calculate a risk score.
4. Store investigations in SQLite.
5. Present findings and export reports.

**Important:** Provider results can disagree or be incomplete. A score is a prioritization aid, not proof that an indicator is malicious. Verify important findings before taking action.
""")
    st.code("Python · Streamlit · SQLite · REST APIs · Pandas · Plotly")
