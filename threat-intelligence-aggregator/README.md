# Threat Intelligence Aggregator

A defensive cybersecurity mini project built with Python, Streamlit and SQLite. It aggregates indicator reputation from VirusTotal, AbuseIPDB, URLhaus and AlienVault OTX.

## Features
- Dashboard with investigation statistics and charts
- IP, URL, domain and file-hash investigations
- Multi-provider API integration
- URLhaus recent malicious URL feed
- Transparent heuristic risk scoring
- IOC correlation across provider results, stored URLhaus feed matches and prior investigations
- SQLite investigation and feed history
- CSV export
- Demonstration mode for testing without API credentials

## Requirements
- Python 3.10 or newer
- Internet connection for live providers
- API keys for providers that require authentication

## Setup (Windows)
1. Extract the ZIP.
2. Open the project folder in VS Code.
3. Open Terminal.
4. Create a virtual environment:

   ```powershell
   py -m venv .venv
   .venv\Scripts\activate
   ```

5. Install packages:

   ```powershell
   pip install -r requirements.txt
   ```

6. Copy `.env.example` to `.env` and add your API keys.
7. Start the app:

   ```powershell
   streamlit run app.py
   ```

8. Streamlit will print a local URL, normally `http://localhost:8501`.

## API setup
- VirusTotal: https://www.virustotal.com/gui/join-us
- AbuseIPDB: https://www.abuseipdb.com/register
- AlienVault OTX: https://otx.alienvault.com/

URLhaus public API is used for URL lookups and recent URL feeds. Provider access limits and terms apply.

## IOC correlation and risk score
The correlation view groups positive and negative signals by provider and reports exact matches against locally stored URLhaus feed entries and prior investigations of the same indicator. Matching is case-insensitive and ignores a trailing slash. Correlation uses locally stored data and the current provider responses; it does not infer relationships between different indicators.

The score is a transparent triage heuristic, not a calibrated probability:
- 0–39: Low
- 40–69: Medium
- 70–89: High
- 90–100: Critical

VirusTotal detection ratio, AbuseIPDB confidence, URLhaus listing, and OTX pulse presence contribute provider scores. The strongest provider score anchors the result; multiple positive provider signals add a bounded corroboration uplift. A matching stored URLhaus record raises the score to at least 90. Scores are capped at 100. Validate findings before blocking or taking action.

## Run and verify
From this project folder, run the tests and then start Streamlit:

```powershell
python -m pytest
streamlit run app.py
```

The tests cover provider/local-record correlation, feed-match scoring, and malformed provider values. Keep `.env` private; do not commit it or share its contents.

## Notes
- Never commit `.env` or expose API keys in screenshots or source control.
- API responses may be incomplete, rate-limited or unavailable.
- Use this project only for authorized defensive analysis.
- Demonstration mode results are synthetic and must not be reported as real threat findings.
