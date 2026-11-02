import requests

BASE = "https://www.virustotal.com/api/v3"

def check_virustotal(indicator, kind, api_key):
    endpoint = {"ip": "ip_addresses", "domain": "domains", "url": "urls", "file": "files"}[kind]
    lookup = indicator
    if kind == "url":
        import base64
        lookup = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
    response = requests.get(
        f"{BASE}/{endpoint}/{lookup}",
        headers={"x-apikey": api_key},
        timeout=20
    )
    response.raise_for_status()
    attrs = response.json().get("data", {}).get("attributes", {})
    return {
        "stats": attrs.get("last_analysis_stats", {}),
        "reputation": attrs.get("reputation"),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "provider": "VirusTotal"
    }
