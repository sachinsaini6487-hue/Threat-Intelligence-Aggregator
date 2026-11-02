import requests

def check_otx(indicator, kind, api_key):
    section = {"ip": "IPv4", "domain": "domain", "url": "url", "hash": "file"}[kind]
    response = requests.get(
        f"https://otx.alienvault.com/api/v1/indicators/{section}/{indicator}/general",
        headers={"X-OTX-API-KEY": api_key},
        timeout=20
    )
    response.raise_for_status()
    data = response.json()
    return {
        "pulse_info": data.get("pulse_info", {}),
        "reputation": data.get("reputation"),
        "country": data.get("country_name")
    }
