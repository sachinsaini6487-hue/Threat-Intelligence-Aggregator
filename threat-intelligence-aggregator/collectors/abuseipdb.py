import requests

def check_abuseipdb(ip, api_key):
    response = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
        timeout=20
    )
    response.raise_for_status()
    data = response.json().get("data", {})
    return {
        "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
        "totalReports": data.get("totalReports", 0),
        "countryCode": data.get("countryCode"),
        "isp": data.get("isp"),
        "usageType": data.get("usageType")
    }
