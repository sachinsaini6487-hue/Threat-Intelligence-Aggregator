import requests

def check_urlhaus(url):
    response = requests.post(
        "https://urlhaus-api.abuse.ch/v1/url/",
        data={"url": url},
        timeout=20
    )
    response.raise_for_status()
    data = response.json()
    return {
        "listed": data.get("query_status") == "ok",
        "query_status": data.get("query_status"),
        "threat": data.get("threat"),
        "url_status": data.get("url_status"),
        "date_added": data.get("date_added")
    }

def fetch_urlhaus_recent(limit=25):
    response = requests.get("https://urlhaus-api.abuse.ch/v1/urls/recent/", timeout=30)
    response.raise_for_status()
    payload = response.json()
    return (payload.get("urls") or [])[:limit]
