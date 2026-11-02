"""Correlate an investigated IOC with provider and locally stored evidence."""


def _key(value):
    return str(value or "").strip().rstrip("/").casefold()


def correlate_ioc(indicator, results, feed_records=(), history_records=()):
    """Summarize provider corroboration and exact matches in local records."""
    positive_providers = []
    negative_providers = []
    for provider, data in (results or {}).items():
        if not isinstance(data, dict):
            continue
        positive = False
        if provider == "VirusTotal":
            stats = data.get("stats") or {}
            positive = isinstance(stats, dict) and any(
                _positive_number(stats.get(key)) for key in ("malicious", "suspicious")
            )
        elif provider == "AbuseIPDB":
            positive = _positive_number(data.get("abuseConfidenceScore"))
        elif provider == "URLhaus":
            positive = data.get("listed") is True
        elif provider == "AlienVault OTX":
            pulse_info = data.get("pulse_info") or {}
            positive = isinstance(pulse_info, dict) and _positive_number(pulse_info.get("count"))
        elif provider == "Demo Intelligence":
            positive = _positive_number(data.get("malicious"))
        (positive_providers if positive else negative_providers).append(provider)

    target = _key(indicator)
    matches = [
        {"indicator": row.get("indicator"), "source": row.get("source"), "threat": row.get("threat")}
        for row in feed_records or ()
        if _key(row.get("indicator")) == target
    ]
    prior = [
        {"created_at": row.get("created_at"), "risk_score": row.get("risk_score"), "severity": row.get("severity")}
        for row in history_records or ()
        if _key(row.get("indicator")) == target
    ]
    return {
        "positive_providers": positive_providers,
        "negative_providers": negative_providers,
        "provider_agreement": len(positive_providers),
        "feed_matches": matches,
        "prior_investigations": prior,
    }


def _positive_number(value):
    try:
        return float(value or 0) > 0
    except (TypeError, ValueError):
        return False
