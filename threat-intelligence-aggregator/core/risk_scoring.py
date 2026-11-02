def _number(value, default=0):
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return default


def calculate_risk(results, correlation=None):
    """Return a transparent 0–100 triage score, never a probability."""
    provider_scores = []
    notes = []
    for provider, data in (results or {}).items():
        if not isinstance(data, dict):
            continue
        if provider == "VirusTotal":
            stats = data.get("stats") or {}
            if isinstance(stats, dict):
                malicious = _number(stats.get("malicious"))
                suspicious = _number(stats.get("suspicious"))
                total = sum(_number(v) for v in stats.values())
                if total:
                    score = min(100, round(100 * (malicious + 0.35 * suspicious) / total))
                    provider_scores.append(score)
                    notes.append(f"VirusTotal: {malicious} malicious and {suspicious} suspicious detections out of {total}.")
        elif provider == "AbuseIPDB":
            confidence = min(100, _number(data.get("abuseConfidenceScore")))
            provider_scores.append(confidence)
            notes.append(f"AbuseIPDB confidence score: {confidence}/100.")
        elif provider == "URLhaus":
            listed = data.get("listed") is True
            provider_scores.append(90 if listed else 0)
            notes.append("URLhaus lists this URL." if listed else "URLhaus did not list this URL.")
        elif provider == "AlienVault OTX":
            pulses = data.get("pulse_info") or {}
            count = _number(pulses.get("count")) if isinstance(pulses, dict) else 0
            if count:
                provider_scores.append(min(85, 45 + count * 5))
                notes.append(f"AlienVault OTX reports {count} associated pulse(s).")
        elif provider == "Demo Intelligence":
            malicious = _number(data.get("malicious"))
            total = _number(data.get("total"))
            provider_scores.append(min(100, round(100 * malicious / total)) if total else 75)
            notes.append("Demonstration-only synthetic signal; not a live reputation result.")
    if not provider_scores:
        return 0, "Unknown", "No usable reputation signals were returned."
    # Strongest source anchors the score; independent corroboration adds a bounded uplift.
    score = max(provider_scores)
    positive_sources = sum(value >= 40 for value in provider_scores)
    if positive_sources > 1:
        score = min(100, score + min(15, (positive_sources - 1) * 7))
        notes.append(f"Corroborated by {positive_sources} independent provider signals.")
    if correlation and correlation.get("feed_matches"):
        score = min(100, max(score, 90))
        notes.append(f"Matched {len(correlation['feed_matches'])} stored threat feed record(s).")
    severity = "Critical" if score >= 90 else "High" if score >= 70 else "Medium" if score >= 40 else "Low"
    return score, severity, " ".join(notes)
