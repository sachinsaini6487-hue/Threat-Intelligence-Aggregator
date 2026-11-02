from core.ioc_correlation import correlate_ioc
from core.risk_scoring import calculate_risk


def test_correlates_provider_signals_and_exact_local_records():
    result = correlate_ioc(
        "https://bad.example/path",
        {"VirusTotal": {"stats": {"malicious": 2, "suspicious": 0}},
         "URLhaus": {"listed": False}},
        feed_records=[{"indicator": "https://bad.example/path/", "source": "URLhaus", "threat": "malware"}],
        history_records=[{"indicator": "https://bad.example/path", "risk_score": 88, "severity": "High"}],
    )
    assert result["positive_providers"] == ["VirusTotal"]
    assert result["negative_providers"] == ["URLhaus"]
    assert len(result["feed_matches"]) == 1
    assert len(result["prior_investigations"]) == 1


def test_correlation_raises_score_for_feed_match():
    result = {"VirusTotal": {"stats": {"malicious": 1, "undetected": 9}}}
    correlation = correlate_ioc("bad.example", result, [{"indicator": "bad.example", "source": "URLhaus"}])
    score, severity, explanation = calculate_risk(result, correlation)
    assert score >= 90
    assert severity == "Critical"
    assert "stored threat feed" in explanation


def test_malformed_and_empty_provider_results_are_safe():
    assert calculate_risk({"VirusTotal": {"stats": {"malicious": "bad"}}}) == (
        0, "Unknown", "No usable reputation signals were returned."
    )
    score, severity, _ = calculate_risk({"AbuseIPDB": {"abuseConfidenceScore": 150}})
    assert (score, severity) == (100, "Critical")
