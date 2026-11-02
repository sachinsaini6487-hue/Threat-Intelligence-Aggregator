import ipaddress
import re
from urllib.parse import urlparse

def normalize_indicator(value, kind):
    value = (value or "").strip()
    if not value:
        raise ValueError("Please enter an indicator.")

    if kind == "IP Address":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            raise ValueError("Invalid IP address.")

    if kind == "URL":
        candidate = value if "://" in value else "http://" + value
        parsed = urlparse(candidate)
        if not parsed.hostname:
            raise ValueError("Invalid URL.")
        return candidate

    if kind == "Domain":
        domain = value.lower().rstrip(".")
        if "://" in domain:
            domain = urlparse(domain).hostname or ""
        if not re.fullmatch(r"(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))+", domain):
            raise ValueError("Invalid domain name.")
        return domain

    if kind == "File Hash":
        if not re.fullmatch(r"(?i)([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})", value):
            raise ValueError("Enter a valid MD5, SHA-1 or SHA-256 hash.")
        return value.lower()

    raise ValueError("Unsupported indicator type.")
