import requests
import json
import yaml
from datetime import datetime
from pathlib import Path

# Import storage helpers
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from database.storage import get_cached_ioc, save_ioc_cache

# Load config
CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"

def load_config() -> dict:
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)


# ─────────────────────────────────────────────
#  CORE API CALL
# ─────────────────────────────────────────────

def query_abuseipdb(ip: str, api_key: str) -> dict | None:
    """
    Hit the AbuseIPDB v2 API for one IP.
    Returns parsed response dict or None on failure.
    """
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key":    api_key,
        "Accept": "application/json",
    }
    params = {
        "ipAddress":    ip,
        "maxAgeInDays": 90,   # look back 90 days for reports
        "verbose":      True,
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)

        if response.status_code == 200:
            return response.json().get("data", {})

        elif response.status_code == 429:
            print(f"[ioc] Rate limit hit — daily quota exceeded")
            return None

        elif response.status_code == 422:
            print(f"[ioc] Invalid IP address: {ip}")
            return None

        else:
            print(f"[ioc] API error {response.status_code} for {ip}")
            return None

    except requests.exceptions.Timeout:
        print(f"[ioc] Timeout querying {ip}")
        return None

    except requests.exceptions.ConnectionError:
        print(f"[ioc] No internet connection — skipping enrichment")
        return None


# ─────────────────────────────────────────────
#  ENRICH ONE IP
# ─────────────────────────────────────────────

def enrich_ip(ip: str) -> dict | None:
    """
    Main function — enriches one IP.
    Checks cache first, only calls API if needed.
    Returns enrichment dict or None.
    """
    config   = load_config()
    api_key  = config["abuseipdb"]["api_key"]
    max_age  = config["abuseipdb"].get("cache_hours", 24)

    if not api_key or api_key == "PUT_YOUR_API_KEY_HERE":
        return None

    # Skip private/internal IPs — no point checking these
    if is_private_ip(ip):
        print(f"[ioc] Skipping private IP: {ip}")
        return None

    # Check cache first
    cached = get_cached_ioc(ip, max_age_hours=max_age)
    if cached:
        print(f"[ioc] Cache hit: {ip} (score: {cached['abuse_score']})")
        return cached

    # Cache miss — call the API
    print(f"[ioc] Querying AbuseIPDB for: {ip}")
    data = query_abuseipdb(ip, api_key)

    if not data:
        return None

    # Normalize into our format
    ioc = {
        "ip":             ip,
        "queried_at":     datetime.now().isoformat(),
        "abuse_score":    data.get("abuseConfidenceScore", 0),
        "total_reports":  data.get("totalReports", 0),
        "country_code":   data.get("countryCode", ""),
        "isp":            data.get("isp", ""),
        "usage_type":     data.get("usageType", ""),
        "last_reported":  data.get("lastReportedAt", ""),
        "is_whitelisted": int(data.get("isWhitelisted", False)),
        "raw_response":   json.dumps(data),
    }

    # Save to cache
    save_ioc_cache(ioc)
    return ioc


# ─────────────────────────────────────────────
#  ENRICH MULTIPLE IPs (batch)
# ─────────────────────────────────────────────

def enrich_alert_ips(alerts: list[dict]) -> list[dict]:
    """
    Takes a list of alert dicts, enriches each source_ip,
    attaches enrichment data to the alert, returns updated alerts.
    """
    config    = load_config()
    min_score = config["abuseipdb"].get("min_score_alert", 25)

    enriched = []
    seen_ips  = {}  # avoid duplicate API calls within one batch

    for alert in alerts:
        ip = alert.get("source_ip")
        if not ip:
            enriched.append(alert)
            continue

        # Check if we already queried this IP in this batch
        if ip not in seen_ips:
            seen_ips[ip] = enrich_ip(ip)

        ioc = seen_ips[ip]

        if ioc:
            alert["ioc_score"]        = ioc["abuse_score"]
            alert["ioc_country"]      = ioc["country_code"]
            alert["ioc_isp"]          = ioc["isp"]
            alert["ioc_total_reports"]= ioc["total_reports"]
            alert["ioc_last_reported"]= ioc["last_reported"]

            # Upgrade severity if IP has high abuse score
            if ioc["abuse_score"] >= 75 and alert["severity"] != "CRITICAL":
                print(f"[ioc] Upgrading {ip} to CRITICAL (abuse score: {ioc['abuse_score']})")
                alert["severity"] = "CRITICAL"

            elif ioc["abuse_score"] >= min_score:
                print(f"[ioc] {ip} confirmed malicious (score: {ioc['abuse_score']}, "
                      f"reports: {ioc['total_reports']}, country: {ioc['country_code']})")

        enriched.append(alert)

    return enriched


# ─────────────────────────────────────────────
#  UTILITY
# ─────────────────────────────────────────────

def is_private_ip(ip: str) -> bool:
    """Return True for RFC1918 and loopback addresses — no point enriching these."""
    import ipaddress
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def get_threat_label(score: int) -> str:
    """Human-readable label for an abuse score."""
    if score >= 75:  return "KNOWN MALICIOUS"
    if score >= 50:  return "HIGH RISK"
    if score >= 25:  return "SUSPICIOUS"
    if score >= 1:   return "LOW RISK"
    return "CLEAN"