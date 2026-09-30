import requests
from config import (
    ABUSEIPDB_API_KEY, ABUSEIPDB_URL,
    REQUEST_TIMEOUT, CACHE_TTL_ABUSE
)
from database import cache_get, cache_set
from logger import logger


class AbuseIPDBClient:
    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or ABUSEIPDB_API_KEY
        self.headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        } if self.api_key else {}

    def is_ready(self) -> bool:
        return bool(self.api_key)

    def check_ip(self, ip: str, max_age_days: int = 90) -> dict:
        """Look up an IP against AbuseIPDB."""
        if not self.api_key or not ip:
            return {"ip": ip, "error": "no api key", "raw": None}

        cache_key = f"abuse:ip:{ip}:{max_age_days}"
        cached = cache_get(cache_key)
        if cached:
            return cached

        try:
            r = requests.get(
                f"{ABUSEIPDB_URL}/check",
                headers=self.headers,
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": max_age_days,
                    "verbose": "true",
                },
                timeout=REQUEST_TIMEOUT,
            )
            if r.status_code == 429:
                return {"ip": ip, "error": "rate limit exceeded", "raw": None}
            r.raise_for_status()
            data = r.json().get("data", {})
            result = {
                "ip": ip,
                "error": None,
                "is_public": data.get("isPublic"),
                "ip_version": data.get("ipVersion"),
                "is_whitelisted": data.get("isWhitelisted"),
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "country_code": data.get("countryCode"),
                "country_name": data.get("countryName"),
                "usage_type": data.get("usageType"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "hostnames": data.get("hostnames", []),
                "is_tor": data.get("isTor"),
                "total_reports": data.get("totalReports", 0),
                "num_distinct_users": data.get("numDistinctUsers", 0),
                "last_reported_at": data.get("lastReportedAt"),
                "reports": data.get("reports", [])[:10],  # cap for UI
                "raw": data,
            }
            cache_set(cache_key, result)
            return result
        except Exception as e:
            logger.warning(f"AbuseIPDB lookup failed for {ip}: {e}")
            return {"ip": ip, "error": str(e), "raw": None}

    def check_block(self, ips: list, max_age_days: int = 90) -> list:
        """Check multiple IPs (limited to 5 per request by AbuseIPDB)."""
        if not self.api_key or not ips:
            return []
        # AbuseIPDB max 5 per request. If more, chunk.
        results = []
        for i in range(0, len(ips), 5):
            chunk = ips[i:i + 5]
            try:
                r = requests.get(
                    f"{ABUSEIPDB_URL}/check-block",
                    headers=self.headers,
                    params={
                        "ipAddress": ",".join(chunk),
                        "maxAgeInDays": max_age_days,
                    },
                    timeout=REQUEST_TIMEOUT,
                )
                if r.status_code == 200:
                    results.extend(r.json().get("data", {}).get("reportedAddress", []))
            except Exception as e:
                logger.warning(f"AbuseIPDB block lookup failed: {e}")
        return results


# Singleton for convenience
abuse_client = AbuseIPDBClient()