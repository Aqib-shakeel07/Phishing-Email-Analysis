import time
import requests
from config import (
    VIRUSTOTAL_API_KEY, VIRUSTOTAL_URL,
    REQUEST_TIMEOUT, CACHE_TTL_VT
)
from database import cache_get, cache_set
from logger import logger


class VirusTotalClient:
    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or VIRUSTOTAL_API_KEY
        self.headers = {"x-apikey": self.api_key} if self.api_key else {}

    def is_ready(self) -> bool:
        return bool(self.api_key)

    # ---------------- Public ----------------

    def lookup_hash(self, sha256: str) -> dict:
        """File hash lookup (used by attachment analyzer)."""
        if not self.api_key or not sha256:
            return {"positives": 0, "total": 0, "error": "no api key"}

        cached = cache_get(f"vt:hash:{sha256}")
        if cached:
            return cached

        try:
            r = requests.get(
                f"{VIRUSTOTAL_URL}/files/{sha256}",
                headers=self.headers,
                timeout=REQUEST_TIMEOUT,
            )
            if r.status_code == 404:
                result = {"positives": 0, "total": 0, "known": False}
                cache_set(f"vt:hash:{sha256}", result)
                return result
            r.raise_for_status()
            data = r.json()
            stats = (data.get("data", {})
                        .get("attributes", {})
                        .get("last_analysis_stats", {}))
            result = {
                "positives": stats.get("malicious", 0) + stats.get("suspicious", 0),
                "total": sum(stats.values()) if stats else 0,
                "known": True,
                "stats": stats,
            }
            cache_set(f"vt:hash:{sha256}", result)
            return result
        except Exception as e:
            logger.warning(f"VT hash lookup failed: {e}")
            return {"positives": 0, "total": 0, "error": str(e)}

    def lookup_ip(self, ip: str) -> dict:
        """Full IP report."""
        if not self.api_key or not ip:
            return {"error": "no api key", "ip": ip, "raw": None}

        cached = cache_get(f"vt:ip:{ip}")
        if cached:
            return cached

        try:
            r = requests.get(
                f"{VIRUSTOTAL_URL}/ip_addresses/{ip}",
                headers=self.headers,
                timeout=REQUEST_TIMEOUT,
            )
            if r.status_code == 404:
                result = {"ip": ip, "known": False, "error": None, "raw": None}
                cache_set(f"vt:ip:{ip}", result)
                return result
            r.raise_for_status()
            data = r.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            result = {
                "ip": ip,
                "known": True,
                "error": None,
                "positives": stats.get("malicious", 0) + stats.get("suspicious", 0),
                "total_engines": sum(stats.values()) if stats else 0,
                "stats": stats,
                "country": attrs.get("country"),
                "as_owner": attrs.get("as_owner"),
                "asn": attrs.get("asn"),
                "network": attrs.get("network"),
                "reputation": attrs.get("reputation"),
                "continent": attrs.get("continent"),
                "regional_internet_registry": attrs.get("regional_internet_registry"),
                "tags": attrs.get("tags", []),
                "whois": attrs.get("whois"),
                "last_analysis_date": attrs.get("last_analysis_date"),
                "last_modification_date": attrs.get("last_modification_date"),
                "raw": attrs,
            }
            cache_set(f"vt:ip:{ip}", result)
            return result
        except Exception as e:
            logger.warning(f"VT IP lookup failed: {e}")
            return {"ip": ip, "error": str(e), "raw": None}

    def lookup_url_full(self, url: str) -> dict:
        """
        Submit a URL for scanning and fetch the full report.
        Note: fresh URLs may take 5–20s to complete.
        """
        if not self.api_key or not url:
            return {"error": "no api key", "url": url, "raw": None}

        cached = cache_get(f"vt:urlfull:{url}")
        if cached:
            return cached

        try:
            # Submit
            submit = requests.post(
                f"{VIRUSTOTAL_URL}/urls",
                headers=self.headers,
                data={"url": url},
                timeout=REQUEST_TIMEOUT,
            )
            if submit.status_code not in (200, 201):
                return {"url": url, "error": f"submit failed ({submit.status_code})", "raw": None}

            analysis_id = submit.json().get("data", {}).get("id")
            if not analysis_id:
                return {"url": url, "error": "no analysis id", "raw": None}

            # Poll a few times
            for _ in range(5):
                time.sleep(3)
                res = requests.get(
                    f"{VIRUSTOTAL_URL}/analyses/{analysis_id}",
                    headers=self.headers,
                    timeout=REQUEST_TIMEOUT,
                )
                if res.status_code != 200:
                    continue
                payload = res.json().get("data", {})
                attrs = payload.get("attributes", {})
                if attrs.get("status") == "completed":
                    stats = attrs.get("stats", {})
                    result = {
                        "url": url,
                        "known": True,
                        "error": None,
                        "positives": stats.get("malicious", 0) + stats.get("suspicious", 0),
                        "total_engines": sum(stats.values()) if stats else 0,
                        "stats": stats,
                        "raw": attrs,
                    }
                    cache_set(f"vt:urlfull:{url}", result)
                    return result

            pending = {"url": url, "known": False, "error": "analysis pending", "raw": None}
            cache_set(f"vt:urlfull:{url}", pending)
            return pending
        except Exception as e:
            logger.warning(f"VT URL full lookup failed: {e}")
            return {"url": url, "error": str(e), "raw": None}

    def lookup_domain_full(self, domain: str) -> dict:
        """Full domain report."""
        if not self.api_key or not domain:
            return {"error": "no api key", "domain": domain, "raw": None}

        cached = cache_get(f"vt:domainfull:{domain}")
        if cached:
            return cached

        try:
            r = requests.get(
                f"{VIRUSTOTAL_URL}/domains/{domain}",
                headers=self.headers,
                timeout=REQUEST_TIMEOUT,
            )
            if r.status_code == 404:
                result = {"domain": domain, "known": False, "error": None, "raw": None}
                cache_set(f"vt:domainfull:{domain}", result)
                return result
            r.raise_for_status()
            data = r.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            result = {
                "domain": domain,
                "known": True,
                "error": None,
                "positives": stats.get("malicious", 0) + stats.get("suspicious", 0),
                "total_engines": sum(stats.values()) if stats else 0,
                "stats": stats,
                "reputation": attrs.get("reputation"),
                "registrar": attrs.get("registrar"),
                "creation_date": attrs.get("creation_date"),
                "last_update_date": attrs.get("last_update_date"),
                "categories": attrs.get("categories", {}),
                "tags": attrs.get("tags", []),
                "whois": attrs.get("whois"),
                "dns_records": attrs.get("last_dns_records", []),
                "raw": attrs,
            }
            cache_set(f"vt:domainfull:{domain}", result)
            return result
        except Exception as e:
            logger.warning(f"VT domain lookup failed: {e}")
            return {"domain": domain, "error": str(e), "raw": None}

    # Back-compat aliases (older code paths)
    def lookup_url(self, url: str) -> dict:
        return self.lookup_url_full(url)

    def lookup_domain(self, domain: str) -> dict:
        return self.lookup_domain_full(domain)