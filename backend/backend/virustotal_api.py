import requests
from config import VIRUSTOTAL_API_KEY, VIRUSTOTAL_URL, REQUEST_TIMEOUT
from database import cache_get, cache_set
from logger import logger


class VirusTotalClient:
    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or VIRUSTOTAL_API_KEY
        self.headers = {"x-apikey": self.api_key} if self.api_key else {}

    # ---------------- Public ----------------

    def lookup_hash(self, sha256: str) -> dict:
        if not self.api_key or not sha256:
            return {"positives": 0, "total": 0, "error": "no api key"}

        cached = cache_get(f"vt:hash:{sha256}")
        if cached:
            return cached

        url = f"{VIRUSTOTAL_URL}/files/{sha256}"
        try:
            r = requests.get(url, headers=self.headers, timeout=REQUEST_TIMEOUT)
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

    def lookup_url(self, url: str) -> dict:
        if not self.api_key or not url:
            return {"positives": 0, "total": 0, "error": "no api key"}

        cached = cache_get(f"vt:url:{url}")
        if cached:
            return cached

        try:
            # Submit URL
            submit = requests.post(
                f"{VIRUSTOTAL_URL}/urls",
                headers=self.headers,
                data={"url": url},
                timeout=REQUEST_TIMEOUT,
            )
            if submit.status_code not in (200, 201):
                return {"positives": 0, "total": 0, "error": "submit failed"}

            analysis_id = submit.json().get("data", {}).get("id")
            if not analysis_id:
                return {"positives": 0, "total": 0, "error": "no analysis id"}

            import time
            for _ in range(3):
                time.sleep(3)
                res = requests.get(
                    f"{VIRUSTOTAL_URL}/analyses/{analysis_id}",
                    headers=self.headers,
                    timeout=REQUEST_TIMEOUT,
                )
                if res.status_code == 200:
                    attrs = res.json().get("data", {}).get("attributes", {})
                    if attrs.get("status") == "completed":
                        stats = attrs.get("stats", {})
                        result = {
                            "positives": stats.get("malicious", 0) + stats.get("suspicious", 0),
                            "total": sum(stats.values()) if stats else 0,
                            "stats": stats,
                        }
                        cache_set(f"vt:url:{url}", result)
                        return result

            return {"positives": 0, "total": 0, "error": "analysis pending"}
        except Exception as e:
            logger.warning(f"VT URL lookup failed: {e}")
            return {"positives": 0, "total": 0, "error": str(e)}

    def lookup_domain(self, domain: str) -> dict:
        if not self.api_key or not domain:
            return {"positives": 0, "total": 0, "error": "no api key"}

        cached = cache_get(f"vt:domain:{domain}")
        if cached:
            return cached

        try:
            r = requests.get(
                f"{VIRUSTOTAL_URL}/domains/{domain}",
                headers=self.headers,
                timeout=REQUEST_TIMEOUT,
            )
            if r.status_code != 200:
                return {"positives": 0, "total": 0, "error": f"status {r.status_code}"}
            stats = (r.json().get("data", {})
                         .get("attributes", {})
                         .get("last_analysis_stats", {}))
            result = {
                "positives": stats.get("malicious", 0) + stats.get("suspicious", 0),
                "total": sum(stats.values()) if stats else 0,
                "stats": stats,
            }
            cache_set(f"vt:domain:{domain}", result)
            return result
        except Exception as e:
            logger.warning(f"VT domain lookup failed: {e}")
            return {"positives": 0, "total": 0, "error": str(e)}