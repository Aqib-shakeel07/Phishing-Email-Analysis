import whois
from datetime import datetime, timezone
from helpers import extract_domain
from database import cache_get, cache_set
from logger import logger


class WhoisLookup:
    def __init__(self, cache_ttl_days: int = 7):
        self.cache_ttl_days = cache_ttl_days

    # ---------------- Public ----------------

    def lookup(self, domain_or_email: str) -> dict:
        domain = extract_domain(domain_or_email)
        if not domain:
            return {"domain": None, "error": "invalid domain"}

        cached = cache_get(f"whois:{domain}")
        if cached:
            return cached

        result = {
            "domain": domain,
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "registrar": None,
            "name_servers": [],
            "age_days": None,
            "is_new": False,
            "error": None,
        }

        try:
            w = whois.whois(domain)
        except Exception as e:
            result["error"] = str(e)
            logger.warning(f"WHOIS failed for {domain}: {e}")
            cache_set(f"whois:{domain}", result)
            return result

        result["creation_date"] = self._first_date(w.get("creation_date"))
        result["expiration_date"] = self._first_date(w.get("expiration_date"))
        result["updated_date"] = self._first_date(w.get("updated_date"))
        result["registrar"] = w.get("registrar")
        ns = w.get("name_servers") or []
        if isinstance(ns, str):
            ns = [ns]
        result["name_servers"] = [str(n).lower() for n in ns]

        if result["creation_date"]:
            age = (datetime.now(timezone.utc) - result["creation_date"]).days
            result["age_days"] = age
            if age <= 30:
                result["is_new"] = True

        cache_set(f"whois:{domain}", result)
        return result

    def domain_age_score(self, domain_or_email: str) -> dict:
        """Return a risk contribution based on domain age."""
        info = self.lookup(domain_or_email)
        score = 0.0
        flags = []

        if info.get("error"):
            score += 5
            flags.append("WHOIS lookup failed")
        elif info["age_days"] is None:
            score += 5
            flags.append("Domain age unknown")
        elif info["age_days"] <= 7:
            score += 30
            flags.append(f"Domain registered {info['age_days']} days ago")
        elif info["age_days"] <= 30:
            score += 20
            flags.append(f"Very new domain ({info['age_days']} days)")
        elif info["age_days"] <= 90:
            score += 10
            flags.append(f"New domain ({info['age_days']} days)")
        elif info["age_days"] <= 365:
            score += 3

        return {"info": info, "score": score, "flags": flags}

    # ---------------- Internal ----------------

    def _first_date(self, value):
        if not value:
            return None
        if isinstance(value, list):
            value = value[0]
        if isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value
        return None