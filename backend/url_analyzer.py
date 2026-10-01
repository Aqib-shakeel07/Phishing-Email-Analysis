import re
import socket
import ipaddress
from urllib.parse import urlparse, unquote
from bs4 import BeautifulSoup
from helpers import (
    extract_domain, get_full_host, get_subdomain,
    load_brands, load_tlds, similarity,
    normalize_homoglyphs, extract_urls, clamp
)
from validators import (
    is_ip_url, is_https, has_at_symbol,
    has_encoded_chars, is_punycode,
    has_excessive_subdomains, has_long_url
)
from logger import logger


IP_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

# $<base64> — pre-filled credential phishing pattern
B64_PAYLOAD_RE = re.compile(r"[\$?](?:u=)?[A-Za-z0-9+/=]{20,}")


def clean_url(url: str) -> str:
    if not url:
        return ""
    url = url.strip()
    while url and url[-1] in ".,;:!?\"')]>":
        url = url[:-1]
    return url


def normalize_url(url: str) -> str:
    u = clean_url(url).lower()
    if u.startswith("//"):
        u = "http:" + u
    return u


class URLAnalyzer:
    def __init__(self):
        self.brands = load_brands()
        self.tlds = load_tlds()
        self.high_risk_tlds = set(self.tlds.get("high_risk", []))
        self.medium_risk_tlds = set(self.tlds.get("medium_risk", []))
        self.shortners = set(self.tlds.get("url_shorteners", []))
        self.free_hosts = set(self.tlds.get("free_hosting", []))

    # ---------------- Public ----------------

    def analyze_text(self, text: str) -> dict:
        urls = extract_urls(text)
        ips = self.extract_ips(text)
        result = self.analyze_urls(urls)
        result["ips"] = ips
        return result

    def analyze_html(self, html: str) -> dict:
        soup = BeautifulSoup(html or "", "lxml")
        urls = []
        mismatches = []

        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            link_text = a.get_text(strip=True)
            if href.lower().startswith(("mailto:", "tel:", "#", "javascript:")):
                continue
            urls.append(href)
            if link_text and self._looks_like_url(link_text):
                if extract_domain(link_text) and extract_domain(href):
                    if extract_domain(link_text) != extract_domain(href):
                        mismatches.append({"text": link_text, "href": href})

        for img in soup.find_all("img", src=True):
            src = img["src"].strip()
            if src.lower().startswith(("cid:", "data:")):
                continue
            urls.append(src)

        urls = self._dedup(urls)

        result = self.analyze_urls(urls)
        result["ips"] = self.extract_ips(html or "")
        if mismatches:
            result["flags"].append(
                f"{len(mismatches)} link(s) with text/href domain mismatch"
            )
            result["score"] = clamp(result["score"] + 20 * len(mismatches))
            result["link_mismatches"] = mismatches
        return result

    def analyze_urls(self, urls: list) -> dict:
        result = {
            "urls": [],
            "ips": [],
            "flags": [],
            "score": 0.0,
            "link_mismatches": [],
        }
        if not urls:
            return result

        urls = self._dedup(urls)

        per_url_scores = []
        for url in urls:
            info = self._analyze_single(url)
            result["urls"].append(info)
            per_url_scores.append(info["score"])
            result["flags"].extend(info["flags"])

        if per_url_scores:
            avg = sum(per_url_scores) / len(per_url_scores)
            worst = max(per_url_scores)
            result["score"] = clamp(0.6 * avg + 0.4 * worst)

        result["flags"] = sorted(set(result["flags"]))
        logger.info(f"URL analysis score: {result['score']} ({len(urls)} urls)")
        return result

    def extract_ips(self, text: str) -> list:
        if not text:
            return []
        found = IP_REGEX.findall(text)
        out = []
        seen = set()
        for ip in found:
            if ip in seen:
                continue
            seen.add(ip)
            info = {"ip": ip, "private": False, "loopback": False,
                    "link_local": False, "multicast": False, "public": True}
            try:
                obj = ipaddress.ip_address(ip)
                info["private"] = obj.is_private
                info["loopback"] = obj.is_loopback
                info["link_local"] = obj.is_link_local
                info["multicast"] = obj.is_multicast
                info["public"] = obj.is_global
            except ValueError:
                pass
            out.append(info)
        return out

    # ---------------- Internal ----------------

    def _dedup(self, urls: list) -> list:
        seen = set()
        out = []
        for u in urls:
            if not u:
                continue
            c = clean_url(u)
            if not c:
                continue
            key = normalize_url(c).split("#")[0]
            if key in seen:
                continue
            seen.add(key)
            out.append(c)
        return out

    def _analyze_single(self, url: str) -> dict:
        info = {
            "url": url,
            "domain": extract_domain(url),
            "host": get_full_host(url),
            "subdomain": get_subdomain(url),
            "flags": [],
            "score": 0.0,
        }
        score = 0.0

        if is_ip_url(url):
            score += 30
            info["flags"].append(f"IP-based URL: {url}")

        if has_at_symbol(url):
            score += 25
            info["flags"].append(f"URL contains '@': {url}")

        if has_encoded_chars(url):
            score += 10
            info["flags"].append(f"URL has encoded characters: {url}")

        if is_punycode(url):
            score += 25
            info["flags"].append(f"Punycode/homograph domain: {url}")

        if not is_https(url):
            score += 5

        if has_excessive_subdomains(url):
            score += 15
            info["flags"].append(f"Excessive subdomains: {url}")

        if has_long_url(url):
            score += 10
            info["flags"].append(f"Unusually long URL: {url}")

        if len(url) > 200:
            score += 15
            info["flags"].append(f"Extremely long URL ({len(url)} chars)")

        if self._has_obfuscated_path(url):
            score += 15
            info["flags"].append(f"Obfuscated/long random path: {info['domain']}")

        # --- NEW: $base64 payload (pre-filled credential phishing) ---
        if B64_PAYLOAD_RE.search(url):
            score += 20
            info["flags"].append(
                f"URL contains $base64 payload (pre-filled credential phish): {info['domain']}"
            )

        host = info["host"]

        if any(host.endswith(s) for s in self.shortners):
            score += 20
            info["flags"].append(f"URL shortener used: {host}")

        if any(host.endswith(f) for f in self.free_hosts):
            score += 15
            info["flags"].append(f"Free hosting domain: {host}")

        tld = info["domain"].split(".")[-1] if info["domain"] else ""
        if tld in self.high_risk_tlds:
            score += 25
            info["flags"].append(f"High-risk TLD: .{tld}")
        elif tld in self.medium_risk_tlds:
            score += 10
            info["flags"].append(f"Medium-risk TLD: .{tld}")

        # Lookalike domain (edit-distance + substring brand match)
        lookalike = self._check_brand_lookalike(info["domain"], info["subdomain"])
        if lookalike:
            score += 30
            info["flags"].append(
                f"Domain looks like brand '{lookalike}': {info['domain']}"
            )

        # Brand used as subdomain of non-brand domain (apple.evil.com)
        brand_sub = self._detect_brand_as_subdomain(host)
        if brand_sub:
            score += 35
            info["flags"].append(
                f"Brand '{brand_sub}' used as subdomain of '{info['domain']}'"
            )
        else:
            brand_sub2 = self._brand_in_subdomain(info["subdomain"])
            if brand_sub2:
                score += 20
                info["flags"].append(
                    f"Brand '{brand_sub2}' used in subdomain: {host}"
                )

        # Brand name in URL path but wrong domain
        brand_path = self._brand_in_path(url)
        if brand_path and info["domain"]:
            expected = self._brand_domains(brand_path)
            if info["domain"] not in expected:
                score += 20
                info["flags"].append(
                    f"Brand '{brand_path}' in URL path but domain is '{info['domain']}'"
                )

        # Hyphen-heavy domain
        if info["domain"] and info["domain"].count("-") >= 2:
            score += 10
            info["flags"].append(f"Hyphen-heavy domain: {info['domain']}")

        info["score"] = clamp(score)
        return info

    def _detect_brand_as_subdomain(self, host: str) -> str | None:
        if not host or "." not in host:
            return None
        labels = host.lower().split(".")
        if len(labels) < 3:
            return None
        registered = extract_domain(host)
        for brand in self.brands:
            name = brand["name"].lower().replace(" ", "")
            for label in labels[:-2]:
                if label == name:
                    if registered not in brand["domains"]:
                        return brand["name"]
        return None

    def _brand_in_path(self, url: str) -> str | None:
        try:
            if "://" not in url:
                url = "http://" + url
            path = urlparse(url).path.lower()
        except Exception:
            return None
        if not path:
            return None
        for brand in self.brands:
            if brand["name"].lower().replace(" ", "") in path.replace("-", "").replace("_", ""):
                return brand["name"]
        return None

    def _brand_domains(self, brand_name: str) -> list:
        for brand in self.brands:
            if brand["name"] == brand_name:
                return brand["domains"]
        return []

    def _check_brand_lookalike(self, domain: str, subdomain: str) -> str | None:
        if not domain:
            return None
        base = domain.split(".")[0]
        norm_base = normalize_homoglyphs(base)

        for brand in self.brands:
            for bd in brand["domains"]:
                brand_base = bd.split(".")[0]
                if base == brand_base:
                    return None

                if brand_base in norm_base or norm_base.startswith(brand_base):
                    return brand["name"]

                sim = similarity(norm_base, brand_base)
                if sim >= 0.80 and abs(len(base) - len(brand_base)) <= 2:
                    return brand["name"]

        return None

    def _brand_in_subdomain(self, subdomain: str) -> str | None:
        if not subdomain:
            return None
        low = normalize_homoglyphs(subdomain)
        for brand in self.brands:
            if brand["name"].lower() in low:
                return brand["name"]
        return None

    def _has_obfuscated_path(self, url: str) -> bool:
        try:
            if "://" not in url:
                url = "http://" + url
            path = urlparse(url).path
        except Exception:
            return False
        if len(path) < 60:
            return False
        segs = [s for s in path.split("/") if s]
        for s in segs:
            if len(s) > 50:
                has_digit = any(c.isdigit() for c in s)
                has_upper = any(c.isupper() for c in s)
                has_lower = any(c.islower() for c in s)
                if has_digit and has_upper and has_lower:
                    return True
        return False

    def _looks_like_url(self, text: str) -> bool:
        return bool(re.search(r"(https?://|www\.|[a-z0-9-]+\.[a-z]{2,})", text, re.I))


def resolve_ip(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None