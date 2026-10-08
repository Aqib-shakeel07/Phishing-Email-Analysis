import re
import json
import os
import hashlib
import ipaddress
import tldextract
from urllib.parse import urlparse
from config import BRANDS_FILE, KEYWORDS_FILE, TLDS_FILE


_extractor = tldextract.TLDExtract(suffix_list_urls=())


# ---------------- JSON loaders ----------------

def load_json(path):
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_brands():
    return load_json(BRANDS_FILE).get("brands", [])


def load_keywords():
    return load_json(KEYWORDS_FILE)


def load_tlds():
    return load_json(TLDS_FILE)


# ---------------- Domain helpers ----------------

def extract_domain(email_or_url: str) -> str:
    if not email_or_url:
        return ""
    if "@" in email_or_url and "://" not in email_or_url:
        return email_or_url.split("@")[-1].strip().lower().strip(">").strip()

    if "://" not in email_or_url:
        email_or_url = "http://" + email_or_url

    try:
        parsed = urlparse(email_or_url)
        host = parsed.hostname or ""
    except Exception:
        return ""

    ext = _extractor(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return host.lower()


def get_full_host(url: str) -> str:
    if "://" not in url:
        url = "http://" + url
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def get_subdomain(url: str) -> str:
    host = get_full_host(url)
    ext = _extractor(host)
    return ext.subdomain.lower() if ext.subdomain else ""


# ---------------- Levenshtein ----------------

def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(
                prev[j] + 1,
                curr[j - 1] + 1,
                prev[j - 1] + (ca != cb)
            ))
        prev = curr
    return prev[-1]


def similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    dist = levenshtein(a, b)
    return 1 - dist / max(len(a), len(b))


# ---------------- Homoglyph ----------------

HOMOGLYPHS = {
    "0": "o", "1": "l", "3": "e", "4": "a",
    "5": "s", "7": "t", "@": "a", "$": "s",
    "rn": "m", "vv": "w",
}


def normalize_homoglyphs(text: str) -> str:
    t = text.lower()
    for k, v in HOMOGLYPHS.items():
        t = t.replace(k, v)
    return t


# ---------------- Hashing ----------------

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


# ---------------- URL extraction ----------------

URL_REGEX = re.compile(
    r"(?:(?:https?|ftp)://|www\.)[^\s<>\"')]+",
    re.IGNORECASE,
)


def extract_urls(text: str) -> list:
    if not text:
        return []
    found = URL_REGEX.findall(text)
    cleaned = []
    for u in found:
        u = u.rstrip(".,;:!?)")
        if u not in cleaned:
            cleaned.append(u)
    return cleaned


EMAIL_REGEX = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
)


def extract_emails(text: str) -> list:
    if not text:
        return []
    return list(set(EMAIL_REGEX.findall(text)))


# ---------------- IP extraction ----------------

# IPv4 (strict)
IPV4_REGEX = re.compile(
    r"(?<![0-9.])"
    r"((?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
    r"(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3})"
    r"(?![0-9.])"
)

# IPv6 (broad match, filter later with ipaddress module)
IPV6_CANDIDATE_REGEX = re.compile(
    r"(?<![0-9A-Fa-f:])"
    r"((?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}"
    r"|::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{0,4})"
    r"(?![0-9A-Fa-f:])"
)


def classify_ip(ip: str) -> dict:
    """Return a dict with ip + its classification flags."""
    info = {
        "ip": ip,
        "private": False,
        "loopback": False,
        "link_local": False,
        "multicast": False,
        "reserved": False,
        "public": True,
        "version": 4 if "." in ip else 6,
    }
    try:
        obj = ipaddress.ip_address(ip)
        info["private"] = obj.is_private
        info["loopback"] = obj.is_loopback
        info["link_local"] = obj.is_link_local
        info["multicast"] = obj.is_multicast
        info["reserved"] = obj.is_reserved
        info["public"] = obj.is_global
    except ValueError:
        info["public"] = False
        info["reserved"] = True
    return info


def extract_ips_from_text(text: str) -> list:
    """
    Extract every IPv4 and IPv6 address from arbitrary text.
    Returns a list of classification dicts (deduped by IP).
    """
    if not text:
        return []

    seen = set()
    out = []

    # IPv4
    for m in IPV4_REGEX.finditer(text):
        ip = m.group(1)
        # reject things like 999.999.999.999 (regex already prevents that)
        # reject version strings like 1.2.3.4.5 (regex already prevents)
        if ip in seen:
            continue
        seen.add(ip)
        out.append(classify_ip(ip))

    # IPv6
    for m in IPV6_CANDIDATE_REGEX.finditer(text):
        raw = m.group(1)
        # strip trailing colon issues
        raw = raw.strip(":")
        if not raw or raw == "::":
            continue
        try:
            # normalize (compressed form)
            obj = ipaddress.IPv6Address(raw)
            ip = str(obj)
        except ValueError:
            continue
        if ip in seen:
            continue
        # Skip if it's really just a portion of a MAC or time like "11:22"
        if ip.count(":") < 2:
            continue
        seen.add(ip)
        out.append(classify_ip(ip))

    return out


# ---------------- Misc ----------------

def clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


def score_to_verdict(score: float, safe_th: int = 30, susp_th: int = 60) -> str:
    if score < safe_th:
        return "Safe"
    if score < susp_th:
        return "Suspicious"
    return "Phishing"


def safe_get(d: dict, *keys, default=None):
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k)
        if d is None:
            return default
    return d