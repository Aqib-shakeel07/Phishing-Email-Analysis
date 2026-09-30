import re
import json
import os
import hashlib
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
    """Extract registered domain from email or URL."""
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