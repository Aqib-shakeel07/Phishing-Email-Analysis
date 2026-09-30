import re
import os
import ipaddress
from urllib.parse import urlparse
from email_validator import validate_email, EmailNotValidError
from helpers import extract_domain, get_full_host
from config import ALLOWED_EXTENSIONS, MAX_UPLOAD_SIZE


# ---------------- Email ----------------

def is_valid_email(email: str) -> bool:
    if not email:
        return False
    try:
        validate_email(email, check_deliverability=False)
        return True
    except EmailNotValidError:
        return False


def is_valid_domain(domain: str) -> bool:
    if not domain:
        return False
    pattern = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
        r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
    )
    return bool(pattern.match(domain))


# ---------------- URL ----------------

def is_valid_url(url: str) -> bool:
    if not url:
        return False
    try:
        if "://" not in url:
            url = "http://" + url
        parsed = urlparse(url)
        return bool(parsed.netloc)
    except Exception:
        return False


def is_ip_url(url: str) -> bool:
    host = get_full_host(url)
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_https(url: str) -> bool:
    if "://" not in url:
        return False
    return urlparse(url).scheme.lower() == "https"


def has_at_symbol(url: str) -> bool:
    return "@" in url


def has_encoded_chars(url: str) -> bool:
    return bool(re.search(r"%[0-9A-Fa-f]{2}", url))


def is_punycode(url: str) -> bool:
    host = get_full_host(url)
    return "xn--" in host


def has_excessive_subdomains(url: str, threshold: int = 3) -> bool:
    host = get_full_host(url)
    if not host:
        return False
    return host.count(".") >= threshold


def has_long_url(url: str, threshold: int = 100) -> bool:
    return len(url) > threshold


def has_double_extension(filename: str) -> bool:
    if not filename:
        return False
    parts = filename.lower().split(".")
    return len(parts) > 2 and parts[-1] in {
        "exe", "scr", "bat", "cmd", "js", "vbs", "jar",
        "com", "pif", "hta", "msi", "ps1"
    }


# ---------------- File ----------------

def allowed_file(filename: str) -> bool:
    if not filename or "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def file_size_ok(path: str) -> bool:
    try:
        return os.path.getsize(path) <= MAX_UPLOAD_SIZE
    except OSError:
        return False


# ---------------- Text ----------------

def is_empty(text: str) -> bool:
    return not text or not text.strip()


def contains_html(text: str) -> bool:
    if not text:
        return False
    return bool(re.search(r"<[^>]+>", text))