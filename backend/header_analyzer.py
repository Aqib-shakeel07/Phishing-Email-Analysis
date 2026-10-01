import re
import math
import email
from email import policy
from email.utils import parseaddr, getaddresses, parsedate_to_datetime
from datetime import timezone
from collections import Counter
from helpers import (
    extract_domain, similarity, normalize_homoglyphs,
    load_brands, clamp
)
from logger import logger


AUTH_REGEX = {
    "spf": re.compile(r"spf=(\w+)", re.IGNORECASE),
    "dkim": re.compile(r"dkim=(\w+)", re.IGNORECASE),
    "dmarc": re.compile(r"dmarc=(\w+)", re.IGNORECASE),
}

RECEIVED_FROM_BY_RE = re.compile(
    r"from\s+(?P<from_host>[^\s(]+)(?:\s*\((?P<from_ip>[^)]+)\))?"
    r"(?:\s+by\s+(?P<by_host>[^\s(]+)(?:\s*\((?P<by_ip>[^)]+)\))?)?",
    re.IGNORECASE,
)
RECEIVED_WITH_RE = re.compile(
    r"with\s+(?P<with>[^;]+?)(?:;|$)",
    re.IGNORECASE,
)

FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "live.com", "aol.com", "protonmail.com", "proton.me",
    "mail.com", "gmx.com", "yandex.com", "zoho.com", "icloud.com",
    "msn.com", "me.com",
}


def _split_addresses(header_value):
    if not header_value:
        return []
    return [(n.strip(), e.strip()) for n, e in getaddresses([header_value]) if e]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((n / length) * math.log2(n / length) for n in freq.values())


def _is_random_local_part(local: str) -> bool:
    """Detect gibberish local parts like mligbkficadjirujblurcj837."""
    if not local or len(local) < 14:
        return False
    # If it contains normal word separators, it's likely not random
    if re.search(r"[._-]", local):
        return False
    entropy = _shannon_entropy(local)
    # High entropy + long + no vowels pattern = random
    vowels = sum(1 for c in local if c.lower() in "aeiou")
    vowel_ratio = vowels / len(local)
    return entropy > 3.2 and vowel_ratio < 0.35


def _is_person_name(name: str) -> bool:
    """Detect 'First Last' style person names."""
    if not name:
        return False
    name = name.strip()
    return bool(re.fullmatch(r"[A-Z][a-zA-Z'\-]+ [A-Z][a-zA-Z'\-]+", name))


def _parse_received(hdr: str, index: int, prev_dt=None):
    hdr_clean = re.sub(r"\s+", " ", hdr).strip()

    hop = {
        "hop": index,
        "raw": hdr_clean,
        "from_host": None,
        "from_ip": None,
        "by_host": None,
        "by_ip": None,
        "with": None,
        "time": None,
        "delay_seconds": None,
    }

    m = RECEIVED_FROM_BY_RE.search(hdr_clean)
    if m:
        hop["from_host"] = m.group("from_host")
        hop["from_ip"] = m.group("from_ip")
        hop["by_host"] = m.group("by_host")
        hop["by_ip"] = m.group("by_ip")

    w = RECEIVED_WITH_RE.search(hdr_clean)
    if w:
        hop["with"] = w.group("with").strip()

    date_part = hdr_clean.rsplit(";", 1)[-1].strip() if ";" in hdr_clean else None
    if date_part:
        try:
            dt = parsedate_to_datetime(date_part)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            hop["time"] = dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            if prev_dt:
                diff = (dt - prev_dt).total_seconds()
                if diff >= 0:
                    hop["delay_seconds"] = int(diff)
        except Exception:
            pass

    return hop


class HeaderAnalyzer:
    def __init__(self):
        self.brands = load_brands()

    def analyze(self, msg: email.message.Message) -> dict:
        result = {
            "sender": None,
            "sender_name": None,
            "sender_domain": None,
            "reply_to": None,
            "reply_to_domain": None,
            "return_path": None,
            "return_path_domain": None,
            "to": [],
            "cc": [],
            "subject": None,
            "date": None,
            "message_id": None,

            "spf_present": False, "spf_pass": None, "spf_raw": None,
            "dkim_present": False, "dkim_pass": None, "dkim_raw": None,
            "dmarc_present": False, "dmarc_pass": None, "dmarc_raw": None,
            "auth_headers_raw": None,

            "auth_summary": {},
            "hops": [],
            "full_headers": [],
            "received_chain": [],

            "flags": [],
            "score": 0.0,
        }

        score = 0.0

        # ----- From -----
        from_header = msg.get("From", "")
        sender_name, sender_email = parseaddr(from_header)
        result["sender"] = sender_email
        result["sender_name"] = sender_name
        result["sender_domain"] = extract_domain(sender_email)

        # ----- To / Cc -----
        result["to"] = _split_addresses(msg.get("To"))
        result["cc"] = _split_addresses(msg.get("Cc"))

        # ----- Reply-To -----
        reply_to = msg.get("Reply-To", "")
        if reply_to:
            _, rt_email = parseaddr(reply_to)
            result["reply_to"] = rt_email
            result["reply_to_domain"] = extract_domain(rt_email)

        # ----- Return-Path -----
        return_path = msg.get("Return-Path", "")
        if return_path:
            _, rp_email = parseaddr(return_path)
            result["return_path"] = rp_email
            result["return_path_domain"] = extract_domain(rp_email)

        result["subject"] = msg.get("Subject", "")
        result["date"] = msg.get("Date", "")
        result["message_id"] = msg.get("Message-ID", "")

        full = []
        for k, v in msg.items():
            full.append({"name": k, "value": str(v)})
        result["full_headers"] = full

        # ----- Hops -----
        received = msg.get_all("Received", []) or []
        result["received_chain"] = [r.strip() for r in received]

        hops = []
        prev_dt = None
        for i, rcv in enumerate(reversed(received), start=1):
            hop = _parse_received(rcv, i, prev_dt)
            hops.append(hop)
            if hop.get("time"):
                try:
                    dt = parsedate_to_datetime(hop["time"].replace(" UTC", " +0000"))
                    prev_dt = dt
                except Exception:
                    pass
        result["hops"] = hops

        # ----- Authentication -----
        auth_parts = []
        auth_parts += msg.get_all("Authentication-Results", []) or []
        auth_parts += msg.get_all("ARC-Authentication-Results", []) or []
        auth_parts += msg.get_all("Received-SPF", []) or []
        auth_parts += msg.get_all("DKIM-Signature", []) or []

        auth_text = " ".join(auth_parts)
        result["auth_headers_raw"] = auth_text if auth_text else None

        spf_pub = bool(msg.get("Received-SPF") or
                       any("spf=" in (x or "").lower() for x in msg.get_all("Authentication-Results", []) or []))
        dkim_pub = bool(msg.get("DKIM-Signature"))
        dmarc_pub = bool(msg.get("DMARC-Filter") or
                         any("dmarc=" in (x or "").lower() for x in msg.get_all("Authentication-Results", []) or []))

        if auth_text:
            spf = AUTH_REGEX["spf"].search(auth_text)
            dkim = AUTH_REGEX["dkim"].search(auth_text)
            dmarc = AUTH_REGEX["dmarc"].search(auth_text)

            if spf:
                result["spf_present"] = True
                result["spf_raw"] = spf.group(1).lower()
                result["spf_pass"] = result["spf_raw"] == "pass"
                if not result["spf_pass"]:
                    score += 15
                    result["flags"].append(f"SPF {result['spf_raw']}")
            if dkim:
                result["dkim_present"] = True
                result["dkim_raw"] = dkim.group(1).lower()
                result["dkim_pass"] = result["dkim_raw"] == "pass"
                if not result["dkim_pass"]:
                    score += 15
                    result["flags"].append(f"DKIM {result['dkim_raw']}")
            if dmarc:
                result["dmarc_present"] = True
                result["dmarc_raw"] = dmarc.group(1).lower()
                result["dmarc_pass"] = result["dmarc_raw"] == "pass"
                if not result["dmarc_pass"]:
                    score += 15
                    result["flags"].append(f"DMARC {result['dmarc_raw']}")

            if not result["spf_present"]:
                result["flags"].append("SPF result missing from Authentication-Results")
                score += 5
            if not result["dkim_present"]:
                result["flags"].append("DKIM result missing from Authentication-Results")
                score += 5
            if not result["dmarc_present"]:
                result["flags"].append("DMARC result missing from Authentication-Results")
                score += 5
        else:
            result["flags"].append("No Authentication-Results / SPF / DKIM headers present")
            score += 10

        result["auth_summary"] = {
            "spf_published": spf_pub,
            "spf_authenticated": result["spf_pass"],
            "spf_aligned": result.get("spf_raw") == "pass",
            "dkim_published": dkim_pub,
            "dkim_authenticated": result["dkim_pass"],
            "dkim_aligned": result["dkim_pass"] is True,
            "dmarc_published": dmarc_pub,
            "dmarc_compliant": (result["spf_pass"] is True and result["dkim_pass"] is True),
        }

        # ============================================================
        # NEW RULES
        # ============================================================

        # --- NEW RULE 1: Random-string sender local part ---
        local_part = sender_email.split("@")[0] if sender_email else ""
        if _is_random_local_part(local_part):
            score += 25
            result["flags"].append(
                f"Random-string sender local part: '{local_part}' "
                f"(typical of bot/compromised accounts)"
            )

        # --- NEW RULE 2: Person name from free email domain ---
        if _is_person_name(sender_name) and result["sender_domain"] in FREE_EMAIL_DOMAINS:
            score += 20
            result["flags"].append(
                f"Person name '{sender_name}' sent from free email "
                f"domain '{result['sender_domain']}' — common impersonation pattern"
            )

        # --- NEW RULE 3: Free email sender → corporate recipient ---
        if result["sender_domain"] in FREE_EMAIL_DOMAINS and result["to"]:
            external_recipients = []
            for _n, e in result["to"]:
                d = extract_domain(e)
                if d and d not in FREE_EMAIL_DOMAINS and d != result["sender_domain"]:
                    external_recipients.append(d)
            if external_recipients:
                score += 10
                result["flags"].append(
                    f"Free email domain sender '{result['sender_domain']}' "
                    f"sending to corporate domain(s): {', '.join(external_recipients[:3])}"
                )

        # --- NEW RULE 4: Received chain contains HTTPREST from Gmail API ---
        received_raw = " ".join(result["received_chain"]).lower()
        if "httpREST".lower() in received_raw and "gmailapi.google.com" in received_raw:
            score += 15
            result["flags"].append(
                "Email sent via Gmail API (HTTPREST) — common in automated/bot phishing"
            )

        # ============================================================

        # ----- Display name spoofing (existing) -----
        if sender_name and sender_email:
            name_brand = self._match_brand_in_text(sender_name)
            if name_brand:
                expected = self._brand_domains(name_brand)
                if result["sender_domain"] not in expected:
                    score += 25
                    result["flags"].append(
                        f"Display name '{sender_name}' claims '{name_brand}' "
                        f"but domain is '{result['sender_domain']}'"
                    )
            elif re.search(
                r"\b(security|support|helpdesk|service|admin|team|alert|bank)\b",
                sender_name, re.I
            ):
                score += 5
                result["flags"].append(f"Generic sender display name: '{sender_name}'")

        # ----- Reply-To mismatch -----
        if result["reply_to_domain"] and result["sender_domain"]:
            if result["reply_to_domain"] != result["sender_domain"]:
                score += 15
                result["flags"].append(
                    f"Reply-To '{result['reply_to_domain']}' differs from "
                    f"From '{result['sender_domain']}'"
                )

        # ----- Return-Path mismatch -----
        if result["return_path_domain"] and result["sender_domain"]:
            if result["return_path_domain"] != result["sender_domain"]:
                score += 10
                result["flags"].append(
                    f"Return-Path '{result['return_path_domain']}' differs from "
                    f"From '{result['sender_domain']}'"
                )

        # ----- Lookalike sender domain -----
        lookalike = self._check_lookalike(result["sender_domain"])
        if lookalike:
            score += 30
            result["flags"].append(
                f"Sender domain '{result['sender_domain']}' looks like '{lookalike}'"
            )

        # ----- Missing headers -----
        if not msg.get("Message-ID"):
            score += 5
            result["flags"].append("Missing Message-ID header")
        if not msg.get("Date"):
            score += 5
            result["flags"].append("Missing Date header")
        if not msg.get("To"):
            score += 3
            result["flags"].append("Missing To header")
        if not result["received_chain"]:
            score += 5
            result["flags"].append("No Received headers (possible spoofed source)")

        result["score"] = clamp(score, 0, 100)
        logger.info(f"Header analysis score: {result['score']}")
        return result

    # ------------- helpers -------------

    def _match_brand_in_text(self, text: str) -> str | None:
        if not text:
            return None
        low = normalize_homoglyphs(text)
        for brand in self.brands:
            name = brand["name"].lower().replace(" ", "")
            if name in low.replace(" ", ""):
                return brand["name"]
        return None

    def _brand_domains(self, brand_name: str) -> list:
        for brand in self.brands:
            if brand["name"] == brand_name:
                return brand["domains"]
        return []

    def _check_lookalike(self, domain: str) -> str | None:
        if not domain:
            return None
        base = domain.split(".")[0]
        norm_base = normalize_homoglyphs(base)
        for brand in self.brands:
            for bd in brand["domains"]:
                brand_base = bd.split(".")[0]
                if base == brand_base:
                    continue
                if brand_base in norm_base:
                    return brand["name"]
                sim = similarity(norm_base, brand_base)
                if sim >= 0.80:
                    return brand["name"]
        return None


def parse_email_bytes(raw_bytes: bytes) -> email.message.Message:
    return email.message_from_bytes(raw_bytes, policy=policy.default)


def parse_email_file(path: str) -> email.message.Message:
    with open(path, "rb") as f:
        return email.message_from_binary_file(f, policy=policy.default)