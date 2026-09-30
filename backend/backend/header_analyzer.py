import re
import email
from email import policy
from email.utils import parseaddr, getaddresses
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


def _split_addresses(header_value):
    """Return list of (name, email) tuples from a To/Cc header."""
    if not header_value:
        return []
    return [(n.strip(), e.strip()) for n, e in getaddresses([header_value]) if e]


class HeaderAnalyzer:
    def __init__(self):
        self.brands = load_brands()

    def analyze(self, msg: email.message.Message) -> dict:
        result = {
            # basic
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

            # auth — both presence and result
            "spf_present": False,
            "spf_pass": None,
            "dkim_present": False,
            "dkim_pass": None,
            "dmarc_present": False,
            "dmarc_pass": None,
            "auth_headers_raw": None,

            # chain
            "received_chain": [],

            # results
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

        # ----- Subject / Date / Message-ID -----
        result["subject"] = msg.get("Subject", "")
        result["date"] = msg.get("Date", "")
        result["message_id"] = msg.get("Message-ID", "")

        # ----- Received -----
        received = msg.get_all("Received", []) or []
        result["received_chain"] = [r.strip() for r in received]

        # ----- Authentication headers -----
        auth_parts = []
        auth_parts += msg.get_all("Authentication-Results", []) or []
        auth_parts += msg.get_all("ARC-Authentication-Results", []) or []
        auth_parts += msg.get_all("Received-SPF", []) or []
        auth_parts += msg.get_all("DKIM-Signature", []) or []

        auth_text = " ".join(auth_parts)
        result["auth_headers_raw"] = auth_text if auth_text else None

        if auth_text:
            spf = AUTH_REGEX["spf"].search(auth_text)
            dkim = AUTH_REGEX["dkim"].search(auth_text)
            dmarc = AUTH_REGEX["dmarc"].search(auth_text)

            if spf:
                result["spf_present"] = True
                result["spf_pass"] = spf.group(1).lower() == "pass"
                if not result["spf_pass"]:
                    score += 15
                    result["flags"].append(f"SPF {spf.group(1)}")
            if dkim:
                result["dkim_present"] = True
                result["dkim_pass"] = dkim.group(1).lower() == "pass"
                if not result["dkim_pass"]:
                    score += 15
                    result["flags"].append(f"DKIM {dkim.group(1)}")
            if dmarc:
                result["dmarc_present"] = True
                result["dmarc_pass"] = dmarc.group(1).lower() == "pass"
                if not result["dmarc_pass"]:
                    score += 15
                    result["flags"].append(f"DMARC {dmarc.group(1)}")

            # Missing in a present auth block
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
            result["flags"].append(
                "No Authentication-Results / SPF / DKIM headers present"
            )
            score += 10

        # ----- Sender display-name vs email mismatch -----
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

            # Name looks like a person's name but is off-brand
            if not name_brand and re.search(
                r"\b(security|support|helpdesk|service|admin|team|alert|bank)\b",
                sender_name, re.I
            ):
                score += 5
                result["flags"].append(
                    f"Generic sender display name: '{sender_name}'"
                )

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

        # ----- Missing required headers -----
        if not msg.get("Message-ID"):
            score += 5
            result["flags"].append("Missing Message-ID header")
        if not msg.get("Date"):
            score += 5
            result["flags"].append("Missing Date header")
        if not msg.get("To"):
            score += 3
            result["flags"].append("Missing To header")

        # ----- No Received chain -----
        if not result["received_chain"]:
            score += 5
            result["flags"].append("No Received headers (possible spoofed source)")

        result["score"] = clamp(score, 0, 100)
        logger.info(f"Header analysis score: {result['score']}")
        return result

    # ------------- internal helpers -------------

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
                sim = similarity(norm_base, brand_base)
                if sim >= 0.80:
                    return brand["name"]
        return None


def parse_email_bytes(raw_bytes: bytes) -> email.message.Message:
    return email.message_from_bytes(raw_bytes, policy=policy.default)


def parse_email_file(path: str) -> email.message.Message:
    with open(path, "rb") as f:
        return email.message_from_binary_file(f, policy=policy.default)