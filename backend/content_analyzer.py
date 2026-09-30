import re
import email
from bs4 import BeautifulSoup
from helpers import (
    load_keywords, extract_urls, extract_emails,
    normalize_homoglyphs, clamp
)
from logger import logger


class ContentAnalyzer:
    def __init__(self):
        self.keywords = load_keywords()

    # ---------------- Public ----------------

    def analyze(self, msg: email.message.Message) -> dict:
        result = {
            "body_text": "",
            "body_html": "",
            "flags": [],
            "score": 0.0,
            "matched_keywords": {},
            "has_html": False,
            "has_plain": False,
            "word_count": 0,
        }

        text_body, html_body = self._extract_bodies(msg)
        result["body_text"] = text_body
        result["body_html"] = html_body
        result["has_html"] = bool(html_body)
        result["has_plain"] = bool(text_body)

        combined = (text_body + " " + html_body).strip()
        result["word_count"] = len(combined.split())

        if not combined:
            result["flags"].append("Empty email body")
            result["score"] = 10.0
            return result

        score = 0.0
        matched = {}

        # ----- Keyword categories -----
        low = combined.lower()

        for category, words in self.keywords.items():
            hits = []
            for w in words:
                if w.lower() in low:
                    hits.append(w)
            if hits:
                matched[category] = hits

        result["matched_keywords"] = matched

        score += len(matched.get("urgency", [])) * 5
        score += len(matched.get("threat", [])) * 7
        score += len(matched.get("credential_request", [])) * 10
        score += len(matched.get("reward", [])) * 6
        score += len(matched.get("financial", [])) * 5
        score += len(matched.get("action_buttons", [])) * 5
        score += len(matched.get("delivery_scam", [])) * 5

        if matched.get("credential_request"):
            result["flags"].append("Credential/OTP request detected")
        if matched.get("threat"):
            result["flags"].append("Threatening language detected")
        if matched.get("urgency"):
            result["flags"].append("Urgency pressure detected")
        if matched.get("reward"):
            result["flags"].append("Too-good-to-be-true reward language")
        if matched.get("greeting_generic"):
            result["flags"].append("Generic greeting used")

        # ----- HTML-only email -----
        if html_body and not text_body:
            score += 8
            result["flags"].append("HTML-only email (no plain-text part)")

        # ----- Hidden text / invisible chars -----
        if html_body:
            hidden = self._find_hidden_text(html_body)
            if hidden:
                score += 15
                result["flags"].append("Hidden/invisible text found in HTML")

        # ----- Mismatch between visible text & anchors -----
        if html_body:
            soup = BeautifulSoup(html_body, "lxml")
            mism = self._anchor_text_mismatch(soup)
            if mism:
                score += 15 * min(len(mism), 3)
                result["flags"].append(
                    f"{len(mism)} anchor(s) with deceptive link text"
                )

        # ----- Excessive punctuation / caps -----
        if self._is_shouty(combined):
            score += 8
            result["flags"].append("Excessive uppercase or punctuation")

        # ----- Forms in email -----
        if html_body and re.search(r"<form\b", html_body, re.I):
            score += 25
            result["flags"].append("Embedded HTML form (credential harvesting)")

        # ----- Password/OTP fields -----
        if html_body and re.search(
            r'type=["\']?(password|otp|pin)["\']?', html_body, re.I
        ):
            score += 20
            result["flags"].append("Password/OTP input field in email")

        result["score"] = clamp(score, 0, 100)
        logger.info(f"Content analysis score: {result['score']}")
        return result

    # ---------------- Internal ----------------

    def _extract_bodies(self, msg: email.message.Message):
        text_body = ""
        html_body = ""

        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                disp = str(part.get("Content-Disposition") or "")
                if "attachment" in disp.lower():
                    continue

                try:
                    payload = part.get_content()
                except Exception:
                    continue

                if ctype == "text/plain" and isinstance(payload, str):
                    text_body += payload + "\n"
                elif ctype == "text/html" and isinstance(payload, str):
                    html_body += payload + "\n"
        else:
            try:
                payload = msg.get_content()
            except Exception:
                payload = ""
            if msg.get_content_type() == "text/html":
                html_body = payload or ""
            else:
                text_body = payload or ""

        return text_body.strip(), html_body.strip()

    def _find_hidden_text(self, html: str) -> list:
        hidden = []
        patterns = [
            r'style=["\'][^"\']*display\s*:\s*none',
            r'style=["\'][^"\']*visibility\s*:\s*hidden',
            r'style=["\'][^"\']*font-size\s*:\s*0',
            r'color\s*:\s*#?(?:fff|ffffff|white)',
        ]
        for p in patterns:
            if re.search(p, html, re.I):
                hidden.append(p)
        return hidden

    def _anchor_text_mismatch(self, soup: BeautifulSoup) -> list:
        mismatches = []
        url_re = re.compile(r"(https?://|www\.)", re.I)
        for a in soup.find_all("a", href=True):
            text = a.get_text(strip=True)
            href = a["href"].strip()
            if not text or not url_re.search(text):
                continue
            text_host = re.sub(r"^https?://", "", text, flags=re.I).split("/")[0]
            href_host = re.sub(r"^https?://", "", href, flags=re.I).split("/")[0]
            if text_host and href_host and text_host.lower() != href_host.lower():
                mismatches.append({"text": text, "href": href})
        return mismatches

    def _is_shouty(self, text: str) -> bool:
        if not text:
            return False
        letters = [c for c in text if c.isalpha()]
        if not letters:
            return False
        upper_ratio = sum(1 for c in letters if c.isupper()) / len(letters)
        exclam = text.count("!")
        return upper_ratio > 0.5 or exclam >= 5