import re
import base64
import binascii
import html
import quopri
from urllib.parse import unquote

from helpers import clamp
from logger import logger


BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{40,}={0,2})(?![A-Za-z0-9+/=])")
QP_RE = re.compile(r"(?:=[0-9A-F]{2}){4,}")
URLENC_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")
HEX_ESC_RE = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){4,}")
HEX_0X_RE = re.compile(r"(?:0x[0-9A-Fa-f]{2}){4,}")
HTML_ENT_RE = re.compile(r"(?:&#x?[0-9A-Fa-f]+;){4,}")
ENC_WORD_RE = re.compile(r"=\?[^?]+\?[BbQq]\?[^?]*\?=")

MAX_ITEMS = 60
MAX_DECODE_BYTES = 20000
SNIPPET_LEN = 200
PREVIEW_LEN = 400
MAX_DUMP_BYTES = 500000    # cap full dump so UI doesn't die on giant .emls


def _safe_b64_decode(s: str) -> str | None:
    try:
        pad = len(s) % 4
        s_padded = s + ("=" * (4 - pad)) if pad else s
        raw = base64.b64decode(s_padded, validate=False)
        if not raw:
            return None
        printable = sum(1 for b in raw if 32 <= b < 127 or b in (9, 10, 13))
        if printable / len(raw) < 0.7:
            return None
        return raw[:MAX_DECODE_BYTES].decode("utf-8", errors="replace")
    except Exception:
        return None


def _safe_b64_decode_binary(s: str):
    try:
        pad = len(s) % 4
        s_padded = s + ("=" * (4 - pad)) if pad else s
        raw = base64.b64decode(s_padded, validate=False)
        if not raw:
            return None, ""
        printable = sum(1 for b in raw if 32 <= b < 127 or b in (9, 10, 13))
        if printable / len(raw) >= 0.7:
            return raw, raw[:MAX_DECODE_BYTES].decode("utf-8", errors="replace")
        return raw, "0x" + raw[:200].hex()
    except Exception:
        return None, ""


def _decode_qp(s: str) -> str | None:
    try:
        raw = quopri.decodestring(s.encode("ascii", errors="ignore"))
        return raw[:MAX_DECODE_BYTES].decode("utf-8", errors="replace")
    except Exception:
        return None


def _decode_url(s: str) -> str:
    try:
        return unquote(s)
    except Exception:
        return ""


def _decode_hex_esc(s: str) -> str:
    try:
        cleaned = s.replace("\\x", "")
        return binascii.unhexlify(cleaned)[:MAX_DECODE_BYTES].decode("utf-8", errors="replace")
    except Exception:
        return ""


def _decode_hex_0x(s: str) -> str:
    try:
        cleaned = s.replace("0x", "")
        return binascii.unhexlify(cleaned)[:MAX_DECODE_BYTES].decode("utf-8", errors="replace")
    except Exception:
        return ""


def _decode_html_entities(s: str) -> str:
    try:
        return html.unescape(s)
    except Exception:
        return ""


def _snippet(s: str, n: int = SNIPPET_LEN) -> str:
    return s if len(s) <= n else s[:n] + "…"


def _preview(s: str, n: int = PREVIEW_LEN) -> str:
    return s if len(s) <= n else s[:n] + "…"


def _join_rfc2047_chunks(line: str) -> str:
    chunks = re.findall(r"=\?[^?]+\?([BbQq])\?([^?]*)\?=", line)
    if not chunks:
        return line
    b64_payloads = [p for (enc, p) in chunks if enc.upper() == "B"]
    qp_payloads = [p for (enc, p) in chunks if enc.upper() == "Q"]
    if b64_payloads and not qp_payloads:
        return "".join(b64_payloads)
    if qp_payloads and not b64_payloads:
        return "".join(qp_payloads)
    return "".join(b64_payloads + qp_payloads)


def _strip_rfc2047_from_body(text: str) -> str:
    if not text:
        return text
    return ENC_WORD_RE.sub(" ", text)


def _parse_header_blocks(raw: str):
    blocks = []
    current_name = None
    current_value_parts = []
    for line in raw.splitlines():
        if not line:
            if current_name is not None:
                blocks.append((current_name, " ".join(current_value_parts)))
                current_name, current_value_parts = None, []
            break
        if line[0].isspace():
            if current_name is not None:
                current_value_parts.append(line.strip())
        else:
            if current_name is not None:
                blocks.append((current_name, " ".join(current_value_parts)))
            if ":" in line:
                name, _, value = line.partition(":")
                current_name = name.strip()
                current_value_parts = [value.strip()]
            else:
                current_name = None
                current_value_parts = []
    if current_name is not None:
        blocks.append((current_name, " ".join(current_value_parts)))
    return blocks


def _split_headers_and_body(raw: str):
    parts = raw.split("\n\n", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return raw, ""


class EncodedAnalyzer:
    """Extract and decode encoded blobs from a raw email."""

    def analyze(self, raw_bytes: bytes, msg=None, html: str = "", text: str = "") -> dict:
        try:
            raw_str = raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            raw_str = ""

        items = []

        # 1) MIME parts
        if msg is not None:
            items.extend(self._mime_parts(msg))

        # 2) RFC 2047 encoded-words in headers
        items.extend(self._scan_rfc2047_headers(raw_str))

        # 3) Base64 blobs in bodies (with RFC 2047 stripped)
        headers_str, body_str = _split_headers_and_body(raw_str)
        body_clean = _strip_rfc2047_from_body(body_str)
        items.extend(self._scan_base64(body_clean, source="raw body"))
        if html:
            items.extend(self._scan_base64(_strip_rfc2047_from_body(html), source="HTML body"))
        if text:
            items.extend(self._scan_base64(_strip_rfc2047_from_body(text), source="text body"))

        # 4) QP
        items.extend(self._scan_qp(body_clean, source="raw body"))
        if html:
            items.extend(self._scan_qp(html, source="HTML body"))

        # 5) URL-encoded
        items.extend(self._scan_urlenc(body_clean, source="raw body"))
        if html:
            items.extend(self._scan_urlenc(html, source="HTML body"))

        # 6) Hex
        items.extend(self._scan_hex(body_clean, source="raw body"))
        if html:
            items.extend(self._scan_hex(html, source="HTML body"))

        # 7) HTML entities
        if html:
            items.extend(self._scan_html_entities(html))

        # Dedup
        dedup = {}
        for it in items:
            key = (it["type"], it["raw"][:80])
            if key not in dedup:
                dedup[key] = it
        items = list(dedup.values())[:MAX_ITEMS]

        # ----- Full dump (Option C) -----
        full_dump = self._build_full_dump(raw_str, items, html, text)

        score = 0.0
        base64_count = sum(1 for i in items if i["type"] == "base64")
        qp_count = sum(1 for i in items if i["type"] == "quoted-printable")
        urlenc_count = sum(1 for i in items if i["type"] == "url-encoded")
        hex_count = sum(1 for i in items if i["type"].startswith("hex"))
        if base64_count >= 3:
            score += 15
        if urlenc_count >= 2:
            score += 10
        if qp_count >= 1:
            score += 5
        if hex_count >= 2:
            score += 15
        score = clamp(score)

        logger.info(f"Encoded analyzer found {len(items)} items, score={score}")
        return {
            "items": items,
            "count": len(items),
            "score": score,
            "full_dump": full_dump,
            "summary": {
                "base64": base64_count,
                "quoted_printable": qp_count,
                "url_encoded": urlenc_count,
                "hex": hex_count,
                "html_entities": sum(1 for i in items if i["type"] == "html-entities"),
                "mime_parts": sum(1 for i in items if i["type"] == "mime-part"),
                "rfc2047_headers": sum(1 for i in items if i["type"] == "rfc2047-header"),
            },
        }

    # ------------- full dump -------------

    def _build_full_dump(self, raw: str, items: list, html: str, text: str) -> dict:
        """Build a forensic dump: whole raw .eml + every encoded blob in order."""
        raw_capped = raw[:MAX_DUMP_BYTES]
        if len(raw) > MAX_DUMP_BYTES:
            raw_capped += "\n\n[... raw .eml truncated at 500 KB ...]"

        return {
            "raw_eml": raw_capped,
            "raw_eml_size": len(raw),
            "raw_eml_truncated": len(raw) > MAX_DUMP_BYTES,
            "blob_count": len(items),
            "blobs": [
                {
                    "index": i + 1,
                    "type": it.get("type"),
                    "encoding": it.get("encoding"),
                    "source": it.get("source"),
                    "raw": it.get("raw", ""),
                    "decoded_preview": it.get("decoded_preview", ""),
                    "decoded_full": it.get("decoded_full", ""),
                    "size_raw": it.get("size_raw", 0),
                    "size_decoded": it.get("size_decoded", 0),
                }
                for i, it in enumerate(items)
            ],
        }

    # ------------- scanners -------------

    def _scan_rfc2047_headers(self, raw: str) -> list:
        out = []
        headers_str, _ = _split_headers_and_body(raw)
        blocks = _parse_header_blocks(headers_str)
        for name, value in blocks:
            if "=?" not in value:
                continue
            joined = _join_rfc2047_chunks(value)
            if not joined:
                continue
            if not re.fullmatch(r"[A-Za-z0-9+/=\s]+", joined):
                continue
            raw_bytes_, preview = _safe_b64_decode_binary(joined)
            if raw_bytes_ is None and not preview:
                continue
            is_binary = preview.startswith("0x")
            out.append({
                "type": "rfc2047-header",
                "source": f"Header: {name}",
                "encoding": "base64 (RFC 2047)",
                "raw": _snippet(joined, 300),
                "decoded_preview": _preview(preview),
                "decoded_full": preview,
                "size_raw": len(joined),
                "size_decoded": len(raw_bytes_) if raw_bytes_ is not None else len(preview),
                "binary": is_binary,
            })
        return out

    def _mime_parts(self, msg) -> list:
        out = []
        try:
            for part in msg.walk():
                cte = (part.get("Content-Transfer-Encoding") or "").lower().strip()
                ctype = part.get_content_type()
                if cte not in ("base64", "quoted-printable"):
                    continue
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                try:
                    decoded = payload[:MAX_DECODE_BYTES].decode("utf-8", errors="replace")
                except Exception:
                    decoded = "(binary)"
                encoded_raw = part.get_payload()
                if isinstance(encoded_raw, list):
                    encoded_raw = "".join(str(x) for x in encoded_raw)
                encoded_raw = str(encoded_raw or "")
                encoded_joined = re.sub(r"\s+", "", encoded_raw)
                out.append({
                    "type": "mime-part",
                    "source": f"Content-Type: {ctype}",
                    "encoding": cte,
                    "raw": _snippet(encoded_joined, 300),
                    "decoded_preview": _preview(decoded),
                    "decoded_full": decoded,
                    "size_raw": len(encoded_joined),
                    "size_decoded": len(decoded),
                })
        except Exception as e:
            logger.debug(f"MIME part scan failed: {e}")
        return out

    def _scan_base64(self, s: str, source: str) -> list:
        out = []
        for m in BASE64_RE.finditer(s):
            raw = m.group(1)
            if len(raw) < 80:
                continue
            decoded = _safe_b64_decode(raw)
            if decoded is None:
                continue
            out.append({
                "type": "base64",
                "source": source,
                "encoding": "base64",
                "raw": _snippet(raw),
                "decoded_preview": _preview(decoded),
                "decoded_full": decoded,
                "size_raw": len(raw),
                "size_decoded": len(decoded),
            })
            if len(out) >= MAX_ITEMS:
                break
        return out

    def _scan_qp(self, s: str, source: str) -> list:
        out = []
        for m in QP_RE.finditer(s):
            raw = m.group(0)
            decoded = _decode_qp(raw)
            if not decoded:
                continue
            out.append({
                "type": "quoted-printable",
                "source": source,
                "encoding": "quoted-printable",
                "raw": _snippet(raw),
                "decoded_preview": _preview(decoded),
                "decoded_full": decoded,
                "size_raw": len(raw),
                "size_decoded": len(decoded),
            })
            if len(out) >= MAX_ITEMS:
                break
        return out

    def _scan_urlenc(self, s: str, source: str) -> list:
        out = []
        for m in URLENC_RE.finditer(s):
            raw = m.group(0)
            decoded = _decode_url(raw)
            if not decoded or decoded == raw:
                continue
            out.append({
                "type": "url-encoded",
                "source": source,
                "encoding": "percent",
                "raw": _snippet(raw),
                "decoded_preview": _preview(decoded),
                "decoded_full": decoded,
                "size_raw": len(raw),
                "size_decoded": len(decoded),
            })
            if len(out) >= MAX_ITEMS:
                break
        return out

    def _scan_hex(self, s: str, source: str) -> list:
        out = []
        for m in HEX_ESC_RE.finditer(s):
            raw = m.group(0)
            decoded = _decode_hex_esc(raw)
            if not decoded:
                continue
            out.append({
                "type": "hex-escape",
                "source": source,
                "encoding": r"\xNN",
                "raw": _snippet(raw),
                "decoded_preview": _preview(decoded),
                "decoded_full": decoded,
                "size_raw": len(raw),
                "size_decoded": len(decoded),
            })
            if len(out) >= MAX_ITEMS:
                break
        for m in HEX_0X_RE.finditer(s):
            raw = m.group(0)
            decoded = _decode_hex_0x(raw)
            if not decoded:
                continue
            out.append({
                "type": "hex-0x",
                "source": source,
                "encoding": "0xNN",
                "raw": _snippet(raw),
                "decoded_preview": _preview(decoded),
                "decoded_full": decoded,
                "size_raw": len(raw),
                "size_decoded": len(decoded),
            })
            if len(out) >= MAX_ITEMS:
                break
        return out

    def _scan_html_entities(self, html_text: str) -> list:
        out = []
        for m in HTML_ENT_RE.finditer(html_text):
            raw = m.group(0)
            decoded = _decode_html_entities(raw)
            if not decoded or decoded == raw:
                continue
            out.append({
                "type": "html-entities",
                "source": "HTML body",
                "encoding": "HTML entities",
                "raw": _snippet(raw),
                "decoded_preview": _preview(decoded),
                "decoded_full": decoded,
                "size_raw": len(raw),
                "size_decoded": len(decoded),
            })
            if len(out) >= MAX_ITEMS:
                break
        return out