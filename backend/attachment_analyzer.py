import os
import re
import email
import zipfile
import hashlib
from helpers import sha256_file, clamp
from validators import has_double_extension
from logger import logger


DANGEROUS_EXTS = {
    "exe", "scr", "bat", "cmd", "com", "pif", "hta",
    "js", "jse", "vbs", "vbe", "wsf", "wsh", "ps1",
    "msi", "jar", "reg", "lnk", "cpl", "dll", "sys",
    "iso", "img", "vhd", "apk", "app", "dmg",
    "svg", "svgz",               # SVG can execute JS via onload
}

MACRO_EXTS = {"docm", "xlsm", "pptm", "dotm", "xltm", "potm"}

ARCHIVE_EXTS = {"zip", "rar", "7z", "tar", "gz", "bz2", "xz"}

IMAGE_EXTS = {"png", "jpg", "jpeg", "gif", "bmp", "webp", "tiff"}


class AttachmentAnalyzer:
    def __init__(self, virustotal_client=None):
        self.vt = virustotal_client

    def analyze(self, msg: email.message.Message) -> dict:
        result = {
            "attachments": [],
            "flags": [],
            "score": 0.0,
        }

        attachments = self._extract_attachments(msg)
        if not attachments:
            return result

        score = 0.0
        for att in attachments:
            info = self._analyze_single(att)
            result["attachments"].append(info)
            result["flags"].extend(info["flags"])
            score += info["score"]

        result["score"] = clamp(score / max(len(attachments), 1) + score * 0.1)
        result["flags"] = sorted(set(result["flags"]))
        logger.info(f"Attachment analysis score: {result['score']}")
        return result

    def _extract_attachments(self, msg: email.message.Message) -> list:
        out = []
        for part in msg.walk():
            disp = str(part.get("Content-Disposition") or "").lower()
            filename = part.get_filename()
            if not filename and "attachment" not in disp:
                continue
            if not filename:
                continue
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""
            out.append({
                "filename": filename,
                "content_type": part.get_content_type(),
                "size": len(payload),
                "bytes": payload,
            })
        return out

    def _analyze_single(self, att: dict) -> dict:
        info = {
            "filename": att["filename"],
            "content_type": att["content_type"],
            "size": att["size"],
            "extension": "",
            "sha256": None,
            "flags": [],
            "score": 0.0,
            "virustotal": None,
            "embedded_urls": [],
        }
        score = 0.0
        filename = att["filename"]
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        info["extension"] = ext

        if att["bytes"]:
            try:
                info["sha256"] = hashlib.sha256(att["bytes"]).hexdigest()
            except Exception:
                pass

        # Double extension
        if has_double_extension(filename):
            score += 35
            info["flags"].append(f"Double extension: {filename}")

        # Dangerous extension
        if ext in DANGEROUS_EXTS:
            score += 40
            info["flags"].append(f"Dangerous file type: .{ext}")

        # Macro-enabled Office
        if ext in MACRO_EXTS:
            score += 30
            info["flags"].append(f"Macro-enabled Office file: .{ext}")

        # Archive
        if ext in ARCHIVE_EXTS:
            score += 10
            info["flags"].append(f"Archive attachment: .{ext}")
            nested = self._inspect_archive(att["bytes"])
            if nested:
                score += 25
                info["flags"].append(
                    f"Archive contains dangerous file(s): {', '.join(nested)}"
                )
                info["nested_dangerous"] = nested

        # Extension vs content-type mismatch
        if self._mismatch(ext, att["content_type"]):
            score += 15
            info["flags"].append(
                f"Extension/content-type mismatch: .{ext} vs {att['content_type']}"
            )

        # ============================================================
        # SVG payload detection (XSS / redirect / embedded URLs)
        # ============================================================
        if ext in ("svg", "svgz"):
            try:
                text = att["bytes"].decode("utf-8", errors="replace")
            except Exception:
                text = ""

            if re.search(r"\bonload\s*=", text, re.I):
                score += 45
                info["flags"].append(
                    "SVG contains 'onload' event handler — XSS/redirect payload"
                )

            if re.search(r"window\.location|location\.href|location\.replace|<script", text, re.I):
                score += 35
                info["flags"].append("SVG executes JavaScript redirect")

            # <foreignObject> is often used for HTML injection
            if re.search(r"<foreignObject", text, re.I):
                score += 20
                info["flags"].append("SVG uses <foreignObject> (HTML injection vector)")

            # Extract any URLs from the SVG
            urls_in_svg = re.findall(r"https?://[^\s'\"<>)\]]+", text)
            if urls_in_svg:
                score += 20
                info["flags"].append(
                    f"SVG embeds URL(s): {', '.join(urls_in_svg[:3])}"
                )
                info["embedded_urls"] = urls_in_svg

            # base64 pre-filled credential payload after $ or ?u=
            if re.search(r"[\$?](?:u=)?[A-Za-z0-9+/=]{20,}", text):
                score += 20
                info["flags"].append(
                    "SVG contains base64 payload (pre-filled credential pattern)"
                )

        # ============================================================
        # Large image attachment (QR / OCR phishing)
        # ============================================================
        if ext in IMAGE_EXTS and att["size"] > 500_000:
            score += 15
            info["flags"].append(
                f"Large image attachment ({att['size']:,} bytes) — "
                f"possible QR-code / image-embedded phishing"
            )

        if ext in IMAGE_EXTS and att["size"] > 1_000_000:
            score += 10
            info["flags"].append(
                f"Very large image ({att['size']:,} bytes) — "
                f"unusual for a legitimate transactional email"
            )

        # Suspicious filename keywords
        if re.search(
            r"(invoice|payment|receipt|statement|order|shipping|resume|cv|scan|purchase|confirm|pymt|pay)",
            filename, re.I
        ):
            score += 5
            info["flags"].append(f"Social-engineering filename: {filename}")

        # Empty attachment
        if att["size"] == 0:
            score += 5
            info["flags"].append(f"Empty attachment: {filename}")

        # VirusTotal lookup
        if self.vt and info["sha256"]:
            try:
                vt_result = self.vt.lookup_hash(info["sha256"])
                info["virustotal"] = vt_result
                positives = (vt_result or {}).get("positives", 0)
                if positives > 0:
                    score += min(40 + positives * 2, 60)
                    info["flags"].append(
                        f"VirusTotal: {positives} engines flagged {filename}"
                    )
            except Exception as e:
                logger.warning(f"VT lookup failed for {filename}: {e}")

        info["score"] = clamp(score)
        return info

    def _inspect_archive(self, data: bytes) -> list:
        dangerous = []
        if not data:
            return dangerous
        try:
            import io
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for name in z.namelist():
                    n_ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
                    if n_ext in DANGEROUS_EXTS or has_double_extension(name):
                        dangerous.append(name)
        except zipfile.BadZipFile:
            pass
        except Exception as e:
            logger.debug(f"Archive inspect error: {e}")
        return dangerous

    def _mismatch(self, ext: str, ctype: str) -> bool:
        if not ext or not ctype:
            return False
        ctype = ctype.lower()
        mapping = {
            "pdf": "application/pdf",
            "doc": "application/msword",
            "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "xls": "application/vnd.ms-excel",
            "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "zip": "application/zip",
            "jpg": "image/jpeg",
            "jpeg": "image/jpeg",
            "png": "image/png",
            "svg": "image/svg+xml",
            "txt": "text/plain",
        }
        expected = mapping.get(ext)
        if expected and expected not in ctype and "octet-stream" not in ctype:
            return True
        if ext in DANGEROUS_EXTS and ("text" in ctype or "image" in ctype):
            return True
        return False


def save_attachment(att: dict, out_dir: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", att["filename"])
    path = os.path.join(out_dir, safe_name)
    with open(path, "wb") as f:
        f.write(att.get("bytes", b""))
    return path