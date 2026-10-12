import os
import io
import base64
import quopri
import binascii
from email import policy
from email.header import decode_header, make_header
from flask import Flask, request, jsonify, send_file, render_template
from flask_cors import CORS
from werkzeug.utils import secure_filename

from config import (
    APP_NAME, APP_VERSION, DEBUG, HOST, PORT,
    UPLOAD_DIR, ALLOWED_EXTENSIONS
)
from logger import logger
from database import (
    init_database, save_analysis, get_analysis,
    get_all_analyses, get_stats, delete_analysis,
    load_brand_domains
)
from helpers import load_brands, score_to_verdict, clamp

from header_analyzer import HeaderAnalyzer, parse_email_bytes
from url_analyzer import URLAnalyzer
from content_analyzer import ContentAnalyzer
from attachment_analyzer import AttachmentAnalyzer
from scoring_engine import ScoringEngine
from virustotal_api import VirusTotalClient
from ml_classifier import MLClassifier, generate_synthetic_dataset
from report_generator import ReportGenerator, build_full_report


# ---------------- App setup ----------------

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024
CORS(app)

# ---------------- Components ----------------

vt_client = VirusTotalClient()
header_analyzer = HeaderAnalyzer()
url_analyzer = URLAnalyzer()
content_analyzer = ContentAnalyzer()
attachment_analyzer = AttachmentAnalyzer(virustotal_client=vt_client)
scoring_engine = ScoringEngine()
ml_classifier = MLClassifier()
report_generator = ReportGenerator()


# ---------------- Bootstrap ----------------

def bootstrap():
    init_database()
    try:
        load_brand_domains(load_brands())
    except Exception as e:
        logger.warning(f"Brand seed skipped: {e}")


# ---------------- MIME-aware extraction ----------------

MAGIC_SIGS = [
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"%PDF-", "PDF document"),
    (b"PK\x03\x04", "ZIP / Office document"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"\x1f\x8b", "GZIP archive"),
    (b"MZ", "Windows executable"),
    (b"\x7fELF", "Linux executable"),
    (b"<svg", "SVG image"),
    (b"<?xml", "XML document"),
    (b"RIFF", "RIFF/WEBP/AVI"),
]


def _decode_header_value(raw_value):
    """Decode RFC 2047 encoded header (=?UTF-8?B?...?=) into plain text."""
    if not raw_value:
        return ""
    try:
        return str(make_header(decode_header(raw_value)))
    except Exception:
        return str(raw_value)


def _fingerprint(data: bytes):
    """Return a short string describing the decoded payload."""
    if not data:
        return None
    head = data[:16]
    for sig, label in MAGIC_SIGS:
        if head.startswith(sig):
            return label
    if b"<svg" in data[:512].lower():
        return "SVG image"
    try:
        sample = data[:512].decode("utf-8", errors="strict")
        if all((ord(c) >= 32 or c in "\r\n\t") for c in sample):
            return "text"
    except Exception:
        pass
    return "binary"


def _part_charset(part):
    try:
        return part.get_content_charset() or "utf-8"
    except Exception:
        return "utf-8"


def _decode_payload(part):
    """
    Decode a MIME part's payload using its Content-Transfer-Encoding.
    Returns (decoded_bytes, method).
    """
    cte = (part.get("Content-Transfer-Encoding") or "").strip().lower()

    try:
        raw = part.get_payload(decode=False)
    except Exception:
        raw = None

    if raw is None:
        try:
            data = part.get_payload(decode=True)
            return (data or b"", "raw")
        except Exception as e:
            return (b"", f"error:{e}")

    if isinstance(raw, list):
        return (b"", "multipart")

    if not isinstance(raw, str):
        raw = str(raw)

    if cte in ("base64",):
        compact = "".join(raw.split())
        try:
            return (base64.b64decode(compact, validate=False), "base64")
        except (binascii.Error, ValueError) as e:
            return (b"", f"error:base64:{e}")

    if cte in ("quoted-printable", "quoted_printable", "quotedprintable"):
        try:
            return (quopri.decodestring(raw.encode("utf-8", errors="ignore")), "qp")
        except Exception as e:
            return (b"", f"error:qp:{e}")

    if cte in ("7bit", "8bit", "binary", ""):
        charset = _part_charset(part)
        try:
            return (raw.encode(charset, errors="replace"), cte or "7bit")
        except Exception:
            return (raw.encode("utf-8", errors="replace"), cte or "7bit")

    try:
        compact = "".join(raw.split())
        return (base64.b64decode(compact, validate=False), "base64(fallback)")
    except Exception:
        pass
    try:
        return (quopri.decodestring(raw.encode("utf-8", errors="ignore")), "qp(fallback)")
    except Exception as e:
        return (b"", f"error:unknown:{e}")


def extract_encoded_parts(msg, max_size=2_000_000):
    """
    Walk every MIME part, decode using the declared CTE + charset,
    and return a list of decoded parts.
    """
    parts_out = []
    idx = 0

    for part in msg.walk():
        if part.is_multipart():
            continue

        ctype = part.get_content_type() or "application/octet-stream"
        cte = (part.get("Content-Transfer-Encoding") or "").strip().lower()
        charset = _part_charset(part)
        filename = part.get_filename()
        if filename:
            filename = _decode_header_value(filename)
        disp = str(part.get("Content-Disposition") or "")

        if ctype in ("text/plain", "text/html") and cte not in ("base64", "quoted-printable"):
            idx += 1
            continue

        decoded, method = _decode_payload(part)

        if not decoded:
            idx += 1
            continue

        if len(decoded) > max_size:
            original_len = len(decoded)
            decoded_trunc = decoded[:max_size]
        else:
            original_len = len(decoded)
            decoded_trunc = decoded

        magic = _fingerprint(decoded_trunc)
        is_binary = magic not in ("text", None) and magic is not None

        if not is_binary:
            try:
                text = decoded_trunc.decode(charset, errors="replace")
            except Exception:
                text = decoded_trunc.decode("utf-8", errors="replace")
        else:
            text = base64.b64encode(decoded_trunc).decode("ascii")

        parts_out.append({
            "part_index": idx,
            "content_type": ctype,
            "transfer_encoding": cte or "7bit",
            "charset": charset,
            "filename": filename,
            "content_disposition": disp.strip() or None,
            "decoded_bytes_len": original_len,
            "decoded_text": text,
            "is_binary": is_binary,
            "magic": magic,
            "method": method,
        })
        idx += 1

    return parts_out


# ---------------- Core pipeline ----------------

def analyze_email_bytes(raw_bytes: bytes, filename: str = "email.eml") -> dict:
    msg = parse_email_bytes(raw_bytes)

    header_res = header_analyzer.analyze(msg)

    body_text = _get_all_text(msg)
    body_html = _get_all_html(msg)
    full_text = body_text + "\n" + body_html

    url_text_res = url_analyzer.analyze_text(full_text)
    url_html_res = _analyze_html_urls(msg)
    url_res = _merge_url_results(url_text_res, url_html_res)

    content_res = content_analyzer.analyze(msg)
    attachment_res = attachment_analyzer.analyze(msg)

    ml_score = ml_classifier.predict(header_res, url_res, content_res, attachment_res)

    final = scoring_engine.compute(
        header_res, url_res, content_res, attachment_res, ml_score
    )

    try:
        encoded_parts = extract_encoded_parts(msg)
    except Exception as e:
        logger.warning(f"extract_encoded_parts failed: {e}")
        encoded_parts = []

    try:
        raw_email_text = raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        raw_email_text = ""

    analysis = {
        "filename": filename,

        "sender": header_res.get("sender"),
        "sender_name": header_res.get("sender_name"),
        "sender_domain": header_res.get("sender_domain"),
        "to": header_res.get("to"),
        "cc": header_res.get("cc"),
        "reply_to": header_res.get("reply_to"),
        "reply_to_domain": header_res.get("reply_to_domain"),
        "return_path": header_res.get("return_path"),
        "return_path_domain": header_res.get("return_path_domain"),
        "subject": header_res.get("subject"),
        "date": header_res.get("date"),
        "message_id": header_res.get("message_id"),
        "received_chain": header_res.get("received_chain"),

        "spf_present": header_res.get("spf_present"),
        "spf_pass": header_res.get("spf_pass"),
        "dkim_present": header_res.get("dkim_present"),
        "dkim_pass": header_res.get("dkim_pass"),
        "dmarc_present": header_res.get("dmarc_present"),
        "dmarc_pass": header_res.get("dmarc_pass"),
        "auth_headers_raw": header_res.get("auth_headers_raw"),

        "header_score": header_res.get("score", 0),
        "url_score": url_res.get("score", 0),
        "content_score": content_res.get("score", 0),
        "attachment_score": attachment_res.get("score", 0),
        "ml_score": ml_score,

        "final_score": final.get("final_score", 0),
        "verdict": final.get("verdict", "Unknown"),
        "component_scores": final.get("component_scores", {}),
        "triggered_features": final.get("triggered_features", []),
        "explanation": final.get("explanation", ""),

        "urls_found": url_res.get("urls", []),
        "ips_found": url_res.get("ips", []),
        "attachments": attachment_res.get("attachments", []),
        "matched_keywords": content_res.get("matched_keywords", {}),
        "raw_headers": _stringify_headers(msg),

        "body_text": body_text,
        "body_html": body_html,

        "raw_email": raw_email_text,

        "encoded_parts": encoded_parts,
    }
    return analysis


def _get_all_text(msg) -> str:
    parts = []
    if msg.is_multipart():
        for p in msg.walk():
            if p.get_content_type() == "text/plain":
                try:
                    parts.append(p.get_content())
                except Exception:
                    pass
    else:
        try:
            parts.append(msg.get_content())
        except Exception:
            pass
    return "\n".join(str(x) for x in parts if x)


def _get_all_html(msg) -> str:
    parts = []
    if msg.is_multipart():
        for p in msg.walk():
            if p.get_content_type() == "text/html":
                try:
                    parts.append(p.get_content())
                except Exception:
                    pass
    else:
        if msg.get_content_type() == "text/html":
            try:
                parts.append(msg.get_content())
            except Exception:
                pass
    return "\n".join(str(x) for x in parts if x)


def _analyze_html_urls(msg) -> dict:
    html = _get_all_html(msg)
    if not html:
        return {"urls": [], "ips": [], "flags": [], "score": 0.0, "link_mismatches": []}
    return url_analyzer.analyze_html(html)


def _merge_url_results(a: dict, b: dict) -> dict:
    urls = []
    seen = set()
    for u in (a.get("urls", []) + b.get("urls", [])):
        key = u.get("url")
        if key and key not in seen:
            seen.add(key)
            urls.append(u)
    flags = sorted(set((a.get("flags", []) or []) + (b.get("flags", []) or [])))
    score = clamp(max(a.get("score", 0), b.get("score", 0)) + 0.1 * sum(
        u.get("score", 0) for u in urls
    ) / max(len(urls), 1))

    ips = []
    seen_ips = set()
    for ip in (a.get("ips", []) or []) + (b.get("ips", []) or []):
        if ip.get("ip") and ip["ip"] not in seen_ips:
            seen_ips.add(ip["ip"])
            ips.append(ip)

    return {
        "urls": urls,
        "ips": ips,
        "flags": flags,
        "score": clamp(score),
        "link_mismatches": b.get("link_mismatches", []) + a.get("link_mismatches", []),
    }


def _stringify_headers(msg) -> str:
    try:
        return "\n".join(f"{k}: {v}" for k, v in msg.items())
    except Exception:
        return ""


# ---------------- Routes ----------------

@app.route("/", methods=["GET"])
def index():
    try:
        return render_template("index.html")
    except Exception:
        return jsonify({
            "app": APP_NAME,
            "version": APP_VERSION,
            "message": "Phishing Email Analyzer API is running",
        })


@app.route("/dashboard", methods=["GET"])
def dashboard():
    return render_template("dashboard.html")


@app.route("/virustotal", methods=["GET"])
def virustotal_page():
    return render_template("virustotal.html")


@app.route("/abuseipdb", methods=["GET"])
def abuseipdb_page():
    return render_template("abuseipdb.html")


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "app": APP_NAME,
        "version": APP_VERSION,
        "ml_ready": ml_classifier.is_ready(),
    })


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    try:
        if "file" in request.files:
            f = request.files["file"]
            raw = f.read()
            filename = secure_filename(f.filename or "upload.eml")
        elif request.is_json and request.json.get("raw"):
            raw = request.json["raw"].encode("utf-8", errors="ignore")
            filename = "raw.eml"
        elif request.form.get("raw"):
            raw = request.form["raw"].encode("utf-8", errors="ignore")
            filename = "raw.eml"
        else:
            return jsonify({"error": "no email provided"}), 400

        if not raw:
            return jsonify({"error": "empty email"}), 400

        analysis = analyze_email_bytes(raw, filename)
        analysis_id = save_analysis(analysis)
        analysis["id"] = analysis_id

        return jsonify({"success": True, "analysis": analysis})
    except Exception as e:
        logger.exception("analyze failed")
        return jsonify({"error": str(e)}), 500


@app.route("/api/analyses", methods=["GET"])
def api_list():
    limit = int(request.args.get("limit", 100))
    offset = int(request.args.get("offset", 0))
    rows = get_all_analyses(limit=limit, offset=offset)
    return jsonify({
        "count": len(rows),
        "items": [_row_to_dict(r) for r in rows],
    })


@app.route("/api/analyses/<int:analysis_id>", methods=["GET"])
def api_get(analysis_id):
    row = get_analysis(analysis_id)
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(_row_to_dict(row))


@app.route("/api/analyses/<int:analysis_id>", methods=["DELETE"])
def api_delete(analysis_id):
    ok = delete_analysis(analysis_id)
    return jsonify({"success": ok})


@app.route("/api/stats", methods=["GET"])
def api_stats():
    return jsonify(get_stats())


@app.route("/api/analyses/<int:analysis_id>/report", methods=["GET"])
def api_report(analysis_id):
    row = get_analysis(analysis_id)
    if not row:
        return jsonify({"error": "not found"}), 404

    fmt = request.args.get("format", "json").lower()
    analysis = _row_to_dict(row)

    if fmt == "pdf":
        path = report_generator.to_pdf(analysis, filename=f"report_{analysis_id}.pdf")
        return send_file(path, as_attachment=True,
                         download_name=os.path.basename(path))
    path = report_generator.to_json(analysis, filename=f"report_{analysis_id}.json")
    return send_file(path, as_attachment=True,
                     download_name=os.path.basename(path))


@app.route("/api/train", methods=["POST"])
def api_train():
    try:
        dataset = request.json.get("dataset") if request.is_json else None
        if not dataset:
            dataset = generate_synthetic_dataset()
        result = ml_classifier.train(dataset)
        return jsonify({"success": True, **result})
    except Exception as e:
        logger.exception("training failed")
        return jsonify({"error": str(e)}), 500


# ---------------- Helpers ----------------

def _row_to_dict(row) -> dict:
    return {
        "id": row.id,
        "filename": row.filename,

        "sender": row.sender,
        "sender_name": getattr(row, "sender_name", None),
        "sender_domain": row.sender_domain,
        "to": getattr(row, "to_recipients", None) or [],
        "cc": getattr(row, "cc_recipients", None) or [],
        "reply_to": row.reply_to,
        "reply_to_domain": getattr(row, "reply_to_domain", None),
        "return_path": row.return_path,
        "return_path_domain": getattr(row, "return_path_domain", None),
        "subject": row.subject,
        "date": getattr(row, "date_header", None),
        "message_id": getattr(row, "message_id", None),
        "received_chain": row.received_chain or [],

        "spf_present": getattr(row, "spf_present", None),
        "spf_pass": row.spf_pass,
        "dkim_present": getattr(row, "dkim_present", None),
        "dkim_pass": row.dkim_pass,
        "dmarc_present": getattr(row, "dmarc_present", None),
        "dmarc_pass": row.dmarc_pass,
        "auth_headers_raw": getattr(row, "auth_headers_raw", None),

        "header_score": row.header_score,
        "url_score": row.url_score,
        "content_score": row.content_score,
        "attachment_score": row.attachment_score,
        "ml_score": row.ml_score,
        "final_score": row.final_score,
        "verdict": row.verdict,

        "component_scores": {
            "header": row.header_score,
            "url": row.url_score,
            "content": row.content_score,
            "attachment": row.attachment_score,
            "ml": row.ml_score,
        },
        "urls_found": row.urls_found or [],
        "ips_found": getattr(row, "ips_found", None) or [],
        "attachments": row.attachments or [],
        "triggered_features": row.triggered_features or [],
        "raw_headers": row.raw_headers,
        "body_text": getattr(row, "body_text", None) or "",
        "body_html": getattr(row, "body_html", None) or "",
        "raw_email": getattr(row, "raw_email", None) or "",
        "encoded_parts": getattr(row, "encoded_parts", None) or [],
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


# ---------------- Entrypoint ----------------

if __name__ == "__main__":
    bootstrap()
    logger.info(f"Starting {APP_NAME} v{APP_VERSION} on {HOST}:{PORT}")
    app.run(host=HOST, port=PORT, debug=DEBUG)