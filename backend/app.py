import os
import io
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
from encoded_analyzer import EncodedAnalyzer
from scoring_engine import ScoringEngine
from virustotal_api import VirusTotalClient
from abuseipdb_api import AbuseIPDBClient
from geoip_lookup import lookup_ip as geo_lookup_ip
from ml_classifier import MLClassifier, generate_synthetic_dataset
from report_generator import ReportGenerator, build_full_report


app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024
CORS(app)


vt_client = VirusTotalClient()
abuse_client = AbuseIPDBClient()
header_analyzer = HeaderAnalyzer()
url_analyzer = URLAnalyzer()
content_analyzer = ContentAnalyzer()
attachment_analyzer = AttachmentAnalyzer(virustotal_client=vt_client)
encoded_analyzer = EncodedAnalyzer()
scoring_engine = ScoringEngine()
ml_classifier = MLClassifier()
report_generator = ReportGenerator()


def bootstrap():
    init_database()
    try:
        load_brand_domains(load_brands())
    except Exception as e:
        logger.warning(f"Brand seed skipped: {e}")


# ---------------- Core pipeline ----------------

def analyze_email_bytes(raw_bytes: bytes, filename: str = "email.eml") -> dict:
    msg = parse_email_bytes(raw_bytes)

    header_res = header_analyzer.analyze(msg)

    text_body = _get_all_text(msg)
    html_body = _get_all_html(msg)
    full_text = text_body + "\n" + html_body

    url_text_res = url_analyzer.analyze_text(full_text)
    url_html_res = _analyze_html_urls(msg)
    url_res = _merge_url_results(url_text_res, url_html_res)

    content_res = content_analyzer.analyze(msg)
    attachment_res = attachment_analyzer.analyze(msg)
    encoded_res = encoded_analyzer.analyze(
        raw_bytes, msg=msg, html=html_body, text=text_body
    )

    # --- Merge URLs found inside attachments into URL analysis ---
    attachment_urls = []
    for att in attachment_res.get("attachments", []):
        for u in att.get("embedded_urls", []) or []:
            attachment_urls.append(u)
    if attachment_urls:
        extra_url_res = url_analyzer.analyze_urls(attachment_urls)
        url_res = _merge_url_results(url_res, extra_url_res)

    ml_score = ml_classifier.predict(header_res, url_res, content_res, attachment_res)

    final = scoring_engine.compute(
        header_res, url_res, content_res, attachment_res, ml_score
    )

    if encoded_res.get("score", 0) > 0:
        final["final_score"] = clamp(final.get("final_score", 0) + encoded_res["score"] * 0.2)
        final["verdict"] = score_to_verdict(final["final_score"])
        summary = encoded_res.get("summary", {})
        final["triggered_features"].append({
            "module": "encoded",
            "detail": f"{encoded_res['count']} encoded blob(s) "
                      f"(base64={summary.get('base64',0)}, "
                      f"QP={summary.get('quoted_printable',0)}, "
                      f"URL={summary.get('url_encoded',0)}, "
                      f"hex={summary.get('hex',0)})"
        })

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

        "hops": header_res.get("hops", []),
        "full_headers": header_res.get("full_headers", []),
        "auth_summary": header_res.get("auth_summary", {}),

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
        "encoded_score": encoded_res.get("score", 0),
        "ml_score": ml_score,

        "final_score": final.get("final_score", 0),
        "verdict": final.get("verdict", "Unknown"),
        "component_scores": final.get("component_scores", {}),
        "triggered_features": final.get("triggered_features", []),
        "explanation": final.get("explanation", ""),

        "urls_found": url_res.get("urls", []),
        "ips_found": url_res.get("ips", []),
        "attachments": attachment_res.get("attachments", []),
        "encoded_found": encoded_res.get("items", []),
        "encoded_summary": encoded_res.get("summary", {}),
        "encoded_full_dump": encoded_res.get("full_dump", {}),
        "matched_keywords": content_res.get("matched_keywords", {}),
        "raw_headers": _stringify_headers(msg),
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


# ---------------- Page routes ----------------

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


# ---------------- Analysis API ----------------

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "app": APP_NAME,
        "version": APP_VERSION,
        "ml_ready": ml_classifier.is_ready(),
        "virustotal_ready": vt_client.is_ready(),
        "abuseipdb_ready": abuse_client.is_ready(),
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
    return jsonify({"count": len(rows), "items": [_row_to_dict(r) for r in rows]})


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


@app.route("/api/threat-map", methods=["GET"])
def api_threat_map():
    """One marker per analyzed email — origin IP only, deduplicated by analysis ID."""
    rows = get_all_analyses(limit=500)
    points = []
    country_counts = {}
    seen_emails = set()

    for row in rows:
        a = _row_to_dict(row)
        verdict = a.get("verdict")
        if verdict not in ("Suspicious", "Phishing"):
            continue

        aid = a.get("id")
        if aid in seen_emails:
            continue
        seen_emails.add(aid)

        # Pick the TRUE origin: last public IPv4 in hops (hops are newest→oldest)
        origin_ip = None
        for h in reversed(a.get("hops", []) or []):
            ip = h.get("from_ip")
            if not ip:
                continue
            if ip.startswith(("10.", "192.168.", "127.", "172.", "169.254.")):
                continue
            if ":" in ip:
                continue  # skip IPv6
            origin_ip = ip
            break

        # Fallback: first public IP from ips_found
        if not origin_ip:
            for entry in a.get("ips_found", []) or []:
                ip = entry.get("ip")
                if not ip or ":" in ip:
                    continue
                if entry.get("public"):
                    origin_ip = ip
                    break

        if not origin_ip:
            continue

        geo = geo_lookup_ip(origin_ip)
        if geo.get("skip") or geo.get("error"):
            continue
        if geo.get("lat") is None or geo.get("lon") is None:
            continue

        cc = geo.get("country_code") or "??"
        country_counts[cc] = country_counts.get(cc, 0) + 1

        points.append({
            "ip": origin_ip,
            "lat": geo["lat"],
            "lon": geo["lon"],
            "country": geo.get("country"),
            "country_code": cc,
            "city": geo.get("city"),
            "isp": geo.get("isp"),
            "verdict": verdict,
            "sender": a.get("sender"),
            "subject": a.get("subject"),
            "analysis_id": aid,
        })

    top_countries = sorted(
        [{"cc": k, "count": v} for k, v in country_counts.items()],
        key=lambda x: -x["count"],
    )[:8]

    return jsonify({
        "points": points,
        "country_counts": top_countries,
        "total": len(points),
    })


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


# ---------------- VirusTotal API ----------------

@app.route("/api/vt/ip", methods=["GET"])
def api_vt_ip():
    ip = request.args.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "missing ?ip="}), 400
    if not vt_client.is_ready():
        return jsonify({"error": "VIRUSTOTAL_API_KEY not configured"}), 503
    return jsonify(vt_client.lookup_ip(ip))


@app.route("/api/vt/url", methods=["GET"])
def api_vt_url():
    url = request.args.get("url", "").strip()
    if not url:
        return jsonify({"error": "missing ?url="}), 400
    if not vt_client.is_ready():
        return jsonify({"error": "VIRUSTOTAL_API_KEY not configured"}), 503
    return jsonify(vt_client.lookup_url_full(url))


@app.route("/api/vt/domain", methods=["GET"])
def api_vt_domain():
    domain = request.args.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "missing ?domain="}), 400
    if not vt_client.is_ready():
        return jsonify({"error": "VIRUSTOTAL_API_KEY not configured"}), 503
    return jsonify(vt_client.lookup_domain_full(domain))


@app.route("/api/vt/hash", methods=["GET"])
def api_vt_hash():
    h = request.args.get("hash", "").strip()
    if not h:
        return jsonify({"error": "missing ?hash="}), 400
    if not vt_client.is_ready():
        return jsonify({"error": "VIRUSTOTAL_API_KEY not configured"}), 503
    return jsonify(vt_client.lookup_hash(h))


# ---------------- AbuseIPDB API ----------------

@app.route("/api/abuse/ip", methods=["GET"])
def api_abuse_ip():
    ip = request.args.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "missing ?ip="}), 400
    if not abuse_client.is_ready():
        return jsonify({"error": "ABUSEIPDB_API_KEY not configured"}), 503
    days = int(request.args.get("days", 90))
    return jsonify(abuse_client.check_ip(ip, max_age_days=days))


# ---------------- Enrichment ----------------

@app.route("/api/enrich/<int:analysis_id>", methods=["GET"])
def api_enrich(analysis_id):
    row = get_analysis(analysis_id)
    if not row:
        return jsonify({"error": "not found"}), 404

    a = _row_to_dict(row)
    urls = a.get("urls_found", []) or []
    ips = a.get("ips_found", []) or []

    vt_urls = []
    if vt_client.is_ready():
        seen = set()
        for u in urls[:10]:
            link = u.get("url")
            if not link or link in seen:
                continue
            seen.add(link)
            try:
                vt_urls.append(vt_client.lookup_url_full(link))
            except Exception as e:
                vt_urls.append({"url": link, "error": str(e)})

    vt_ips = []
    abuse_ips = []
    seen_ips = set()
    for entry in ips[:10]:
        ip = entry.get("ip")
        if not ip or ip in seen_ips:
            continue
        seen_ips.add(ip)
        if vt_client.is_ready():
            try:
                vt_ips.append(vt_client.lookup_ip(ip))
            except Exception as e:
                vt_ips.append({"ip": ip, "error": str(e)})
        if abuse_client.is_ready():
            try:
                abuse_ips.append(abuse_client.check_ip(ip))
            except Exception as e:
                abuse_ips.append({"ip": ip, "error": str(e)})

    return jsonify({
        "analysis_id": analysis_id,
        "virustotal": {"urls": vt_urls, "ips": vt_ips},
        "abuseipdb": {"ips": abuse_ips},
        "keys": {
            "virustotal": vt_client.is_ready(),
            "abuseipdb": abuse_client.is_ready(),
        },
    })


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

        "hops": getattr(row, "hops", None) or [],
        "full_headers": getattr(row, "full_headers", None) or [],
        "auth_summary": getattr(row, "auth_summary", None) or {},

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
        "encoded_score": getattr(row, "encoded_score", 0.0),
        "ml_score": row.ml_score,
        "final_score": row.final_score,
        "verdict": row.verdict,

        "component_scores": {
            "header": row.header_score,
            "url": row.url_score,
            "content": row.content_score,
            "attachment": row.attachment_score,
            "encoded": getattr(row, "encoded_score", 0.0),
            "ml": row.ml_score,
        },
        "urls_found": row.urls_found or [],
        "ips_found": getattr(row, "ips_found", None) or [],
        "attachments": row.attachments or [],
        "encoded_found": getattr(row, "encoded_found", None) or [],
        "encoded_full_dump": getattr(row, "encoded_full_dump", None) or {},
        "triggered_features": row.triggered_features or [],
        "raw_headers": row.raw_headers,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


if __name__ == "__main__":
    bootstrap()
    logger.info(f"Starting {APP_NAME} v{APP_VERSION} on {HOST}:{PORT}")
    app.run(host=HOST, port=PORT, debug=DEBUG)