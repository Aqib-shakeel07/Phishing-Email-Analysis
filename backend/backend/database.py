from models import SessionLocal, EmailAnalysis, LookupCache, BrandDomain, init_db
from datetime import datetime
import json


def init_database():
    """Create all tables."""
    init_db()


# ---------------- EmailAnalysis CRUD ----------------

def _to_json_safe(value):
    """Ensure value is JSON-serializable."""
    if value is None:
        return None
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return str(value)


def save_analysis(data: dict) -> int:
    """Insert a new email analysis record. Returns record ID."""
    db = SessionLocal()
    try:
        record = EmailAnalysis(
            filename=data.get("filename"),

            # From / To
            sender=data.get("sender"),
            sender_name=data.get("sender_name"),
            sender_domain=data.get("sender_domain"),
            to_recipients=_to_json_safe(data.get("to")),
            cc_recipients=_to_json_safe(data.get("cc")),
            reply_to=data.get("reply_to"),
            reply_to_domain=data.get("reply_to_domain"),
            return_path=data.get("return_path"),
            return_path_domain=data.get("return_path_domain"),
            subject=data.get("subject"),
            date_header=data.get("date"),
            message_id=data.get("message_id"),
            received_chain=_to_json_safe(data.get("received_chain")),

            # Auth
            spf_present=data.get("spf_present"),
            spf_pass=data.get("spf_pass"),
            dkim_present=data.get("dkim_present"),
            dkim_pass=data.get("dkim_pass"),
            dmarc_present=data.get("dmarc_present"),
            dmarc_pass=data.get("dmarc_pass"),
            auth_headers_raw=data.get("auth_headers_raw"),

            # Scores
            header_score=data.get("header_score", 0.0),
            url_score=data.get("url_score", 0.0),
            content_score=data.get("content_score", 0.0),
            attachment_score=data.get("attachment_score", 0.0),
            ml_score=data.get("ml_score", 0.0),
            final_score=data.get("final_score", 0.0),
            verdict=data.get("verdict", "Unknown"),

            # Contents
            urls_found=_to_json_safe(data.get("urls_found")),
            ips_found=_to_json_safe(data.get("ips_found")),
            attachments=_to_json_safe(data.get("attachments")),
            triggered_features=_to_json_safe(data.get("triggered_features")),
            raw_headers=data.get("raw_headers"),
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record.id
    finally:
        db.close()


def get_analysis(analysis_id: int):
    db = SessionLocal()
    try:
        return db.query(EmailAnalysis).filter(EmailAnalysis.id == analysis_id).first()
    finally:
        db.close()


def get_all_analyses(limit: int = 100, offset: int = 0):
    db = SessionLocal()
    try:
        return (
            db.query(EmailAnalysis)
            .order_by(EmailAnalysis.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
    finally:
        db.close()


def get_analyses_by_verdict(verdict: str):
    db = SessionLocal()
    try:
        return db.query(EmailAnalysis).filter(EmailAnalysis.verdict == verdict).all()
    finally:
        db.close()


def delete_analysis(analysis_id: int) -> bool:
    db = SessionLocal()
    try:
        record = db.query(EmailAnalysis).filter(EmailAnalysis.id == analysis_id).first()
        if record:
            db.delete(record)
            db.commit()
            return True
        return False
    finally:
        db.close()


def get_stats():
    """Summary stats for dashboard."""
    db = SessionLocal()
    try:
        total = db.query(EmailAnalysis).count()
        safe = db.query(EmailAnalysis).filter(EmailAnalysis.verdict == "Safe").count()
        suspicious = db.query(EmailAnalysis).filter(EmailAnalysis.verdict == "Suspicious").count()
        phishing = db.query(EmailAnalysis).filter(EmailAnalysis.verdict == "Phishing").count()
        return {
            "total": total,
            "safe": safe,
            "suspicious": suspicious,
            "phishing": phishing,
        }
    finally:
        db.close()


# ---------------- Cache ----------------

def cache_get(key: str):
    db = SessionLocal()
    try:
        row = db.query(LookupCache).filter(LookupCache.key == key).first()
        return row.value if row else None
    finally:
        db.close()


def cache_set(key: str, value):
    db = SessionLocal()
    try:
        row = db.query(LookupCache).filter(LookupCache.key == key).first()
        if row:
            row.value = value
        else:
            row = LookupCache(key=key, value=value)
            db.add(row)
        db.commit()
    finally:
        db.close()


# ---------------- Brand domains ----------------

def load_brand_domains(brands: list):
    """Seed brand domains if not present."""
    db = SessionLocal()
    try:
        existing = {b.domain for b in db.query(BrandDomain).all()}
        for brand in brands:
            for domain in brand["domains"]:
                if domain not in existing:
                    db.add(BrandDomain(brand=brand["name"], domain=domain))
        db.commit()
    finally:
        db.close()


def get_brand_by_domain(domain: str):
    db = SessionLocal()
    try:
        return db.query(BrandDomain).filter(BrandDomain.domain == domain).first()
    finally:
        db.close()