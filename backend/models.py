from datetime import datetime
from sqlalchemy import (
    create_engine, Column, Integer, String, Float,
    Text, DateTime, Boolean, JSON
)
from sqlalchemy.orm import declarative_base, sessionmaker
from config import DATABASE_URL

Base = declarative_base()
engine = create_engine(DATABASE_URL, echo=False, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class EmailAnalysis(Base):
    __tablename__ = "email_analyses"

    id = Column(Integer, primary_key=True, autoincrement=True)
    filename = Column(String(255), nullable=True)

    # From / To
    sender = Column(String(320), nullable=True)
    sender_name = Column(String(320), nullable=True)
    sender_domain = Column(String(255), nullable=True)
    to_recipients = Column(JSON, nullable=True)
    cc_recipients = Column(JSON, nullable=True)
    reply_to = Column(String(320), nullable=True)
    reply_to_domain = Column(String(255), nullable=True)
    return_path = Column(String(320), nullable=True)
    return_path_domain = Column(String(255), nullable=True)
    subject = Column(Text, nullable=True)
    date_header = Column(String(255), nullable=True)
    message_id = Column(String(512), nullable=True)
    received_chain = Column(JSON, nullable=True)

    # Hops / headers / auth summary
    hops = Column(JSON, nullable=True)
    full_headers = Column(JSON, nullable=True)
    auth_summary = Column(JSON, nullable=True)

    # Authentication
    spf_present = Column(Boolean, nullable=True)
    spf_pass = Column(Boolean, nullable=True)
    dkim_present = Column(Boolean, nullable=True)
    dkim_pass = Column(Boolean, nullable=True)
    dmarc_present = Column(Boolean, nullable=True)
    dmarc_pass = Column(Boolean, nullable=True)
    auth_headers_raw = Column(Text, nullable=True)

    # Scores
    header_score = Column(Float, default=0.0)
    url_score = Column(Float, default=0.0)
    content_score = Column(Float, default=0.0)
    attachment_score = Column(Float, default=0.0)
    encoded_score = Column(Float, default=0.0)
    ml_score = Column(Float, default=0.0)
    final_score = Column(Float, default=0.0)

    verdict = Column(String(20), default="Unknown")

    # Contents
    urls_found = Column(JSON, nullable=True)
    ips_found = Column(JSON, nullable=True)
    attachments = Column(JSON, nullable=True)
    encoded_found = Column(JSON, nullable=True)
    encoded_full_dump = Column(JSON, nullable=True)     # ← NEW
    triggered_features = Column(JSON, nullable=True)
    raw_headers = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)


class BrandDomain(Base):
    __tablename__ = "brand_domains"

    id = Column(Integer, primary_key=True, autoincrement=True)
    brand = Column(String(100), nullable=False)
    domain = Column(String(255), nullable=False, unique=True)


class LookupCache(Base):
    __tablename__ = "lookup_cache"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(255), unique=True, nullable=False)
    value = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()