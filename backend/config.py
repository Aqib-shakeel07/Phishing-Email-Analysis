import os
from dotenv import load_dotenv

load_dotenv()

# ---------- App ----------
APP_NAME = "Phishing Email Analyzer"
APP_VERSION = "1.0.0"
DEBUG = os.getenv("DEBUG", "False").lower() == "true"
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", 5000))

# ---------- Paths ----------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

DATA_DIR = os.path.join(PROJECT_ROOT, "data")
MODEL_DIR = os.path.join(PROJECT_ROOT, "models")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
REPORT_DIR = os.path.join(BASE_DIR, "reports")
LOG_DIR = os.path.join(BASE_DIR, "logs")

for d in [DATA_DIR, MODEL_DIR, UPLOAD_DIR, REPORT_DIR, LOG_DIR]:
    os.makedirs(d, exist_ok=True)

# ---------- Data files ----------
BRANDS_FILE = os.path.join(DATA_DIR, "brands.json")
KEYWORDS_FILE = os.path.join(DATA_DIR, "keywords.json")
TLDS_FILE = os.path.join(DATA_DIR, "suspicious_tlds.json")

# ---------- ML ----------
MODEL_PATH = os.path.join(MODEL_DIR, "model.pkl")
DATASET_PATH = os.path.join(DATA_DIR, "phishing_dataset.csv")

# ---------- Database ----------
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'phishing.db')}")

# ---------- External APIs ----------
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3"

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2"

# ---------- Scoring weights ----------
WEIGHTS = {
    "header": 0.25,
    "url": 0.30,
    "content": 0.25,
    "attachment": 0.15,
    "ml": 0.05,
}

# ---------- Verdict thresholds ----------
THRESHOLD_SAFE = 30
THRESHOLD_SUSPICIOUS = 60

# ---------- Limits ----------
MAX_UPLOAD_SIZE = 25 * 1024 * 1024  # 25 MB
ALLOWED_EXTENSIONS = {"eml", "msg", "txt"}
REQUEST_TIMEOUT = 15

# ---------- API cache TTL (seconds) ----------
CACHE_TTL_VT = 60 * 60 * 24         # 24h
CACHE_TTL_ABUSE = 60 * 60 * 24      # 24h

# ---------- Logging ----------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = os.path.join(LOG_DIR, "app.log")