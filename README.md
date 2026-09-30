# Phishing-Email-Analysis# 🛡️ Phishing Email Analyzer

A modular Python + Flask project that analyzes `.eml` files (or raw email source) for phishing indicators using header, URL, content, and attachment analysis, combined with an optional machine learning classifier.

---

## Features

- **Header analysis**: SPF/DKIM/DMARC, From/Reply-To/Return-Path mismatches, display-name spoofing, lookalike domains.
- **URL analysis**: IP-based URLs, shorteners, suspicious TLDs, punycode/homograph, brand impersonation, anchor-text mismatch, embedded HTML forms.
- **Content analysis**: urgency, threat, credential/OTP requests, reward scams, generic greetings, hidden text, shouty formatting.
- **Attachment analysis**: dangerous extensions, double extensions, macro-enabled files, archive nesting, VirusTotal hash lookup.
- **Scoring engine**: weighted component scoring with boosters and explainability.
- **ML classifier** (optional): Random Forest trained on engineered features.
- **Reports**: JSON + PDF export per analysis.
- **Dashboard**: history, stats, filters, downloads.

---

## Project Structure
phishing-analyzer/
├── app.py
├── config.py
├── requirements.txt
├── .env
├── models.py
├── database.py
├── helpers.py
├── validators.py
├── logger.py
├── header_analyzer.py
├── url_analyzer.py
├── content_analyzer.py
├── attachment_analyzer.py
├── scoring_engine.py
├── whois_lookup.py
├── virustotal_api.py
├── ml_classifier.py
├── report_generator.py
├── data/
│ ├── brands.json
│ ├── keywords.json
│ ├── suspicious_tlds.json
│ └── phishing_dataset.csv
├── models/
│ └── model.pkl
├── templates/
│ ├── index.html
│ └── dashboard.html
├── static/
│ ├── style.css
│ ├── script.js
│ └── dashboard.js
├── tests/
│ ├── test_header.py
│ ├── test_url.py
│ ├── test_content.py
│ └── test_scoring.py
└── reports/

text

---

## Installation

```bash
git clone <your-repo-url>
cd phishing-analyzer
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
Copy .env.example → .env and set values:

text
DEBUG=True
VIRUSTOTAL_API_KEY=your_key_here
Running
bash
python app.py
Open:

Web UI: http://localhost:5000

Dashboard: http://localhost:5000/dashboard

Health check: http://localhost:5000/api/health

Training the ML Model
Bootstrap with synthetic data:

bash
curl -X POST http://localhost:5000/api/train -H "Content-Type: application/json" -d '{}'
Or with your own CSV (must include columns listed in ml_classifier.FEATURE_NAMES plus a label column, 0=legit, 1=phishing):

bash
curl -X POST http://localhost:5000/api/train \
  -H "Content-Type: application/json" \
  -d '{"dataset": "data/phishing_dataset.csv"}'
Model is saved to models/model.pkl and auto-loaded on next start.

API Endpoints
Method	Endpoint	Description
GET	/api/health	Health check
POST	/api/analyze	Analyze uploaded/raw email
GET	/api/analyses?limit=&offset=	List analyses
GET	/api/analyses/<id>	Get single analysis
DELETE	/api/analyses/<id>	Delete analysis
GET	/api/stats	Dashboard stats
GET	/api/analyses/<id>/report?format=	Download report (json / pdf)
POST	/api/train	Train ML model
Example: Analyze via curl
bash
curl -X POST http://localhost:5000/api/analyze \
  -F "file=@sample.eml"
Or raw:

bash
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"raw": "From: attacker@paypa1.com\nSubject: Urgent\n\nVerify your account now!"}'
Scoring
Final score = weighted sum of module scores:

Module	Weight
Header	0.25
URL	0.30
Content	0.25
Attachment	0.15
ML	0.05
Verdict thresholds:

0–29 → Safe

30–59 → Suspicious

60–100 → Phishing

Testing
bash
pytest tests/ -v
Notes
VirusTotal and WHOIS lookups are cached in the local SQLite DB.

The ML classifier is optional — the analyzer works fully without it.

All thresholds and weights are configurable in config.py.

Disclaimer
This tool is intended for defensive security research and educational purposes only. Always handle suspicious emails in an isolated environment.

