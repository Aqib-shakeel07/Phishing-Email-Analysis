import os
import sys
import email
from email import policy

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from header_analyzer import HeaderAnalyzer, parse_email_bytes


def _build_email(headers: dict, body: str = "Hello") -> email.message.Message:
    lines = [f"{k}: {v}" for k, v in headers.items()]
    raw = "\n".join(lines) + "\n\n" + body
    return parse_email_bytes(raw.encode("utf-8"))


def test_spf_dkim_dmarc_pass():
    analyzer = HeaderAnalyzer()
    msg = _build_email({
        "From": "Alice <alice@example.com>",
        "To": "bob@example.com",
        "Subject": "Hello",
        "Authentication-Results": "mx.example.com; spf=pass dkim=pass dmarc=pass",
        "Message-ID": "<abc@example.com>",
        "Date": "Mon, 1 Jan 2024 10:00:00 +0000",
    })
    res = analyzer.analyze(msg)
    assert res["spf_pass"] is True
    assert res["dkim_pass"] is True
    assert res["dmarc_pass"] is True
    assert res["score"] == 0.0


def test_spf_fail_increases_score():
    analyzer = HeaderAnalyzer()
    msg = _build_email({
        "From": "Alice <alice@example.com>",
        "Subject": "Hello",
        "Authentication-Results": "mx.example.com; spf=fail dkim=fail dmarc=fail",
    })
    res = analyzer.analyze(msg)
    assert res["spf_pass"] is False
    assert res["score"] >= 30
    assert any("SPF" in f for f in res["flags"])


def test_reply_to_mismatch_flag():
    analyzer = HeaderAnalyzer()
    msg = _build_email({
        "From": "Alice <alice@example.com>",
        "Reply-To": "attacker@evil.com",
        "Subject": "Hello",
        "Authentication-Results": "mx; spf=pass dkim=pass dmarc=pass",
    })
    res = analyzer.analyze(msg)
    assert res["reply_to_domain"] == "evil.com"
    assert any("Reply-To" in f for f in res["flags"])


def test_return_path_mismatch_flag():
    analyzer = HeaderAnalyzer()
    msg = _build_email({
        "From": "Alice <alice@example.com>",
        "Return-Path": "<bounce@otherdomain.com>",
        "Subject": "Hello",
    })
    res = analyzer.analyze(msg)
    assert res["return_path_domain"] == "otherdomain.com"
    assert any("Return-Path" in f for f in res["flags"])


def test_display_name_spoofing_detected():
    analyzer = HeaderAnalyzer()
    msg = _build_email({
        "From": "PayPal Support <support@evil-domain.com>",
        "Subject": "Important",
        "Authentication-Results": "mx; spf=pass dkim=pass dmarc=pass",
    })
    res = analyzer.analyze(msg)
    assert any("impersonates" in f for f in res["flags"])


def test_lookalike_domain_detected():
    analyzer = HeaderAnalyzer()
    msg = _build_email({
        "From": "Security <security@paypa1.com>",
        "Subject": "Alert",
    })
    res = analyzer.analyze(msg)
    assert res["score"] > 0
    assert any(
        "looks like" in f.lower() or "paypal" in f.lower()
        for f in res["flags"]
    )


def test_missing_message_id_and_date():
    analyzer = HeaderAnalyzer()
    msg = _build_email({
        "From": "Alice <alice@example.com>",
        "Subject": "Hi",
    })
    res = analyzer.analyze(msg)
    assert any("Message-ID" in f for f in res["flags"])
    assert any("Date" in f for f in res["flags"])


def test_score_is_clamped():
    analyzer = HeaderAnalyzer()
    msg = _build_email({
        "From": "PayPal <security@paypa1.com>",
        "Reply-To": "attacker@evil.com",
        "Return-Path": "<x@bad.com>",
        "Authentication-Results": "mx; spf=fail dkim=fail dmarc=fail",
    })
    res = analyzer.analyze(msg)
    assert 0 <= res["score"] <= 100