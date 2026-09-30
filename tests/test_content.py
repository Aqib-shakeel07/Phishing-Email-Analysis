import os
import sys
import email
from email import policy

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from content_analyzer import ContentAnalyzer


def _build_email(body: str, html: str = None, subject: str = "Test") -> email.message.Message:
    if html is not None:
        raw = (
            f"From: a@b.com\n"
            f"Subject: {subject}\n"
            f"MIME-Version: 1.0\n"
            f'Content-Type: multipart/alternative; boundary="BOUND"\n\n'
            f"--BOUND\n"
            f"Content-Type: text/plain; charset=utf-8\n\n"
            f"{body}\n"
            f"--BOUND\n"
            f"Content-Type: text/html; charset=utf-8\n\n"
            f"{html}\n"
            f"--BOUND--\n"
        )
    else:
        raw = (
            f"From: a@b.com\n"
            f"Subject: {subject}\n"
            f"Content-Type: text/plain; charset=utf-8\n\n"
            f"{body}\n"
        )
    return email.message_from_string(raw, policy=policy.default)


def setup_module(module):
    global analyzer
    analyzer = ContentAnalyzer()


def test_credential_request_detected():
    msg = _build_email("Please verify your account and enter your password immediately.")
    res = analyzer.analyze(msg)
    assert res["matched_keywords"].get("credential_request")
    assert any("Credential" in f for f in res["flags"])
    assert res["score"] > 0


def test_urgency_detected():
    msg = _build_email("Act now! Your account will be suspended within 24 hours.")
    res = analyzer.analyze(msg)
    assert res["matched_keywords"].get("urgency")
    assert any("Urgency" in f for f in res["flags"])


def test_threat_detected():
    msg = _build_email("Your account suspended due to suspicious activity.")
    res = analyzer.analyze(msg)
    assert res["matched_keywords"].get("threat")
    assert any("Threatening" in f for f in res["flags"])


def test_reward_detected():
    msg = _build_email("Congratulations! You have won a free gift. Claim your prize now.")
    res = analyzer.analyze(msg)
    assert res["matched_keywords"].get("reward")
    assert any("reward" in f.lower() for f in res["flags"])


def test_generic_greeting_detected():
    msg = _build_email("Dear Customer, please review the attached document.")
    res = analyzer.analyze(msg)
    assert res["matched_keywords"].get("greeting_generic")
    assert any("Generic greeting" in f for f in res["flags"])


def test_html_only_email_flagged():
    msg = _build_email("", html="<p>Hello</p>")
    msg.replace_header("Content-Type", 'multipart/alternative; boundary="BOUND"')
    # Force html-only by removing plain part manually
    raw = (
        "From: a@b.com\n"
        "Subject: Test\n"
        "Content-Type: text/html; charset=utf-8\n\n"
        "<p>Click here to verify your account</p>"
    )
    msg = email.message_from_string(raw, policy=policy.default)
    res = analyzer.analyze(msg)
    assert res["has_html"] is True
    assert res["has_plain"] is False
    assert any("HTML-only" in f for f in res["flags"])


def test_form_detected():
    html = '<form action="http://evil.com"><input type="password" name="p"></form>'
    msg = _build_email("Please login", html=html)
    res = analyzer.analyze(msg)
    assert any("form" in f.lower() for f in res["flags"])
    assert any("Password" in f for f in res["flags"])


def test_hidden_text_detected():
    html = '<div style="display:none">hidden content</div><p>Visible</p>'
    msg = _build_email("Visible", html=html)
    res = analyzer.analyze(msg)
    assert any("Hidden" in f or "invisible" in f for f in res["flags"])


def test_anchor_text_mismatch_detected():
    html = '<a href="http://evil.com">https://paypal.com</a>'
    msg = _build_email("Click here", html=html)
    res = analyzer.analyze(msg)
    assert any("deceptive" in f.lower() or "anchor" in f.lower() for f in res["flags"])


def test_shouty_email_flagged():
    msg = _build_email("URGENT!!! YOUR ACCOUNT IS SUSPENDED!!! CLICK NOW!!!")
    res = analyzer.analyze(msg)
    assert any("uppercase" in f.lower() or "punctuation" in f.lower() for f in res["flags"])


def test_empty_body_flagged():
    msg = _build_email("")
    res = analyzer.analyze(msg)
    assert any("Empty" in f for f in res["flags"])


def test_safe_email_low_score():
    msg = _build_email("Hi Bob, the meeting is at 3 PM tomorrow. Thanks, Alice.")
    res = analyzer.analyze(msg)
    assert res["score"] < 20
    assert not res["matched_keywords"].get("credential_request")


def test_score_bounded():
    body = (
        "Dear Customer, act now! Your account suspended. "
        "Verify your account and enter your password, OTP, and card number. "
        "Click here urgently! You have won a free gift!"
    )
    msg = _build_email(body)
    res = analyzer.analyze(msg)
    assert 0 <= res["score"] <= 100
    assert res["score"] > 50