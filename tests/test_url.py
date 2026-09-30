import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from url_analyzer import URLAnalyzer


def setup_module(module):
    global analyzer
    analyzer = URLAnalyzer()


def test_ip_based_url_flagged():
    res = analyzer.analyze_urls(["http://192.168.1.1/login"])
    assert res["score"] > 0
    assert any("IP-based" in f for f in res["flags"])


def test_url_shortener_flagged():
    res = analyzer.analyze_urls(["https://bit.ly/abc123"])
    assert any("shortener" in f.lower() for f in res["flags"])


def test_suspicious_tld_flagged():
    res = analyzer.analyze_urls(["http://free-prize.tk/claim"])
    assert any("TLD" in f for f in res["flags"])


def test_lookalike_domain_flagged():
    res = analyzer.analyze_urls(["http://paypa1.com/login"])
    assert res["score"] > 0
    assert any("resembles brand" in f.lower() for f in res["flags"])


def test_punycode_flagged():
    res = analyzer.analyze_urls(["http://xn--pypal-4ve.com/"])
    assert any("Punycode" in f or "homograph" in f.lower() for f in res["flags"])


def test_at_symbol_flagged():
    res = analyzer.analyze_urls(["http://example.com@evil.com/login"])
    assert any("@" in f for f in res["flags"])


def test_long_url_flagged():
    long_url = "http://evil.com/" + "a" * 200
    res = analyzer.analyze_urls([long_url])
    assert any("long URL" in f for f in res["flags"])


def test_safe_url_low_score():
    res = analyzer.analyze_urls(["https://www.google.com/search?q=test"])
    assert res["score"] < 30


def test_empty_urls():
    res = analyzer.analyze_urls([])
    assert res["score"] == 0
    assert res["urls"] == []


def test_html_anchor_text_mismatch():
    html = '<a href="http://evil.com/login">https://paypal.com/login</a>'
    res = analyzer.analyze_html(html)
    assert res["link_mismatches"]
    assert any("mismatch" in f.lower() for f in res["flags"])


def test_brand_in_subdomain_flagged():
    res = analyzer.analyze_urls(["http://paypal.evil.com/login"])
    assert any("subdomain" in f.lower() for f in res["flags"])


def test_multiple_urls_aggregate_score():
    urls = [
        "https://google.com",
        "http://paypa1.com/login",
        "http://free.tk/claim",
    ]
    res = analyzer.analyze_urls(urls)
    assert len(res["urls"]) == 3
    assert res["score"] > 20


def test_score_bounded():
    urls = [
        "http://192.168.1.1@paypa1.tk/x" * 3,
    ]
    res = analyzer.analyze_urls(urls)
    assert 0 <= res["score"] <= 100