import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scoring_engine import ScoringEngine
from helpers import score_to_verdict


def setup_module(module):
    global engine
    engine = ScoringEngine()


def _empty():
    return {"score": 0.0, "flags": []}


def test_all_clean_gives_safe():
    res = engine.compute(_empty(), _empty(), _empty(), _empty(), ml_score=0.0)
    assert res["final_score"] < 30
    assert res["verdict"] == "Safe"


def test_all_bad_gives_phishing():
    header = {"score": 90, "flags": ["Display name impersonates PayPal"],
              "spf_pass": False, "dmarc_pass": False}
    url = {"score": 85, "flags": ["Punycode/homograph domain: http://xn--x.com"],
           "urls": []}
    content = {"score": 80, "flags": ["Credential/OTP request detected"]}
    attachment = {"score": 80, "flags": ["Dangerous file type: .exe"]}
    res = engine.compute(header, url, content, attachment, ml_score=90)
    assert res["verdict"] == "Phishing"
    assert res["final_score"] >= 60


def test_medium_scores_suspicious():
    header = {"score": 40, "flags": []}
    url = {"score": 40, "flags": [], "urls": []}
    content = {"score": 40, "flags": []}
    attachment = {"score": 40, "flags": []}
    res = engine.compute(header, url, content, attachment, ml_score=40)
    assert res["verdict"] == "Suspicious"


def test_score_clamped_to_100():
    header = {"score": 200, "flags": []}
    url = {"score": 200, "flags": [], "urls": []}
    content = {"score": 200, "flags": []}
    attachment = {"score": 200, "flags": []}
    res = engine.compute(header, url, content, attachment, ml_score=200)
    assert res["final_score"] <= 100


def test_component_scores_present():
    res = engine.compute(_empty(), _empty(), _empty(), _empty())
    assert "header" in res["component_scores"]
    assert "url" in res["component_scores"]
    assert "content" in res["component_scores"]
    assert "attachment" in res["component_scores"]
    assert "ml" in res["component_scores"]


def test_triggered_features_collected():
    header = {"score": 10, "flags": ["SPF failed"]}
    url = {"score": 10, "flags": ["URL shortener used: bit.ly"], "urls": []}
    content = {"score": 10, "flags": ["Urgency pressure detected"]}
    attachment = {"score": 10, "flags": ["Dangerous file type: .exe"]}
    res = engine.compute(header, url, content, attachment)
    modules = {f["module"] for f in res["triggered_features"]}
    assert {"header", "url", "content", "attachment"}.issubset(modules)


def test_explanation_present():
    res = engine.compute(_empty(), _empty(), _empty(), _empty())
    assert isinstance(res["explanation"], str)
    assert len(res["explanation"]) > 0


def test_booster_for_spf_and_dmarc_fail():
    base = {"score": 0.0, "flags": []}
    header = {"score": 0.0, "flags": [], "spf_pass": False, "dmarc_pass": False}
    res = engine.compute(header, base, base, base)
    assert res["final_score"] > 0


def test_worst_module_floor():
    header = {"score": 95, "flags": ["Display name impersonates PayPal"]}
    url = {"score": 0, "flags": [], "urls": []}
    content = {"score": 0, "flags": []}
    attachment = {"score": 0, "flags": []}
    res = engine.compute(header, url, content, attachment)
    assert res["final_score"] >= 60


def test_score_to_verdict_boundaries():
    assert score_to_verdict(0) == "Safe"
    assert score_to_verdict(29.9) == "Safe"
    assert score_to_verdict(30) == "Suspicious"
    assert score_to_verdict(59.9) == "Suspicious"
    assert score_to_verdict(60) == "Phishing"
    assert score_to_verdict(100) == "Phishing"


def test_ml_score_included():
    base = _empty()
    res = engine.compute(base, base, base, base, ml_score=100)
    assert res["component_scores"]["ml"] == 100.0