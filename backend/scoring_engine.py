from config import (
    WEIGHTS, THRESHOLD_SAFE, THRESHOLD_SUSPICIOUS
)
from helpers import clamp, score_to_verdict
from logger import logger


class ScoringEngine:
    def __init__(self, weights: dict | None = None):
        self.weights = weights or WEIGHTS

    # ---------------- Public ----------------

    def compute(self, header: dict, url: dict,
                content: dict, attachment: dict,
                ml_score: float = 0.0) -> dict:
        component_scores = {
            "header": float(header.get("score", 0.0)),
            "url": float(url.get("score", 0.0)),
            "content": float(content.get("score", 0.0)),
            "attachment": float(attachment.get("score", 0.0)),
            "ml": float(ml_score or 0.0),
        }

        final = 0.0
        for key, weight in self.weights.items():
            final += component_scores.get(key, 0.0) * weight

        final = self._apply_boosters(final, header, url, content, attachment)

        worst = max(component_scores.values()) if component_scores else 0.0
        total_sum = sum(component_scores.values())

        if worst >= 80:
            final = max(final, 75)
        elif worst >= 60:
            final = max(final, 55)
        elif worst >= 45 and total_sum > 120:
            final = max(final, 45)

        final = clamp(final, 0, 100)
        verdict = score_to_verdict(final, THRESHOLD_SAFE, THRESHOLD_SUSPICIOUS)

        triggered = self._collect_flags(header, url, content, attachment)

        result = {
            "component_scores": component_scores,
            "final_score": round(final, 2),
            "verdict": verdict,
            "triggered_features": triggered,
            "explanation": self._explain(component_scores, final, verdict),
        }
        logger.info(f"Final score={result['final_score']} verdict={verdict}")
        return result

    # ---------------- Internal ----------------

    def _apply_boosters(self, score: float, header, url, content, attachment) -> float:
        # High-signal pairings
        if header.get("spf_pass") is False and header.get("dmarc_pass") is False:
            score += 10
        if any("Punycode" in f or "homograph" in f.lower() for f in url.get("flags", [])):
            score += 10
        if any("Credential/OTP" in f for f in content.get("flags", [])):
            score += 10
        if any("Dangerous file" in f for f in attachment.get("flags", [])):
            score += 10
        if any("impersonates" in f or "claims" in f for f in header.get("flags", [])):
            score += 10
        if any("differs from From" in f for f in header.get("flags", [])):
            score += 8

        # Correlated-signal booster: many moderate flags = high risk
        total_flags = (
            len(header.get("flags", []) or []) +
            len(url.get("flags", []) or []) +
            len(content.get("flags", []) or []) +
            len(attachment.get("flags", []) or [])
        )
        if total_flags >= 10:
            score += 15
        elif total_flags >= 6:
            score += 10
        elif total_flags >= 4:
            score += 5

        return score

    def _collect_flags(self, header, url, content, attachment) -> list:
        flags = []
        for f in header.get("flags", []) or []:
            flags.append({"module": "header", "detail": f})

        url_summary = self._summarize_url_flags(url)
        for f in url_summary:
            flags.append({"module": "url", "detail": f})

        for f in content.get("flags", []) or []:
            flags.append({"module": "content", "detail": f})

        for f in attachment.get("flags", []) or []:
            flags.append({"module": "attachment", "detail": f})

        return flags

    def _summarize_url_flags(self, url: dict) -> list:
        urls = url.get("urls", []) or []
        if not urls:
            return []

        total = len(urls)
        very_long = sum(1 for u in urls if any("Extremely long" in f for f in u.get("flags", [])))
        long_cnt = sum(1 for u in urls if any("Unusually long" in f for f in u.get("flags", [])))
        obf = sum(1 for u in urls if any("Obfuscated" in f for f in u.get("flags", [])))
        short = sum(1 for u in urls if any("shortener" in f.lower() for f in u.get("flags", [])))
        ip_based = sum(1 for u in urls if any("IP-based" in f for f in u.get("flags", [])))
        puny = sum(1 for u in urls if any("Punycode" in f or "homograph" in f.lower() for f in u.get("flags", [])))
        lookalike = sum(1 for u in urls if any("resembles brand" in f.lower() or "looks like" in f.lower() for f in u.get("flags", [])))
        brand_sub = sum(1 for u in urls if any("used as subdomain" in f for f in u.get("flags", [])))
        bad_tld = sum(1 for u in urls if any("TLD" in f for f in u.get("flags", [])))
        at_sym = sum(1 for u in urls if any("@" in f and "URL contains" in f for f in u.get("flags", [])))
        hyphen = sum(1 for u in urls if any("Hyphen-heavy" in f for f in u.get("flags", [])))
        encoded = sum(1 for u in urls if any("encoded" in f.lower() for f in u.get("flags", [])))

        summary = [f"{total} unique URL(s) extracted — see 'URLs Found' card for details"]

        if very_long:
            summary.append(f"{very_long} extremely long URL(s) (>200 chars)")
        if long_cnt:
            summary.append(f"{long_cnt} unusually long URL(s) (>100 chars)")
        if obf:
            summary.append(f"{obf} URL(s) with obfuscated / random-looking path")
        if encoded:
            summary.append(f"{encoded} URL(s) with encoded characters")
        if brand_sub:
            summary.append(f"{brand_sub} URL(s) using a brand name as subdomain")
        if lookalike:
            summary.append(f"{lookalike} URL(s) resembling a known brand")
        if puny:
            summary.append(f"{puny} punycode/homograph URL(s)")
        if ip_based:
            summary.append(f"{ip_based} IP-based URL(s)")
        if short:
            summary.append(f"{short} shortened URL(s)")
        if bad_tld:
            summary.append(f"{bad_tld} URL(s) with suspicious TLD")
        if at_sym:
            summary.append(f"{at_sym} URL(s) with '@' trick")
        if hyphen:
            summary.append(f"{hyphen} hyphen-heavy domain(s)")

        return summary

    def _explain(self, comps: dict, final: float, verdict: str) -> str:
        parts = [f"{name}={round(val, 1)}" for name, val in comps.items()]
        return (
            f"Final score {round(final, 2)} ({verdict}). "
            f"Component scores: {', '.join(parts)}."
        )