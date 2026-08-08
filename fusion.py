
from typing import List

SEVERITY_ORDER = {"OK": 0, "WARMING_UP": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEVERITY_DOWN  = ["OK", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

BENIGN_CONTEXTS = {"streaming", "large_download", "upload", "browsing"}


def _get_sev(h) -> str:
    return h.get("severity", "OK") if isinstance(h, dict) else getattr(h, "severity", "OK")


def _get_conf(h) -> float:
    return h.get("confidence", 0.0) if isinstance(h, dict) else getattr(h, "confidence", 0.0)


def _demote(sev: str) -> str:
    idx = SEVERITY_DOWN.index(sev) if sev in SEVERITY_DOWN else 0
    return SEVERITY_DOWN[max(0, idx - 1)]


def _ml_conf(score: float) -> float:
    """Map IsolationForest score [-1, 0] to [0, 1] confidence."""
    if score >= 0:
        return 0.0
    # Sigmoid-shaped mapping: score -0.3 → ~0.35, -0.6 → ~0.70, -0.9 → ~0.90
    return float(min(1.0, abs(score) * 1.6))


def fuse(
    rule_hits: list,
    ml_score:  float,
    ml_severity: str,
    context:   str = "unknown",
) -> dict:
    """
    Returns dict with keys:
      fused_severity, fused_confidence, fusion_reason, context
    """
    # ── Rule engine summary ──
    rule_sev  = "OK"
    rule_conf = 0.0
    if rule_hits:
        best = max(rule_hits, key=lambda h: SEVERITY_ORDER.get(_get_sev(h), 0))
        rule_sev  = _get_sev(best)
        rule_conf = _get_conf(best)

    # ── ML summary ──
    if ml_severity == "WARMING_UP":
        # Only rule engine available
        return {
            "fused_severity":   rule_sev,
            "fused_confidence": round(rule_conf, 3),
            "fusion_reason":    "rules_only_ml_warming_up",
            "context":          context,
        }

    ml_conf = _ml_conf(ml_score)
    r_rank  = SEVERITY_ORDER.get(rule_sev,  0)
    m_rank  = SEVERITY_ORDER.get(ml_severity, 0)

    # ── Benign context guard ──
    # If we're in a known-benign state and both sources agree on <= HIGH,
    # demote the final severity by one level.
    in_benign = context in BENIGN_CONTEXTS

    if r_rank >= 2 and m_rank >= 2:
        final_sev  = max([rule_sev, ml_severity], key=lambda s: SEVERITY_ORDER.get(s, 0))
        final_conf = min(0.97, (rule_conf + ml_conf) / 2 + 0.12)
        reason     = "both_agree"
        if in_benign and final_sev != "CRITICAL":
            final_sev  = _demote(final_sev)
            final_conf *= 0.80
            reason     = "both_agree_context_suppressed"

    elif r_rank >= 2 and m_rank < 2:
        final_sev  = rule_sev
        final_conf = rule_conf * 0.82
        reason     = "rule_only"
        if in_benign and final_sev != "CRITICAL":
            final_sev  = _demote(final_sev)
            final_conf *= 0.75
            reason     = "rule_only_context_suppressed"

    elif r_rank < 2 and m_rank >= 2:
        final_sev  = ml_severity
        final_conf = ml_conf * 0.78
        reason     = "ml_only"
        if in_benign and final_sev != "CRITICAL":
            final_sev  = _demote(final_sev)
            final_conf *= 0.70
            reason     = "ml_only_context_suppressed"

    else:
        final_sev  = "OK"
        final_conf = 0.0
        reason     = "clean"

    return {
        "fused_severity":   final_sev,
        "fused_confidence": round(max(0.0, final_conf), 3),
        "fusion_reason":    reason,
        "context":          context,
    }
