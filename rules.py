

import json
import os
import numpy as np
from collections import deque
from typing import TypedDict

SETTINGS_FILE = "settings.json"
HISTORY_LEN   = 500   # rolling window per metric (~16 minutes at 2s interval)
WARMUP_MIN    = 30    # samples before rules activate


class RuleHit(TypedDict, total=False):
    rule_id:     str
    description: str
    severity:    str
    confidence:  float


DEFAULT_SETTINGS = {
    "rules": {
        "SCAN_001": {
            "enabled":         True,
            "sigma_mult":      3.0,
            "abs_floor":       12,        # never trigger below 12 unique ports
            "severity":        "HIGH",
            "description":     "Adaptive port-scan threshold exceeded",
        },
        "CONN_001": {
            "enabled":         True,
            "sigma_mult":      3.0,
            "abs_floor":       8.0,       # conn_rate floor
            "severity":        "MEDIUM",
            "description":     "Adaptive connection-rate threshold exceeded",
        },
        "VOL_001": {
            "enabled":         True,
            "sigma_mult":      3.5,
            "abs_floor":       30_000_000,  # 30 MB/s absolute floor
            "severity":        "HIGH",
            "description":     "Adaptive bandwidth threshold exceeded",
        },
        "SYN_001": {
            "enabled":         True,
            "sigma_mult":      4.0,
            "abs_floor":       15.0,       # SYN/s floor
            "severity":        "HIGH",
            "description":     "Adaptive SYN-rate threshold exceeded",
        },
        "SNORT_001": {
            "enabled":         True,
            "severity":        "CRITICAL",
            "description":     "Snort DPI signature match",
        },
    },
    "global": {
        "suppress_benign_contexts": True,  # suppress during streaming/download
        "benign_suppression_rules": ["VOL_001", "CONN_001"],  # which rules to suppress
    }
}


def load_settings() -> dict:
    """Load settings from file, filling gaps with defaults."""
    if not os.path.exists(SETTINGS_FILE):
        return DEFAULT_SETTINGS
    try:
        with open(SETTINGS_FILE, "r") as f:
            on_disk = json.load(f)
        # Deep merge: disk overrides defaults
        merged = {**DEFAULT_SETTINGS}
        if "rules" in on_disk:
            merged["rules"] = {**DEFAULT_SETTINGS["rules"], **on_disk.get("rules", {})}
        if "global" in on_disk:
            merged["global"] = {**DEFAULT_SETTINGS["global"], **on_disk.get("global", {})}
        return merged
    except Exception:
        return DEFAULT_SETTINGS


def save_settings(settings: dict):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=2)


class AdaptiveRuleEngine:
    def __init__(self):
        self.sample_count = 0
        self.history = {
            "unique_dst_ports": deque(maxlen=HISTORY_LEN),
            "conn_rate":        deque(maxlen=HISTORY_LEN),
            "bandwidth_total":  deque(maxlen=HISTORY_LEN),
            "syn_rate":         deque(maxlen=HISTORY_LEN),
        }

    def _dynamic_threshold(self, history_key: str, sigma_mult: float, abs_floor: float) -> float:
        data = self.history[history_key]
        if len(data) < WARMUP_MIN:
            return abs_floor
        arr   = np.array(data)
        mean  = float(np.mean(arr))
        std   = float(np.std(arr))
        return max(abs_floor, mean + sigma_mult * std)

    def evaluate(self, features: dict, context: str = "unknown") -> list[RuleHit]:
        hits: list[RuleHit] = []
        cfg  = load_settings()
        rules_cfg  = cfg.get("rules", {})
        global_cfg = cfg.get("global", {})
        suppress_benign = global_cfg.get("suppress_benign_contexts", True)
        suppressed_rules = set(global_cfg.get("benign_suppression_rules", []))
        benign_contexts  = {"streaming", "large_download", "upload"}

        # Compute compound features
        ports    = features.get("unique_dst_ports", 0)
        conn_rate= features.get("conn_rate", 0.0)
        bw_total = features.get("bytes_in",  0) + features.get("bytes_out", 0)
        syn_rate = features.get("syn_rate",  0.0)

        # Update rolling histories
        self.history["unique_dst_ports"].append(ports)
        self.history["conn_rate"].append(conn_rate)
        self.history["bandwidth_total"].append(bw_total)
        self.history["syn_rate"].append(syn_rate)
        self.sample_count += 1

        if self.sample_count < WARMUP_MIN:
            # Only Snort fires during warmup
            if features.get("snort_alert") == 1:
                r = rules_cfg.get("SNORT_001", DEFAULT_SETTINGS["rules"]["SNORT_001"])
                if r.get("enabled", True):
                    hits.append({
                        "rule_id":     "SNORT_001",
                        "description": features.get("snort_msg", r["description"]),
                        "severity":    r["severity"],
                        "confidence":  1.0,
                    })
            return hits

        # ── SCAN_001: Port scan ──
        r = rules_cfg.get("SCAN_001", DEFAULT_SETTINGS["rules"]["SCAN_001"])
        if r.get("enabled", True):
            threshold = self._dynamic_threshold(
                "unique_dst_ports", r["sigma_mult"], r["abs_floor"]
            )
            if ports > threshold:
                is_suppressed = suppress_benign and context in benign_contexts and "SCAN_001" in suppressed_rules
                if not is_suppressed:
                    conf = min(0.99, 0.60 + (ports - threshold) / max(threshold, 1) * 0.3)
                    hits.append({
                        "rule_id":     "SCAN_001",
                        "description": f"{r['description']} ({ports:.0f} > {threshold:.0f})",
                        "severity":    r["severity"],
                        "confidence":  round(conf, 3),
                    })

        # ── CONN_001: Connection rate spike ──
        r = rules_cfg.get("CONN_001", DEFAULT_SETTINGS["rules"]["CONN_001"])
        if r.get("enabled", True):
            threshold = self._dynamic_threshold(
                "conn_rate", r["sigma_mult"], r["abs_floor"]
            )
            if conn_rate > threshold:
                is_suppressed = suppress_benign and context in benign_contexts and "CONN_001" in suppressed_rules
                if not is_suppressed:
                    conf = min(0.99, 0.55 + (conn_rate - threshold) / max(threshold, 1) * 0.35)
                    hits.append({
                        "rule_id":     "CONN_001",
                        "description": f"{r['description']} ({conn_rate:.1f} > {threshold:.1f})",
                        "severity":    r["severity"],
                        "confidence":  round(conf, 3),
                    })

        # ── VOL_001: Bandwidth flood ──
        r = rules_cfg.get("VOL_001", DEFAULT_SETTINGS["rules"]["VOL_001"])
        if r.get("enabled", True):
            threshold = self._dynamic_threshold(
                "bandwidth_total", r["sigma_mult"], r["abs_floor"]
            )
            if bw_total > threshold:
                is_suppressed = suppress_benign and context in benign_contexts and "VOL_001" in suppressed_rules
                if not is_suppressed:
                    conf = min(0.99, 0.65 + (bw_total - threshold) / max(threshold, 1) * 0.25)
                    hits.append({
                        "rule_id":     "VOL_001",
                        "description": f"{r['description']} ({bw_total/1e6:.1f} MB > {threshold/1e6:.1f} MB)",
                        "severity":    r["severity"],
                        "confidence":  round(conf, 3),
                    })

        # ── SYN_001: SYN flood ──
        r = rules_cfg.get("SYN_001", DEFAULT_SETTINGS["rules"]["SYN_001"])
        if r.get("enabled", True):
            threshold = self._dynamic_threshold(
                "syn_rate", r["sigma_mult"], r["abs_floor"]
            )
            # SYN rate is NOT suppressed by benign context — SYN floods aren't benign
            if syn_rate > threshold:
                conf = min(0.99, 0.70 + (syn_rate - threshold) / max(threshold, 1) * 0.25)
                hits.append({
                    "rule_id":     "SYN_001",
                    "description": f"{r['description']} ({syn_rate:.1f} > {threshold:.1f})",
                    "severity":    r["severity"],
                    "confidence":  round(conf, 3),
                })

        # ── SNORT_001: DPI signature match ──
        if features.get("snort_alert") == 1:
            r = rules_cfg.get("SNORT_001", DEFAULT_SETTINGS["rules"]["SNORT_001"])
            if r.get("enabled", True):
                hits.append({
                    "rule_id":     "SNORT_001",
                    "description": features.get("snort_msg", r["description"]),
                    "severity":    r["severity"],
                    "confidence":  1.0,
                })

        return hits

    def current_thresholds(self) -> dict:
        """Returns live threshold values for the settings dashboard."""
        cfg = load_settings()
        rules_cfg = cfg.get("rules", {})

        def thresh(hist_key, rule_id, abs_floor):
            r = rules_cfg.get(rule_id, {})
            sigma = r.get("sigma_mult", 3.0)
            return round(self._dynamic_threshold(hist_key, sigma, abs_floor), 2)

        return {
            "SCAN_001_threshold": thresh("unique_dst_ports", "SCAN_001", 12),
            "CONN_001_threshold": thresh("conn_rate",        "CONN_001", 8.0),
            "VOL_001_threshold":  thresh("bandwidth_total",  "VOL_001",  30_000_000),
            "SYN_001_threshold":  thresh("syn_rate",         "SYN_001",  15.0),
            "samples":            self.sample_count,
        }

_engine = AdaptiveRuleEngine()


def evaluate_rules(features: dict, context: str = "unknown") -> list[RuleHit]:
    return _engine.evaluate(features, context)


def get_current_thresholds() -> dict:
    return _engine.current_thresholds()


def get_default_settings() -> dict:
    return DEFAULT_SETTINGS


def get_settings() -> dict:
    return load_settings()


def update_settings(new_settings: dict) -> dict:
    existing = load_settings()
    if "rules" in new_settings:
        existing["rules"].update(new_settings["rules"])
    if "global" in new_settings:
        existing["global"].update(new_settings["global"])
    save_settings(existing)
    return existing
