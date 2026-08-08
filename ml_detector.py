

import os
import json
import numpy as np
from collections import deque
from datetime import datetime, timezone

import joblib
from sklearn.ensemble import IsolationForest

WARMUP_SAMPLES  = 20   
REFIT_EVERY     = 100      
CONTAMINATION   = 0.04    
MODEL_FILE      = "ml_baseline.pkl"
QUARANTINE_FILE = "quarantined_anomalies.json"

EMA_ALPHA = 0.05

MIN_STD = 0.015

FEATURE_KEYS = [
    "bytes_in",
    "bytes_out",
    "conn_total",
    "conn_rate",
    "unique_dst_ports",
    "syn_rate",
]


def infer_activity_context(features: dict, ema: dict) -> str:
    b_in   = features.get("bytes_in",   0.0)
    b_out  = features.get("bytes_out",  0.0)
    ports  = features.get("unique_dst_ports", 0)
    syn    = features.get("syn_rate",   0.0)
    conns  = features.get("conn_total", 0)

    ema_bin  = ema.get("bytes_in",  1.0) or 1.0
    ema_bout = ema.get("bytes_out", 1.0) or 1.0

    ratio_in  = b_in  / ema_bin
    ratio_out = b_out / ema_bout

    if b_in > 500_000 and ports <= 8 and syn < 3.0 and ratio_in > 1.5:
        if ratio_out < 0.5:  # mostly receiving, not sending
            return "streaming"

    if b_in > 2_000_000 and ports <= 4 and syn < 1.0 and conns < 15:
        return "large_download"

    if b_out > 1_000_000 and ports <= 6 and ratio_out > 2.0:
        return "upload"

    if ports > 5 and syn < 5.0 and b_in < 2_000_000:
        return "browsing"

    if b_in < 50_000 and b_out < 50_000:
        return "idle"

    return "unknown"


# Benign contexts where ML anomaly severity should be suppressed one level
BENIGN_CONTEXTS = {"streaming", "large_download", "upload", "browsing"}

# How many sigma above mean to trigger each severity (adaptive)
SIGMA_THRESHOLDS = {
    "CRITICAL": 5.0,
    "HIGH":     3.5,
    "MEDIUM":   2.5,
    "LOW":      1.8,
}


class AnomalyDetector:
    def __init__(self):
        self._model: IsolationForest | None = None
        self._fitted  = False
        self._sample_count = 0

        # Circular buffer of CLEAN feature vectors (quarantine keeps anomalies out)
        self._buffer: deque = deque(maxlen=2000)

        # Rolling score history for adaptive sigma thresholds (clean samples only)
        self._score_history: deque = deque(maxlen=1000)

        # EMA state for each feature (for context inference normalization)
        self._ema: dict = {k: None for k in FEATURE_KEYS}

        # Current inferred activity context (exposed to dashboard)
        self.current_context = "warming_up"

        self._load_if_exists()

    def _load_if_exists(self):
        if not os.path.exists(MODEL_FILE):
            return
        try:
            state = joblib.load(MODEL_FILE)
            self._buffer        = state.get("buffer",        self._buffer)
            self._score_history = state.get("score_history", self._score_history)
            self._ema           = state.get("ema",           self._ema)
            self._model         = state.get("model",         None)
            self._sample_count  = state.get("sample_count",  0)
            self._fitted        = self._model is not None
            print(f"[ML] Loaded baseline from {MODEL_FILE} ({self._sample_count} samples)")
        except Exception as e:
            print(f"[ML] Could not load baseline: {e} — starting fresh")

    def _save(self):
        try:
            joblib.dump({
                "buffer":        self._buffer,
                "score_history": self._score_history,
                "ema":           self._ema,
                "model":         self._model,
                "sample_count":  self._sample_count,
            }, MODEL_FILE)
        except Exception as e:
            print(f"[ML] Save error: {e}")

    def _update_ema(self, features: dict):
        for k in FEATURE_KEYS:
            v = float(features.get(k, 0.0))
            if self._ema[k] is None:
                self._ema[k] = v
            else:
                self._ema[k] = EMA_ALPHA * v + (1 - EMA_ALPHA) * self._ema[k]

    def _fit(self):
        if len(self._buffer) < WARMUP_SAMPLES:
            return
        X = np.array(self._buffer)
        self._model = IsolationForest(
            n_estimators=200,
            contamination=CONTAMINATION,
            max_samples=min(512, len(self._buffer)),
            random_state=42,
            n_jobs=-1,
        )
        self._model.fit(X)
        self._fitted = True
        self._save()

    def _to_vec(self, features: dict) -> np.ndarray:
        return np.array([features.get(k, 0.0) for k in FEATURE_KEYS], dtype=float)

    def _adaptive_severity(self, score: float) -> str:
        """
        Maps raw IsolationForest score to severity using YOUR network's sigma distribution.
        Falls back to static thresholds during warmup.
        """
        if len(self._score_history) < 30:
            # Static fallback during warmup
            if score >= -0.15:  return "OK"
            if score >= -0.30:  return "LOW"
            if score >= -0.45:  return "MEDIUM"
            if score >= -0.60:  return "HIGH"
            return "CRITICAL"

        arr  = np.array(self._score_history)
        mean = float(np.mean(arr))
        std  = float(max(np.std(arr), MIN_STD))

        
        sigmas_below = (mean - score) / std

        if sigmas_below >= SIGMA_THRESHOLDS["CRITICAL"]: return "CRITICAL"
        if sigmas_below >= SIGMA_THRESHOLDS["HIGH"]:     return "HIGH"
        if sigmas_below >= SIGMA_THRESHOLDS["MEDIUM"]:   return "MEDIUM"
        if sigmas_below >= SIGMA_THRESHOLDS["LOW"]:      return "LOW"
        return "OK"

    def _apply_context_suppression(self, severity: str, context: str) -> str:
        """
        If we're in a benign context (streaming, download, etc.), demote severity
        by one level. This prevents video/download from triggering HIGH alerts.
        """
        if context not in BENIGN_CONTEXTS:
            return severity
        order   = ["OK", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        idx     = order.index(severity) if severity in order else 0
        demoted = order[max(0, idx - 1)]
        return demoted

    def _quarantine(self, features: dict, score: float, severity: str):
        try:
            record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "severity":  severity,
                "ml_score":  round(score, 4),
                "features":  features,
            }
            with open(QUARANTINE_FILE, "a") as f:
                f.write(json.dumps(record) + "\n")
        except Exception:
            pass

    def score(self, features: dict) -> tuple[float, str]:
        """
        Returns (raw_score, final_severity).
        raw_score: float in [-1, 0], 0=normal.
        final_severity: OK | LOW | MEDIUM | HIGH | CRITICAL | WARMING_UP
        """
        # Always update EMA regardless of warmup state
        self._update_ema(features)

        # Infer activity context using EMA-normalized values
        context = infer_activity_context(features, self._ema)
        self.current_context = context

        vec = self._to_vec(features)

        # ── Warmup phase ──
        if not self._fitted:
            self._buffer.append(vec)
            self._sample_count += 1
            if self._sample_count >= WARMUP_SAMPLES:
                self._fit()
            return 0.0, "WARMING_UP"

        # ── Score ──
        raw = float(
            np.clip(self._model.score_samples(vec.reshape(1, -1))[0], -1.0, 0.0)
        )

        severity = self._adaptive_severity(raw)
        severity = self._apply_context_suppression(severity, context)

        # ── Quarantine gate ──
        if severity in ("HIGH", "CRITICAL"):
            self._quarantine(features, raw, severity)
            # Do NOT add to buffer — keeps baseline clean
        else:
            self._buffer.append(vec)
            self._score_history.append(raw)
            self._sample_count += 1
            # Periodic refit on clean data only
            if self._sample_count % REFIT_EVERY == 0:
                self._fit()

        return raw, severity

    @property
    def is_warmed_up(self) -> bool:
        return self._fitted

    @property
    def samples_collected(self) -> int:
        return self._sample_count

    @property
    def warmup_needed(self) -> int:
        return max(0, WARMUP_SAMPLES - self._sample_count)

    @property
    def ema_snapshot(self) -> dict:
        return {k: round(v, 2) if v is not None else None for k, v in self._ema.items()}

    @property
    def score_stats(self) -> dict:
        if len(self._score_history) < 2:
            return {"mean": None, "std": None, "p95": None}
        arr = np.array(self._score_history)
        return {
            "mean": round(float(np.mean(arr)), 4),
            "std":  round(float(np.std(arr)),  4),
            "p95":  round(float(np.percentile(arr, 5)), 4),  # 5th percentile = anomaly direction
        }
