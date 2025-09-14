# Security/Keystroke/adapter.py
from __future__ import annotations
import json, math
from pathlib import Path
import numpy as np

STORE = Path(__file__).resolve().parent / "store"
BASELINE = STORE / "baseline.npz"      # dwell_mean,std, flight_mean,std, length
PWD_JSON = STORE / "password.json"     # {"salt_hex": "...", "pbkdf2_hex": "...", "iters": 200000}

def _load_baseline():
    if not BASELINE.exists():
        raise FileNotFoundError("keystroke baseline not found; run enroll first")
    data = np.load(BASELINE)
    return {
        "dwell_mean": data["dwell_mean"],
        "dwell_std":  data["dwell_std"],
        "flight_mean": data["flight_mean"],
        "flight_std":  data["flight_std"],
        "length": int(data["length"][0]),
    }

def score_sample(dwell: list[float], flight: list[float]) -> float:
    """
    dwell:  per-char (len = L)
    flight: between chars (len = L-1)
    returns similarity in [0,1]
    """
    bl = _load_baseline()
    L = bl["length"]
    if len(dwell) != L or len(flight) != L-1:
        return 0.0

    dmean, dstd = bl["dwell_mean"], bl["dwell_std"]
    fmean, fstd = bl["flight_mean"], bl["flight_std"]

    # clamp std to avoid div by zero
    dstd = np.maximum(dstd, 1e-6)
    fstd = np.maximum(fstd, 1e-6)

    d = (np.array(dwell) - dmean) / dstd
    f = (np.array(flight) - fmean) / fstd

    # robust aggregation: mean squared z then convert to similarity
    mse = float((np.mean(d**2) + np.mean(f**2)) / 2.0)
    # Similarity in [0,1]; lower MSE → higher score
    sim = math.exp(-mse)  # exp(-mse) gives a nice curve
    return max(0.0, min(1.0, sim))
