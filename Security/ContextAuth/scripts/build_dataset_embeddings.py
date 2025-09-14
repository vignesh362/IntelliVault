from pathlib import Path
import numpy as np
from ..core.embedder import embed

BASE = Path(__file__).resolve().parents[1]
P_PHRASES = BASE / "assets" / "mini_dataset" / "phrases.jsonl"
P_OUT     = BASE / "assets" / "mini_dataset" / "embeddings.npy"

def main():
    lines = [ln.strip() for ln in P_PHRASES.read_text(encoding="utf-8").splitlines() if ln.strip()]
    # Embed in batches (handled inside embed()) and save
    M = embed(lines)  # (N, D) float32 L2-normalized
    np.save(P_OUT, M)
    print(f"Saved {M.shape} to {P_OUT}")

if __name__ == "__main__":
    main()
