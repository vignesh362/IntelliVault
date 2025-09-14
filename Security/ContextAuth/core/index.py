from pathlib import Path
import numpy as np

class MiniIndex:
    def __init__(self, assets_dir: Path):
        p_phr = assets_dir / "mini_dataset" / "phrases.jsonl"
        p_emb = assets_dir / "mini_dataset" / "embeddings.npy"
        self.phrases = [ln.strip() for ln in p_phr.read_text(encoding="utf-8").splitlines() if ln.strip()]
        self.E = np.load(p_emb)  # (N, D) float32 unit-norm

    def neighbors(self, v: np.ndarray, topN: int = 128):
        sims = self.E @ v
        idxs = np.argsort(sims)[-topN:][::-1]
        return idxs, sims[idxs]

    def by_indices(self, idxs: np.ndarray) -> np.ndarray:
        return self.E[idxs]

    def all_sims(self, v: np.ndarray) -> np.ndarray:
        return self.E @ v  # (N,)
