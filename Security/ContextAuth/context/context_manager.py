from pathlib import Path
import json, os
import numpy as np
from ..core.embedder import embed
from ..core.index import MiniIndex
import yaml

BASE = Path(__file__).resolve().parents[1]
ASSETS = BASE / "assets"
STORE  = BASE / "store"
POLICY = BASE / "policy" / "thresholds.yaml"
STORE.mkdir(exist_ok=True, parents=True)

STATE_NPZ = STORE / "context_state.npz"   # binary store for vectors/indices
STATE_JSON = STORE / "context_state.json" # small meta for inspection

def _load_policy():
    with open(POLICY, "r") as f:
        return yaml.safe_load(f)

def set_context(context_text: str):
    pol = _load_policy()
    idx = MiniIndex(ASSETS)

    # 1) context vector
    v_ctx = embed([context_text])[0]  # (D,)

    # 2) context bank: topN_ctx nearest in dataset
    all_sims = idx.all_sims(v_ctx)  # (N,)
    topN = min(pol["topN_ctx"], len(all_sims))
    ctx_bank_idxs = np.argsort(all_sims)[-topN:][::-1]
    ctx_vecs = idx.by_indices(ctx_bank_idxs)  # (topN, D)

    # centroid + distribution inside the bank
    C_pos = ctx_vecs.mean(axis=0)
    C_pos /= (np.linalg.norm(C_pos) + 1e-8)
    sims_pos = ctx_vecs @ C_pos
    mu_pos = float(sims_pos.mean())
    sigma_pos = float(sims_pos.std() + 1e-6)

    # 3) background bank: far from context
    far_mask = all_sims <= pol["bg_max_sim"]
    far_idxs = np.where(far_mask)[0]
    if len(far_idxs) < pol["bg_pool_size"]:
        # fallback: take the worst similarities
        order = np.argsort(all_sims)
        far_idxs = order[:max(pol["bg_pool_size"] * 2, 64)]
    bg_size = min(pol["bg_pool_size"], len(far_idxs))
    rng = np.random.default_rng()
    bg_bank_idxs = rng.choice(far_idxs, size=bg_size, replace=False)
    bg_vecs = idx.by_indices(bg_bank_idxs)
    C_bg = bg_vecs.mean(axis=0)
    C_bg /= (np.linalg.norm(C_bg) + 1e-8)
    sims_bg = bg_vecs @ C_bg
    mu_bg = float(sims_bg.mean())

    # 4) clear user tail on context rotate
    tail = np.zeros((0, ctx_vecs.shape[1]), dtype=np.float32)
    pass_streak = 0

    # 5) persist
    np.savez_compressed(
        STATE_NPZ,
        v_ctx=v_ctx,
        ctx_bank_idxs=ctx_bank_idxs,
        bg_bank_idxs=bg_bank_idxs,
        C_pos=C_pos,
        mu_pos=np.array([mu_pos], dtype=np.float32),
        sigma_pos=np.array([sigma_pos], dtype=np.float32),
        C_bg=C_bg,
        mu_bg=np.array([mu_bg], dtype=np.float32),
        tail=tail,
        pass_streak=np.array([pass_streak], dtype=np.int32),
    )
    STATE_JSON.write_text(json.dumps({
        "neighbors": int(topN),
        "bg_size": int(bg_size),
        "mu_pos": mu_pos, "sigma_pos": float(sigma_pos),
        "mu_bg": mu_bg
    }, indent=2), encoding="utf-8")

    return {"status": "OK", "neighbors": int(topN), "bg_size": int(bg_size)}
