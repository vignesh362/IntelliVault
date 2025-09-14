from pathlib import Path
import numpy as np
import yaml
from ..core.embedder import embed
from ..core.index import MiniIndex

BASE = Path(__file__).resolve().parents[1]
ASSETS = BASE / "assets"
STORE  = BASE / "store"
POLICY = BASE / "policy" / "thresholds.yaml"
STATE_NPZ = STORE / "context_state.npz"

def _load_policy():
    with open(POLICY, "r") as f:
        return yaml.safe_load(f)

def verify_answer(answer_text: str):
    """
    Contrastive, context-aware verification:
      1) Directional gate vs context vector (s_ctx)
      2) Strength gate: top-k mean similarity inside context bank (s_pos)
      3) Margin gate: s_pos - s_bg (vs background bank)
      4) Local z-score gate: z_local against sims distribution of (ctx_bank ⋅ v_ans)

    Returns:
      {
        "status": "PASS|FAIL",
        "flag":   "allow|deny",
        "scores": {
          "s_ctx": float,
          "s_pos": float,
          "s_bg":  float,
          "margin": float,
          "z_local": float,
          "k_used": int
        },
        "auto_enrolled": bool
      }
    """
    pol = _load_policy()
    idx = MiniIndex(ASSETS)

    if not STATE_NPZ.exists():
        return {"status": "ERROR", "flag": "deny", "reason": "no-context"}

    st = np.load(STATE_NPZ, allow_pickle=True)
    v_ctx      = st["v_ctx"]                  # (D,)
    ctx_idxs   = st["ctx_bank_idxs"]          # (M,)
    bg_idxs    = st["bg_bank_idxs"]           # (B,)
    # C_pos, mu_pos, sigma_pos persisted but not used in local-z variant:
    # C_pos      = st["C_pos"]
    # mu_pos     = float(st["mu_pos"][0])
    # sigma_pos  = float(st["sigma_pos"][0])
    # Background centroid/mean kept only for future audits
    # C_bg       = st["C_bg"]
    # mu_bg      = float(st["mu_bg"][0])
    tail       = st["tail"]                   # (T, D)
    pass_streak= int(st["pass_streak"][0])

    # 1) Embed answer
    v_ans = embed([answer_text])[0]           # (D,)

    # 2) Gate: similarity to raw context vector
    s_ctx = float(v_ans @ v_ctx)
    ctx_ok = s_ctx >= pol["gate_ctx"]

    # 3) Positive pool: context bank (+ user tail)
    ctx_vecs = idx.by_indices(ctx_idxs)       # (M, D)
    if tail.shape[0] > 0:
        ctx_vecs = np.vstack([ctx_vecs, tail])

    # 4) Strength inside positive pool: top-k mean
    sims_pos_all = ctx_vecs @ v_ans           # (M+T,)
    k = min(int(pol["k"]), sims_pos_all.shape[0]) if sims_pos_all.shape[0] > 0 else 1
    if sims_pos_all.shape[0] >= k:
        topk = np.partition(sims_pos_all, -k)[-k:]
    else:
        topk = sims_pos_all
    s_pos = float(topk.mean())
    pos_ok = s_pos >= pol["gate_pos"]

    # 5) Background mean similarity
    bg_vecs = idx.by_indices(bg_idxs)         # (B, D)
    s_bg = float((bg_vecs @ v_ans).mean()) if bg_vecs.shape[0] else -1.0

    # 6) Margin vs background
    margin = s_pos - s_bg
    margin_ok = margin >= pol["gate_margin"]

    # 7) LOCAL z-score: compare s_pos vs distribution of (ctx_bank ⋅ v_ans)
    mu_local = float(sims_pos_all.mean()) if sims_pos_all.size else 0.0
    sigma_local = float(sims_pos_all.std() + 1e-6) if sims_pos_all.size else 1.0
    z_local = (s_pos - mu_local) / sigma_local
    z_ok = z_local >= pol["gate_zlocal"]

    passed = bool(ctx_ok and pos_ok and margin_ok and z_ok)

    # 8) Auto-enroll: require margin and consecutive passes; cap tail
    enrolled = False
    if passed and margin >= pol["auto_enroll_min_margin"]:
        pass_streak += 1
        if pass_streak >= int(pol["auto_enroll_consecutive_passes"]):
            if tail.shape[0] < int(pol["auto_enroll_cap"]):
                tail = np.vstack([tail, v_ans.reshape(1, -1)])
                enrolled = True
            pass_streak = 0
    else:
        pass_streak = 0

    # 9) Persist updated tail / pass_streak
    np.savez_compressed(
        STATE_NPZ,
        v_ctx=v_ctx, ctx_bank_idxs=ctx_idxs, bg_bank_idxs=bg_idxs,
        # keep these for audit/future, even if not used by local z gate
        C_pos=st["C_pos"], mu_pos=st["mu_pos"], sigma_pos=st["sigma_pos"],
        C_bg=st["C_bg"],   mu_bg=st["mu_bg"],
        tail=tail, pass_streak=np.array([pass_streak], dtype=np.int32),
    )

    return {
        "status": "PASS" if passed else "FAIL",
        "flag": "allow" if passed else "deny",
        "scores": {
            "s_ctx": round(s_ctx, 4),
            "s_pos": round(s_pos, 4),
            "s_bg":  round(s_bg, 4),
            "margin": round(margin, 4),
            "z_local": round(z_local, 3),
            "k_used": int(k)
        },
        "auto_enrolled": enrolled
    }
