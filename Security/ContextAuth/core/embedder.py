# Real ONNX embedder (macOS: CPU provider). Fully offline.
from pathlib import Path
import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer

_ASSETS = Path(__file__).resolve().parents[1] / "assets"
_MODEL = _ASSETS / "encoder.onnx"
_TOKZ = _ASSETS / "tokenizer" / "tokenizer.json"

# Cache singletons
_SESSION = None
_TOKENIZER = None
_OUT_NAMES = None

def _load():
    global _SESSION, _TOKENIZER, _OUT_NAMES
    if _SESSION is None:
        _SESSION = ort.InferenceSession(str(_MODEL), providers=["CPUExecutionProvider"])
        _OUT_NAMES = [o.name for o in _SESSION.get_outputs()]
    if _TOKENIZER is None:
        _TOKENIZER = Tokenizer.from_file(str(_TOKZ))

def _mean_pool(last_hidden_state: np.ndarray, attention_mask: np.ndarray) -> np.ndarray:
    # last_hidden_state: (B, L, D), attention_mask: (B, L)
    mask = attention_mask.astype(np.float32)
    mask = np.expand_dims(mask, axis=-1)  # (B, L, 1)
    summed = (last_hidden_state * mask).sum(axis=1)           # (B, D)
    counts = np.clip(mask.sum(axis=1), 1e-6, None)            # (B, 1)
    return summed / counts

def embed(texts: list[str], max_length: int = 128, batch_size: int = 64) -> np.ndarray:
    """
    Returns (B, D) float32 L2-normalized embeddings.
    Works with common Sentence-Transformer style ONNX exports:
    - If the model exposes 'sentence_embedding' -> use it
    - Else pools 'last_hidden_state' with attention mask
    """
    _load()

    # Tokenize in batches
    vecs = []
    for i in range(0, len(texts), batch_size):
        chunk = texts[i:i+batch_size]
        encs = _TOKENIZER.encode_batch(chunk)
        ids = [e.ids[:max_length] for e in encs]
        am  = [[1]*len(x) for x in ids]
        # pad
        L = max(len(x) for x in ids)
        ids = [x + [0]*(L-len(x)) for x in ids]
        am  = [x + [0]*(L-len(x)) for x in am]
        input_ids = np.array(ids, dtype=np.int64)
        attention_mask = np.array(am, dtype=np.int64)

        inputs = {}
        # Common input names
        if "input_ids" in [i.name for i in _SESSION.get_inputs()]:
            inputs["input_ids"] = input_ids
            if "attention_mask" in [i.name for i in _SESSION.get_inputs()]:
                inputs["attention_mask"] = attention_mask
        else:
            # Fallback (rare): guess first two inputs are ids/mask
            inps = _SESSION.get_inputs()
            inputs[inps[0].name] = input_ids
            if len(inps) > 1:
                inputs[inps[1].name] = attention_mask

        out = _SESSION.run(None, inputs)  # list aligned to _OUT_NAMES
        out_map = {name: val for name, val in zip(_OUT_NAMES, out)}

        if "sentence_embedding" in out_map:
            emb = out_map["sentence_embedding"]
        elif "last_hidden_state" in out_map:
            emb = _mean_pool(out_map["last_hidden_state"], attention_mask)
        else:
            # Fallback: take the first output and try mean-pool if 3D
            first = out[0]
            if first.ndim == 3:
                emb = _mean_pool(first, attention_mask)
            else:
                emb = first

        emb = emb.astype(np.float32)
        # L2 normalize rows
        n = np.linalg.norm(emb, axis=1, keepdims=True) + 1e-8
        emb = emb / n
        vecs.append(emb)

    return np.vstack(vecs)
