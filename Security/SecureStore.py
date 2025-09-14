# secure_store.py
import json, os, ctypes, ctypes.wintypes as w
from pathlib import Path
from datetime import datetime

APP_DIR = Path(os.getenv("LOCALAPPDATA", ".")) / "ContextAuth"
APP_DIR.mkdir(parents=True, exist_ok=True)
CTX_FILE = APP_DIR / "context.bin"
ENTROPY = b"context-auth-v1"

CRYPTPROTECT_UI_FORBIDDEN = 0x1

class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", w.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

crypt32 = ctypes.windll.crypt32
kernel32 = ctypes.windll.kernel32

def _blob_from_bytes(b: bytes):
    blob = DATA_BLOB()
    blob.cbData = len(b)
    blob.pbData = ctypes.cast(ctypes.create_string_buffer(b), ctypes.POINTER(ctypes.c_char))
    return blob

def _bytes_from_blob(blob: DATA_BLOB) -> bytes:
    out = ctypes.string_at(blob.pbData, blob.cbData)
    kernel32.LocalFree(blob.pbData)
    return out

def dpapi_encrypt(plaintext: bytes, entropy: bytes = ENTROPY) -> bytes:
    inb, ent, outb = _blob_from_bytes(plaintext), _blob_from_bytes(entropy), DATA_BLOB()
    ok = crypt32.CryptProtectData(ctypes.byref(inb), None, ctypes.byref(ent), None, None,
                                  CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(outb))
    if not ok: raise RuntimeError("CryptProtectData failed")
    return _bytes_from_blob(outb)

def dpapi_decrypt(ciphertext: bytes, entropy: bytes = ENTROPY) -> bytes:
    inb, ent, outb = _blob_from_bytes(ciphertext), _blob_from_bytes(entropy), DATA_BLOB()
    desc = ctypes.c_wchar_p()
    ok = crypt32.CryptUnprotectData(ctypes.byref(inb), ctypes.byref(desc), ctypes.byref(ent),
                                    None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(outb))
    if not ok: raise RuntimeError("CryptUnprotectData failed")
    return _bytes_from_blob(outb)

def save_context(context_text: str, keywords: list[str], rotate_days: int = 14):
    payload = {
        "context": context_text.strip(),
        "keywords": [k.lower().strip() for k in keywords if k.strip()],
        "rotate_days": int(rotate_days),
        "last_set": datetime.utcnow().isoformat(timespec="seconds") + "Z"
    }
    CTX_FILE.write_bytes(dpapi_encrypt(json.dumps(payload).encode()))

def load_context() -> dict:
    if not CTX_FILE.exists(): return {}
    return json.loads(dpapi_decrypt(CTX_FILE.read_bytes()).decode())
