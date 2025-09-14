import json, secrets, hmac, hashlib
from pathlib import Path

APP_DIR = Path.home() / ".context_auth_dev"
APP_DIR.mkdir(parents=True, exist_ok=True)
STORE_FILE = APP_DIR / "store.json"
KEY_FILE = APP_DIR / "key.bin"

def _load_key() -> bytes:
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes()
    k = secrets.token_bytes(32)
    KEY_FILE.write_bytes(k)
    return k

def save_payload(obj: dict) -> None:
    key = _load_key()
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    tag = hmac.new(key, body, hashlib.sha256).hexdigest()
    blob = {"tag": tag, "body": body.decode("utf-8")}
    STORE_FILE.write_text(json.dumps(blob))

def load_payload() -> dict | None:
    if not STORE_FILE.exists():
        return None
    key = _load_key()
    blob = json.loads(STORE_FILE.read_text())
    body = blob["body"].encode("utf-8")
    tag = blob.get("tag", "")
    if not hmac.compare_digest(tag, hmac.new(key, body, hashlib.sha256).hexdigest()):
        raise RuntimeError("Integrity check failed")
    return json.loads(body.decode("utf-8"))
