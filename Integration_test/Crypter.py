#!/usr/bin/env python3
import argparse, json, pathlib, secrets, sys
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"CRPTv1\0"   # 7 bytes + NUL
KEY_SIZE = 32         # 256-bit AES
NONCE_SIZE = 12       # GCM standard
SALT_SIZE = 16

def derive_key(passphrase: str, salt: bytes, n=2**14, r=8, p=1) -> Tuple[bytes, dict]:
    kdf = Scrypt(salt=salt, length=KEY_SIZE, n=n, r=r, p=p)
    return kdf.derive(passphrase.encode()), {"kdf":"scrypt","n":n,"r":r,"p":p}

def encrypt_file(inp: str, outp: str, passphrase: str):
    in_path = pathlib.Path(inp)
    out_path = pathlib.Path(outp)
    data = in_path.read_bytes()

    salt = secrets.token_bytes(SALT_SIZE)
    key, kdf_params = derive_key(passphrase, salt)
    nonce = secrets.token_bytes(NONCE_SIZE)

    ct = AESGCM(key).encrypt(nonce, data, None)

    header = {
        "version": 1,
        "algorithm": "AES-256-GCM",
        "salt_hex": salt.hex(),
        "nonce_hex": nonce.hex(),
        **kdf_params
    }
    header_bytes = json.dumps(header, separators=(",",":")).encode("utf-8")
    header_len = len(header_bytes).to_bytes(4, "big")

    out_path.write_bytes(MAGIC + header_len + header_bytes + ct)
    print(f"Encrypted {in_path} → {out_path} ({len(ct)} bytes ciphertext)")

def decrypt_file(inp: str, outp: str, passphrase: str):
    in_path = pathlib.Path(inp)
    out_path = pathlib.Path(outp)
    blob = in_path.read_bytes()

    if not blob.startswith(MAGIC):
        raise ValueError("Not a CRPTv1 file")
    i = len(MAGIC)
    hlen = int.from_bytes(blob[i:i+4], "big"); i += 4
    header = json.loads(blob[i:i+hlen].decode("utf-8")); i += hlen
    ct = blob[i:]

    if header.get("algorithm") != "AES-256-GCM":
        raise ValueError("Unsupported algorithm")

    salt = bytes.fromhex(header["salt_hex"])
    nonce = bytes.fromhex(header["nonce_hex"])
    key, _ = derive_key(passphrase, salt, n=header["n"], r=header["r"], p=header["p"])

    pt = AESGCM(key).decrypt(nonce, ct, None)
    out_path.write_bytes(pt)
    print(f"Decrypted {in_path} → {out_path} ({len(pt)} bytes)")