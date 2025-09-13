#!/usr/bin/env python3
import argparse, json, pathlib, sys, hashlib
import os
import math
from Crypter import derive_key, MAGIC, KEY_SIZE, NONCE_SIZE, SALT_SIZE
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024  # 4 MiB

def split_file(input_file: str, out_dir: str, chunk_size: int = DEFAULT_CHUNK_SIZE, passphrase: str = None):
    in_path = pathlib.Path(input_file)
    outp = pathlib.Path(out_dir); outp.mkdir(parents=True, exist_ok=True)

    # Generate encryption parameters if passphrase provided
    encryption_info = None
    if passphrase:
        salt = secrets.token_bytes(SALT_SIZE)
        key, kdf_params = derive_key(passphrase, salt)
        encryption_info = {
            "algorithm": "AES-256-GCM",
            "salt_hex": salt.hex(),
            **kdf_params
        }

    manifest = {
        "version": 1,
        "original_filename": in_path.name,
        "original_size": in_path.stat().st_size,
        "original_sha256": None,
        "chunk_size": chunk_size,
        "encrypted": passphrase is not None,
        "encryption_info": encryption_info,
        "chunks": []
    }

    h = hashlib.sha256()
    idx = 0
    with in_path.open("rb") as f:
        while True:
            buf = f.read(chunk_size)
            if not buf: break
            idx += 1
            h.update(buf)
            
            # Encrypt chunk if passphrase provided
            if passphrase:
                nonce = secrets.token_bytes(NONCE_SIZE)
                cipher = AESGCM(key)
                encrypted_buf = cipher.encrypt(nonce, buf, None)
                
                # Create encrypted chunk with header
                header = {
                    "version": 1,
                    "algorithm": "AES-256-GCM",
                    "nonce_hex": nonce.hex()
                }
                header_bytes = json.dumps(header, separators=(",",":")).encode("utf-8")
                header_len = len(header_bytes).to_bytes(4, "big")
                
                final_buf = MAGIC + header_len + header_bytes + encrypted_buf
                chunk_size_written = len(final_buf)
            else:
                final_buf = buf
                chunk_size_written = len(buf)
            
            name = f"chunk_{idx:05d}.part"
            (outp / name).write_bytes(final_buf)
            manifest["chunks"].append({"name": name, "size": chunk_size_written})

    manifest["original_sha256"] = h.hexdigest()
    (outp / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"Split {in_path} → {outp} ({idx} chunks)")

def join_chunks(in_dir: str, output_file: str, passphrase: str = None):
    inp = pathlib.Path(in_dir)
    man = inp / "manifest.json"
    if not man.is_file():
        raise FileNotFoundError("manifest.json not found")

    manifest = json.loads(man.read_text())
    out_path = pathlib.Path(output_file); out_path.parent.mkdir(parents=True, exist_ok=True)

    # Check if chunks are encrypted and validate passphrase
    is_encrypted = manifest.get("encrypted", False)
    if is_encrypted and not passphrase:
        raise ValueError("Chunks are encrypted but no passphrase provided")
    if not is_encrypted and passphrase:
        print("Warning: Passphrase provided but chunks are not encrypted")

    # Derive key if encrypted
    key = None
    if is_encrypted:
        encryption_info = manifest.get("encryption_info", {})
        salt = bytes.fromhex(encryption_info["salt_hex"])
        key, _ = derive_key(passphrase, salt, 
                          n=encryption_info["n"], 
                          r=encryption_info["r"], 
                          p=encryption_info["p"])

    h = hashlib.sha256()
    with out_path.open("wb") as out:
        for i, ch in enumerate(manifest["chunks"], start=1):
            part = inp / ch["name"]
            if not part.is_file():
                raise FileNotFoundError(f"Missing chunk: {part.name}")
            data = part.read_bytes()
            if len(data) != ch["size"]:
                raise ValueError(f"Size mismatch in {part.name}")
            
            # Decrypt chunk if encrypted
            if is_encrypted:
                if not data.startswith(MAGIC):
                    raise ValueError(f"Invalid encrypted chunk format: {part.name}")
                i = len(MAGIC)
                hlen = int.from_bytes(data[i:i+4], "big"); i += 4
                header = json.loads(data[i:i+hlen].decode("utf-8")); i += hlen
                ct = data[i:]
                
                if header.get("algorithm") != "AES-256-GCM":
                    raise ValueError(f"Unsupported algorithm in {part.name}")
                
                nonce = bytes.fromhex(header["nonce_hex"])
                cipher = AESGCM(key)
                decrypted_data = cipher.decrypt(nonce, ct, None)
                data = decrypted_data
            
            out.write(data)
            h.update(data)

    expected = manifest.get("original_sha256")
    if expected and h.hexdigest() != expected:
        out_path.unlink(missing_ok=True)
        raise ValueError("SHA256 mismatch after join; output removed")

    print(f"Joined chunks from {inp} → {out_path}")
import os
import math

def choose_chunk_size_for_file(path: str,
                               target_chunks: int = 300,
                               min_chunk_bytes: int = 1 * 1024 * 1024,   # 1 MiB (soft minimum)
                               max_chunk_bytes: int = 128 * 1024 * 1024, # 128 MiB
                               align_bytes: int = 1 * 1024 * 1024,        # align to MiB
                               min_parts: int = 4                          # ensure ≥4 chunks
                               ) -> int:
    size = os.path.getsize(path)
    if size <= 0:
        return 1

    print("File Size:", size)

    # Ideal to hit target_chunks
    ideal = max(1, math.ceil(size / max(1, target_chunks)))

    # Upper bound to guarantee ≥ min_parts chunks
    upper_bound = max(1, size // max(1, min_parts))  # floor(size/min_parts)

    # For tiny files, allow smaller chunks than the soft min to meet ≥ min_parts
    effective_min = min(min_chunk_bytes, upper_bound)

    # Clamp by effective min/max, then by upper_bound (to guarantee ≥ min_parts)
    clamped = max(effective_min, min(ideal, max_chunk_bytes))
    clamped = min(clamped, upper_bound)

    # Align DOWN to nearest multiple of align_bytes to avoid bumping chunk size up
    if align_bytes > 1:
        aligned = (clamped // align_bytes) * align_bytes
        if aligned == 0:
            aligned = min(clamped, upper_bound)  # fallback for very small files
    else:
        aligned = clamped

    # Final safety checks
    aligned = max(1, min(aligned, upper_bound, size))

    print("Chosen split size:", aligned)
    return int(aligned)

def main():
    parser = argparse.ArgumentParser(description="Split files into encrypted chunks and reassemble them")
    parser.add_argument("--input", "-i", default="Test Files/vov.pdf", help="Input file to split")
    parser.add_argument("--output-dir", "-o", default="Test Chunks", help="Output directory for chunks")
    parser.add_argument("--reconstruct", "-r", help="Reconstruct file from chunks (specify output file)")
    parser.add_argument("--passphrase", "-p", help="Passphrase for encryption/decryption")
    parser.add_argument("--chunk-size", "-c", type=int, help="Chunk size in bytes")
    parser.add_argument("--target-chunks", "-t", type=int, default=300, help="Target number of chunks")
    
    args = parser.parse_args()
    
    try:
        if args.reconstruct:
            # Reconstruct mode
            if not args.passphrase:
                args.passphrase = input("Enter passphrase for decryption (or press Enter for no encryption): ").strip()
                if not args.passphrase:
                    args.passphrase = None
            
            print(f"Reconstructing file from {args.output_dir}...")
            join_chunks(args.output_dir, args.reconstruct, args.passphrase)
            print(f"File successfully reconstructed as {args.reconstruct}!")
        else:
            # Split mode
            if not args.chunk_size:
                fileSize = choose_chunk_size_for_file(args.input, target_chunks=args.target_chunks)
            else:
                fileSize = args.chunk_size
            
            if not args.passphrase:
                args.passphrase = input("Enter passphrase for encryption (or press Enter for no encryption): ").strip()
                if not args.passphrase:
                    args.passphrase = None
                    print("Splitting file without encryption...")
                else:
                    print("Splitting file with encryption...")
            
            split_file(args.input, args.output_dir, fileSize, args.passphrase)
            print(f"File split into chunks in {args.output_dir}")
        
    except Exception as ex:
        print(f"Error: {ex}", file=sys.stderr); sys.exit(2)

if __name__ == "__main__":
    main()