from pathlib import Path
from PyPDF2 import PdfReader
from typing import Union
from sentence_transformers import SentenceTransformer
import hashlib
from typing import List, Tuple, Union
from PIL import Image

def read_file_content(path: Union[str, Path]) -> str:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"[!] File not found: {path}")
    
    ext = path.suffix.lower()
    
    if ext == ".txt":
        return path.read_text(encoding="utf-8", errors="ignore")
    
    elif ext == ".pdf":
        text = []
        with open(path, "rb") as f:
            pdf = PdfReader(f)
            for page in pdf.pages:
                text.append(page.extract_text())
        return "\n".join(text).strip()
    
    elif ext in [".png", ".jpg", ".jpeg"]:
        return "IMAGE"
    
    else:
        raise ValueError(f"[!] Unsupported file type: {ext}")

text_model = SentenceTransformer("all-MiniLM-L6-v2")
img_model = SentenceTransformer("clip-ViT-B-32")

def chunk_text(text: str, size: int = 800, overlap: int = 100) -> List[str]:
    if not text: return []
    out, i, n = [], 0, len(text)
    while i < n:
        out.append(text[i:i+size])
        i += size - overlap
    return out

def embed_file_content(file_path: str) -> List[Tuple[List[float], dict]]:
    file_path = Path(file_path)
    raw = read_file_content(file_path)
    results = []
    if raw == "IMAGE":
        img = Image.open(file_path).convert("RGB")
        vec = img_model.encode([img], normalize_embeddings=True)[0].tolist()
        payload = {
            "filename": file_path.name,
            "path": str(file_path),
            "type": "image"
        }
        results.append((vec, payload))
    elif isinstance(raw, str):
        chunks = chunk_text(raw)
        embeds = text_model.encode(chunks, normalize_embeddings=True)
        for i, (chunk, vec) in enumerate(zip(chunks, embeds)):
            payload = {
                "filename": file_path.name,
                "path": str(file_path),
                "type": "text",
                "chunk_index": i,
                "chunk": chunk[:512]  # cap for readability
            }
            results.append((vec.tolist(), payload))
    else:
        raise ValueError(f"Unsupported content: {file_path}")
    return results

if __name__ == "__main__":
    test_paths = [
        r"C:\Intellivault\test.txt",
        r"C:\Intellivault\test_image.jpg",
        r"C:\Intellivault\sample_pdf.pdf"
    ]
    for path in test_paths:
        try:
            print(f"\n== Reading: {path}")
            result = embed_file_content(path)
            print(result)
        except Exception as e:
            print("Error:", e)
