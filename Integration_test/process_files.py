from pathlib import Path
from PyPDF2 import PdfReader
from typing import Union
from sentence_transformers import SentenceTransformer
from transformers import pipeline
from typing import List, Tuple, Union
from qdrant_utils import Qdrant
from PIL import Image
import torch

class FileProcessor:

    def __init__(self):
        self.text_model = SentenceTransformer("all-MiniLM-L12-v2")
        self.img_model = SentenceTransformer("clip-ViT-B-32")
        self.clip_model = SentenceTransformer("clip-ViT-B-32")
        device = torch.device("cpu")
        self.summarizer = pipeline("summarization", model="facebook/bart-large-cnn", device=-1)
        self.qdrant = Qdrant()

    def read_file_content(self, path: Union[str, Path]) -> str:
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

    def embed_file_content(self, file_path: str) -> List[Tuple[List[float], dict]]:
        file_path = Path(file_path)
        raw = self.read_file_content(file_path)
        results = []
        if raw == "IMAGE":
            img = Image.open(file_path).convert("RGB")
            vec = self.clip_model.encode([img], normalize_embeddings=True)[0].tolist()
            payload = {
                "filename": file_path.name,
                "path": str(file_path),
                "type": "image"
            }
            results.append((vec, payload))
        elif isinstance(raw, str):
            summary = self.summarizer(raw[:1000], max_length=60, min_length=30, do_sample=False)
            vec = self.clip_model.encode([summary[0]['summary_text']], normalize_embeddings=True)[0].tolist()
            payload = {
                "filename": file_path.name,
                "path": str(file_path),
                "type": "text",
                "context": summary[0]['summary_text']
            }
            results.append((vec, payload))
        else:
            raise ValueError(f"Unsupported content: {file_path}")
        self.qdrant.insert(results)

