import uuid
from qdrant_client import QdrantClient
from qdrant_client.http.models import VectorParams, Distance, PointStruct
from sentence_transformers import SentenceTransformer

class Qdrant:

    def __init__(self):
        self.client = QdrantClient(host="127.0.0.1", port=6333)        
        self.clip_model = SentenceTransformer("clip-ViT-B-32")  # 384-dim
        # self.client.recreate_collection(
        #     collection_name="files",
        #     vectors_config=VectorParams(size=512, distance=Distance.COSINE),
        # )

    def insert(self, vec_payload_list):
        """
        vec_payload_list: List of tuples (vector, payload) 
                          e.g. from embed_file_content()
        """
        points = []
        for vec, payload in vec_payload_list:
            points.append(
                PointStruct(
                    id=str(uuid.uuid4()),
                    vector=vec,
                    payload=payload
                )
            )

        self.client.upsert(collection_name="files", points=points)

    def search(self, query):
        qvec = self.clip_model.encode([query], normalize_embeddings=True)[0].tolist()
        hits = self.client.search(collection_name="files", query_vector=qvec, limit=10)
        return hits
