from qdrant_client import QdrantClient
from qdrant_client.http.models import VectorParams, Distance, PointStruct
from sentence_transformers import SentenceTransformer

print("first line")

# 1. Connect to local Qdrant
client = QdrantClient(host="127.0.0.1", port=6333)

# 2. Use a text embedding model
model = SentenceTransformer("all-MiniLM-L6-v2")  # 384-dim

print("Above creation")

# 3. Create (or reset) a collection
client.recreate_collection(
    collection_name="demo",
    vectors_config=VectorParams(size=384, distance=Distance.COSINE),
)

print("Below creation")

# 4. Insert one text
text = "Qdrant is a vector database running locally on Windows"
vec = model.encode([text], normalize_embeddings=True)[0].tolist()

client.upsert(
    collection_name="demo",
    points=[PointStruct(id=1, vector=vec, payload={"text": text})],
)

print("[✓] Inserted text into Qdrant.")

# 5. Query with another sentence
query = "What is Qdrant?"
qvec = model.encode([query], normalize_embeddings=True)[0].tolist()

hits = client.search(collection_name="demo", query_vector=qvec, limit=1)

print("\nSearch result:")
for h in hits:
    print(f"score={h.score:.3f} | payload={h.payload}")
