from qdrant_client import QdrantClient

# Connect to Qdrant
client = QdrantClient(host="127.0.0.1", port=6333)

# Get list of all collection names
collections = client.get_collections().collections

# Delete each collection
for collection in collections:
    print(f"Deleting collection: {collection.name}")
    client.delete_collection(collection.name)

print("✅ All collections deleted.")
