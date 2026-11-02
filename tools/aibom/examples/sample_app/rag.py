from sentence_transformers import SentenceTransformer
import chromadb

embedder = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
db = chromadb.PersistentClient(path="./db")
