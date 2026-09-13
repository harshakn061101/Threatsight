"""
Indexer — builds Qdrant + BM25 indexes from NVD + CISA KEV data.
"""

import os
import sys
import pickle
import numpy as np

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.config import QDRANT_PATH, QDRANT_COLLECTION, EMBEDDING_DIMENSION, PROCESSED_DIR


class MockEmbedder:
    def encode(self, texts, show_progress_bar=False):
        single = isinstance(texts, str)
        if single:
            texts = [texts]
        vectors = []
        for text in texts:
            np.random.seed(hash(text) % (2**32))
            vectors.append(np.random.rand(EMBEDDING_DIMENSION).astype(np.float32))
        arr = np.array(vectors)
        return arr[0] if single else arr


def get_embedder():
    try:
        cache_dir = os.path.expanduser("~/.cache/huggingface/hub")
        if os.path.exists(cache_dir):
            cached = os.listdir(cache_dir)
            if any("MiniLM" in d or "minilm" in d.lower() for d in cached):
                from sentence_transformers import SentenceTransformer
                print("Loading real SentenceTransformer embedder...")
                return SentenceTransformer("all-MiniLM-L6-v2")
    except Exception as e:
        print(f"Embedder check failed: {e}")
    print("Using MockEmbedder")
    return MockEmbedder()


def embed_query(embedder, text: str) -> list:
    enc = embedder.encode(text)
    arr = np.asarray(enc, dtype=np.float32)
    if arr.ndim == 2:
        arr = arr[0]
    return arr.tolist()


def build_qdrant_index(chunks: list, embedder) -> object:
    from qdrant_client import QdrantClient
    from qdrant_client.models import Distance, VectorParams, PointStruct

    os.makedirs(QDRANT_PATH, exist_ok=True)
    client   = QdrantClient(path=QDRANT_PATH)
    existing = [c.name for c in client.get_collections().collections]
    if QDRANT_COLLECTION in existing:
        client.delete_collection(QDRANT_COLLECTION)
        print("Deleted existing collection (clean rebuild)")

    client.create_collection(
        collection_name=QDRANT_COLLECTION,
        vectors_config=VectorParams(size=EMBEDDING_DIMENSION, distance=Distance.COSINE),
    )
    print(f"Created collection: {QDRANT_COLLECTION}")

    if not chunks:
        return client

    BATCH_SIZE = 100
    total = 0
    for start in range(0, len(chunks), BATCH_SIZE):
        batch   = chunks[start : start + BATCH_SIZE]
        texts   = [c["text"] for c in batch]
        vectors = np.asarray(embedder.encode(texts), dtype=np.float32)
        if vectors.ndim == 1:
            vectors = vectors.reshape(1, -1)

        points = []
        for i, (chunk, vector) in enumerate(zip(batch, vectors)):
            points.append(PointStruct(
                id=start + i,
                vector=vector.tolist(),
                payload={
                    "chunk_id":           chunk["chunk_id"],
                    "text":               chunk["text"],
                    "chunk_type":         chunk["chunk_type"],
                    "actively_exploited": chunk["metadata"].get("actively_exploited", False),
                    **chunk["metadata"],
                },
            ))
        client.upsert(collection_name=QDRANT_COLLECTION, points=points)
        total += len(batch)
        if total % 500 == 0 or total == len(chunks):
            print(f"  Indexed {total}/{len(chunks)} chunks")

    print(f"Qdrant index complete: {total} chunks")
    return client


def build_bm25_index(chunks: list) -> tuple:
    from rank_bm25 import BM25Okapi
    if not chunks:
        return None, []
    print("Building BM25 index...")
    tokenized = [c["text"].lower().split() for c in chunks]
    bm25      = BM25Okapi(tokenized)
    print(f"BM25 index complete: {len(chunks)} documents")
    return bm25, tokenized


def save_bm25_index(bm25, chunks: list, filename: str = "bm25_index.pkl") -> str:
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    fp = os.path.join(PROCESSED_DIR, filename)
    with open(fp, "wb") as f:
        pickle.dump({"bm25": bm25, "chunks": chunks}, f)
    print(f"BM25 index saved to {fp}")
    return fp


def load_bm25_index(filename: str = "bm25_index.pkl"):
    fp = os.path.join(PROCESSED_DIR, filename)
    if not os.path.exists(fp):
        return None, None
    with open(fp, "rb") as f:
        data = pickle.load(f)
    print(f"BM25 index loaded: {len(data['chunks'])} documents")
    return data["bm25"], data["chunks"]


def build_full_index(chunks: list) -> None:
    if not chunks:
        print("No chunks — skipping.")
        return
    print(f"\nBuilding indexes for {len(chunks)} chunks...")
    embedder = get_embedder()
    print("\n[1/2] Building Qdrant dense index...")
    build_qdrant_index(chunks, embedder)
    print("\n[2/2] Building BM25 sparse index...")
    bm25, _ = build_bm25_index(chunks)
    if bm25:
        save_bm25_index(bm25, chunks)
    print("\n✓ Both indexes built and saved")


if __name__ == "__main__":
    from src.corpus.nvd_fetcher import (
        fetch_recent_cves, save_raw_cves, load_raw_cves,
        fetch_cisa_kev, save_kev, load_kev,
    )
    from src.corpus.chunker import process_cve_list, save_chunks, load_chunks

    # ── Step 1: CISA KEV (download or load from cache) ───────────────
    kev_path = os.path.join("data", "raw", "cisa_kev.json")
    if os.path.exists(kev_path):
        kev_lookup = load_kev()
    else:
        kev_lookup = fetch_cisa_kev()
        if kev_lookup:
            save_kev(kev_lookup)

    # ── Step 2: NVD CVEs (download or load from cache) ───────────────
    raw_path = os.path.join("data", "raw", "nvd_raw.json")
    if os.path.exists(raw_path):
        print(f"Found cached CVEs — loading...")
        raw_cves = load_raw_cves()
    else:
        print("Fetching 500 recent CVEs from NVD...")
        raw_cves = fetch_recent_cves(days_back=120, max_cves=500)
        if raw_cves:
            save_raw_cves(raw_cves)
        else:
            print("NVD fetch failed.")
            exit(1)

    print(f"\nTotal CVEs: {len(raw_cves)}")

    # ── Step 3: Chunk (with KEV enrichment) ──────────────────────────
    chunks_path = os.path.join("data", "processed", "cve_chunks.json")
    # Always rebuild chunks when indexer runs — ensures KEV data is fresh
    print("Processing CVEs into chunks (with CISA KEV enrichment)...")
    all_chunks = process_cve_list(raw_cves, kev_lookup)
    save_chunks(all_chunks)

    # ── Step 4: Build indexes ─────────────────────────────────────────
    build_full_index(all_chunks)

    # ── Step 5: Verify ────────────────────────────────────────────────
    print("\n" + "="*50)
    print("Verification")
    print("="*50)

    from qdrant_client import QdrantClient
    embedder = get_embedder()
    client   = QdrantClient(path=QDRANT_PATH)

    # Check for actively exploited CVEs in the corpus
    bm25, chunks = load_bm25_index()
    kev_chunks   = [c for c in chunks if c.get("metadata", {}).get("actively_exploited")]
    print(f"\nChunks flagged as actively exploited: {len(kev_chunks)}")
    if kev_chunks:
        print("Sample KEV chunks:")
        for c in kev_chunks[:3]:
            print(f"  {c['chunk_id']}")

    # Quick BM25 test
    scores     = bm25.get_scores("actively exploited critical remote".split())
    top_idx    = scores.argsort()[-3:][::-1]
    print(f"\nBM25: 'actively exploited critical remote'")
    for idx in top_idx:
        if scores[idx] > 0:
            print(f"  {scores[idx]:.4f} | {chunks[idx]['chunk_id']}")

    print(f"\n✓ Done. Corpus: {len(all_chunks)} chunks from {len(raw_cves)} CVEs")
    kev_count = len(set(
        c["metadata"]["cve_id"]
        for c in all_chunks
        if c.get("metadata", {}).get("actively_exploited")
    ))
    print(f"  Actively exploited CVEs in corpus: {kev_count}")