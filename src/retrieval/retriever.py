"""
ThreatSight Hybrid Retriever — dense + sparse search with RRF fusion.

Why hybrid?
-----------
Dense search (Qdrant):  finds chunks by meaning.
Sparse search (BM25):   finds chunks by exact keywords.
Neither alone is enough. Hybrid + RRF gets the best of both.

RRF formula (Cormack, Clarke & Buettcher 2009):
  score(chunk) = sum of  1 / (k + rank_in_ranker)  across all rankers
  k = 60  (standard smoothing constant)
"""

import os
import sys
import pickle
import numpy as np
from typing import Optional

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from src.config import (
    QDRANT_PATH, QDRANT_COLLECTION,
    EMBEDDING_DIMENSION, PROCESSED_DIR,
    TOP_K_DENSE, TOP_K_SPARSE, TOP_K_FINAL,
)


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
                print("Retriever: loading real SentenceTransformer...")
                return SentenceTransformer("all-MiniLM-L6-v2")
    except Exception as e:
        print(f"Retriever: embedder check failed: {e}")
    print("Retriever: using MockEmbedder")
    return MockEmbedder()


def embed_query(embedder, text: str) -> list:
    enc = embedder.encode(text)
    arr = np.asarray(enc, dtype=np.float32)
    if arr.ndim == 2:
        arr = arr[0]
    return arr.tolist()


def dense_search(query: str, embedder, client, top_k: int = TOP_K_DENSE) -> list:
    query_vector = embed_query(embedder, query)
    results = client.query_points(
        collection_name=QDRANT_COLLECTION,
        query=query_vector,
        limit=top_k,
        with_payload=True,
    ).points

    hits = []
    for rank, point in enumerate(results, start=1):
        payload = point.payload
        hits.append({
            "chunk_id":   payload.get("chunk_id", ""),
            "text":       payload.get("text", ""),
            "chunk_type": payload.get("chunk_type", ""),
            "cve_id":     payload.get("cve_id", ""),
            "severity":   payload.get("severity", ""),
            "base_score": payload.get("base_score", "N/A"),
            "published":  payload.get("published", ""),
            "source":     "dense",
            "score":      point.score,
            "rank":       rank,
        })
    return hits


def sparse_search(query: str, bm25, chunks: list, top_k: int = TOP_K_SPARSE) -> list:
    query_tokens = query.lower().split()
    scores       = bm25.get_scores(query_tokens)
    top_indices  = scores.argsort()[-top_k:][::-1]

    hits = []
    for rank, idx in enumerate(top_indices, start=1):
        chunk = chunks[idx]
        meta  = chunk.get("metadata", {})
        hits.append({
            "chunk_id":   chunk["chunk_id"],
            "text":       chunk["text"],
            "chunk_type": chunk.get("chunk_type", ""),
            "cve_id":     meta.get("cve_id", ""),
            "severity":   meta.get("severity", ""),
            "base_score": meta.get("base_score", "N/A"),
            "published":  meta.get("published", ""),
            "source":     "sparse",
            "score":      float(scores[idx]),
            "rank":       rank,
        })
    return hits


def reciprocal_rank_fusion(
    dense_hits:  list,
    sparse_hits: list,
    k:           int = 60,
    top_k_final: int = TOP_K_FINAL,
) -> list:
    rrf_scores = {}
    chunk_data = {}

    for hit in dense_hits:
        cid = hit["chunk_id"]
        rrf_scores[cid] = rrf_scores.get(cid, 0.0) + 1.0 / (k + hit["rank"])
        if cid not in chunk_data:
            chunk_data[cid] = hit

    for hit in sparse_hits:
        cid = hit["chunk_id"]
        rrf_scores[cid] = rrf_scores.get(cid, 0.0) + 1.0 / (k + hit["rank"])
        if cid not in chunk_data:
            chunk_data[cid] = hit

    sorted_ids = sorted(rrf_scores, key=lambda x: rrf_scores[x], reverse=True)
    top_ids    = sorted_ids[:top_k_final]

    results = []
    for final_rank, cid in enumerate(top_ids, start=1):
        chunk = chunk_data[cid].copy()
        chunk["rrf_score"]  = round(rrf_scores[cid], 6)
        chunk["final_rank"] = final_rank
        results.append(chunk)

    return results


class HybridRetriever:
    """
    Single interface for hybrid retrieval.
    Agents call retrieve(query) and get top-k grounded chunks.
    """

    def __init__(self):
        print("Initialising HybridRetriever...")

        self.embedder = get_embedder()

        from qdrant_client import QdrantClient
        self.qdrant_client = QdrantClient(path=QDRANT_PATH)
        existing = [c.name for c in self.qdrant_client.get_collections().collections]
        if QDRANT_COLLECTION not in existing:
            raise RuntimeError(
                f"Qdrant collection '{QDRANT_COLLECTION}' not found. "
                "Run src/corpus/indexer.py first."
            )
        print(f"  Qdrant: collection '{QDRANT_COLLECTION}' ready")

        bm25_path = os.path.join(PROCESSED_DIR, "bm25_index.pkl")
        if not os.path.exists(bm25_path):
            raise RuntimeError(
                f"BM25 index not found at {bm25_path}. "
                "Run src/corpus/indexer.py first."
            )
        with open(bm25_path, "rb") as f:
            data = pickle.load(f)
        self.bm25   = data["bm25"]
        self.chunks = data["chunks"]
        print(f"  BM25: {len(self.chunks)} documents ready")
        print("HybridRetriever ready.\n")

    def retrieve(
        self,
        query:       str,
        top_k_final: int  = TOP_K_FINAL,
        verbose:     bool = False,
    ) -> list:
        if verbose:
            print(f"\n[Retriever] Query: '{query}'")

        dense_hits  = dense_search(query, self.embedder, self.qdrant_client, TOP_K_DENSE)
        sparse_hits = sparse_search(query, self.bm25, self.chunks, TOP_K_SPARSE)

        if verbose:
            print(f"  Dense top-3:")
            for h in dense_hits[:3]:
                print(f"    rank {h['rank']} | score {h['score']:.4f} | {h['chunk_id']}")
            print(f"  Sparse top-3:")
            for h in sparse_hits[:3]:
                print(f"    rank {h['rank']} | score {h['score']:.4f} | {h['chunk_id']}")

        fused = reciprocal_rank_fusion(dense_hits, sparse_hits, top_k_final=top_k_final)

        if verbose:
            print(f"  Fused top-{len(fused)}:")
            for h in fused:
                print(f"    final_rank {h['final_rank']} | rrf {h['rrf_score']:.6f} | {h['chunk_id']}")

        return fused

    def format_context(self, chunks: list) -> str:
        if not chunks:
            return "No relevant context found."
        parts = []
        for chunk in chunks:
            header = (
                f"[SOURCE {chunk['final_rank']}] "
                f"{chunk['chunk_id']} "
                f"(RRF score: {chunk['rrf_score']:.4f})"
            )
            parts.append(f"{header}\n{chunk['text']}")
        return "\n\n" + ("\n\n" + "─" * 60 + "\n\n").join(parts)


if __name__ == "__main__":
    print("=" * 60)
    print("ThreatSight Hybrid Retriever — Test")
    print("=" * 60)

    retriever = HybridRetriever()

    print("\n--- Test 1: Exact CVE ID ---")
    chunks = retriever.retrieve("CVE-2024-21762", verbose=True)
    print(f"\nTop result: {chunks[0]['chunk_id']}")

    print("\n--- Test 2: Semantic query ---")
    chunks = retriever.retrieve(
        "critical vulnerability in network appliance remote code execution",
        verbose=True,
    )
    print(f"\nTop result: {chunks[0]['chunk_id']}")

    print("\n--- Test 3: Formatted context ---")
    context = retriever.format_context(chunks[:2])
    print(context[:500])

    print("\nRetriever test complete")