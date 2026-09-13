"""
Retriever Agent — runs hybrid search and attaches chunks to state.

FIX: when the user's query contains explicit CVE IDs, we now guarantee
ALL chunks for those CVEs are included directly (exact filter lookup),
not left to probabilistic RRF ranking across 6 separate queries.

This matters because: if someone asks about CVE-2026-21385 specifically,
the report should never be missing that CVE's own affected_products or
cvss chunk just because a different CVE scored higher in semantic search.
Direct ID lookup must be deterministic, not best-effort.
"""

import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from src.agents.state import ThreatAnalysisState
from src.retrieval.retriever import HybridRetriever
from src.config import TOP_K_FINAL


_retriever: HybridRetriever | None = None


def get_retriever() -> HybridRetriever:
    global _retriever
    if _retriever is None:
        _retriever = HybridRetriever()
    return _retriever


def get_all_chunks_for_cve(retriever: HybridRetriever, cve_id: str) -> list:
    """
    Exact lookup: return ALL chunks belonging to a specific CVE ID,
    regardless of semantic/keyword ranking. This guarantees completeness
    for direct CVE queries — the overview, affected_products, cvss,
    kev (if present), and references chunks are ALL included.
    """
    matches = [
        chunk for chunk in retriever.chunks
        if chunk.get("metadata", {}).get("cve_id", "").upper() == cve_id.upper()
    ]
    # Tag these as exact matches with a high synthetic rrf_score so they
    # always sort to the top when merged with hybrid search results
    for chunk in matches:
        chunk = dict(chunk)  # avoid mutating the underlying index
    results = []
    for chunk in matches:
        results.append({
            "chunk_id":   chunk["chunk_id"],
            "text":       chunk["text"],
            "chunk_type": chunk.get("chunk_type", ""),
            "cve_id":     chunk.get("metadata", {}).get("cve_id", ""),
            "severity":   chunk.get("metadata", {}).get("severity", ""),
            "base_score": chunk.get("metadata", {}).get("base_score", "N/A"),
            "published":  chunk.get("metadata", {}).get("published", ""),
            "source":     "exact_id_match",
            "rrf_score":  1.0,   # forces top rank — exact ID match beats any semantic score
            "metadata":   chunk.get("metadata", {}),
        })
    return results


def run_retriever_agent(state: ThreatAnalysisState) -> ThreatAnalysisState:
    """
    Retriever agent node for LangGraph.

    Strategy:
    1. If extracted_cve_ids exist — exact-fetch ALL chunks for those CVEs first.
       This guarantees the report never has gaps for the CVE the user actually asked about.
    2. Run subtask queries through hybrid search for supplementary context
       (broader correlation, similar CVEs, general technique mapping).
    3. Merge: exact CVE matches always rank first, hybrid results fill in the rest.
    4. Deduplicate by chunk_id, cap at a reasonable total.
    """
    retriever  = get_retriever()
    subtasks   = state.get("subtasks") or []
    raw_input  = state["raw_input"]
    cve_ids    = state.get("extracted_cve_ids") or []

    all_chunks = {}   # chunk_id -> chunk dict

    # ── Step 1: Exact fetch for any CVE IDs mentioned ─────────────────
    if cve_ids:
        print(f"[Retriever Agent] Exact-fetching all chunks for: {cve_ids}")
        for cve_id in cve_ids:
            exact_chunks = get_all_chunks_for_cve(retriever, cve_id)
            for chunk in exact_chunks:
                all_chunks[chunk["chunk_id"]] = chunk
            print(f"  {cve_id}: {len(exact_chunks)} chunks found directly")

    # ── Step 2: Hybrid search for broader context ─────────────────────
    queries = list(subtasks)
    if raw_input not in queries:
        queries.append(raw_input)

    print(f"[Retriever Agent] Running {len(queries)} hybrid search queries...")
    for query in queries:
        try:
            hits = retriever.retrieve(query, top_k_final=TOP_K_FINAL)
            for chunk in hits:
                cid = chunk["chunk_id"]
                # Don't overwrite exact matches — they're already correct and ranked first
                if cid not in all_chunks:
                    all_chunks[cid] = chunk
        except Exception as e:
            print(f"[Retriever Agent] Query failed: '{query}' — {e}")

    # ── Step 3: Sort — exact matches (rrf_score=1.0) always first ─────
    top_chunks = sorted(
        all_chunks.values(),
        key=lambda x: x.get("rrf_score", 0),
        reverse=True,
    )[:TOP_K_FINAL * 2]

    for i, chunk in enumerate(top_chunks, start=1):
        chunk["final_rank"] = i

    print(f"[Retriever Agent] Final: {len(top_chunks)} unique chunks")
    for c in top_chunks[:6]:
        tag = "[EXACT]" if c.get("source") == "exact_id_match" else "[hybrid]"
        print(f"  {tag} [{c['final_rank']}] {c['chunk_id']} (score={c.get('rrf_score', 0):.4f})")

    if not top_chunks:
        return {
            **state,
            "retrieved_chunks": [],
            "error": "No relevant chunks found in the corpus. The CVE may not be in the indexed date range.",
        }

    return {
        **state,
        "retrieved_chunks": top_chunks,
    }


if __name__ == "__main__":
    from src.agents.state import create_initial_state
    from src.agents.planner import run_planner

    test_inputs = [
        "CVE-2026-21385",   # the KEV CVE — should now get ALL its own chunks
        "critical remote code execution in network appliance",
    ]

    for test_input in test_inputs:
        print(f"\n{'='*60}")
        print(f"Input: {test_input}")

        state = create_initial_state(test_input)
        state = run_planner(state)
        state = run_retriever_agent(state)

        chunks = state["retrieved_chunks"]
        print(f"\nTotal chunks retrieved: {len(chunks)}")
        for c in chunks[:8]:
            print(f"  [{c['final_rank']}] {c['chunk_id']} | {c.get('source', 'hybrid')}")