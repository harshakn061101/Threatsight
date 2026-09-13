"""
Citation Validator — deterministic check that every citation in the
Executor's output actually references a chunk_id that was retrieved.

WHY THIS EXISTS:
Test 4 (natural language query, no CVE ID) revealed the Executor citing
CVE-2026-27446_cvss and CVE-2026-21385_kev — neither of which were in
the actually retrieved chunks for that query. The Critic's LLM-based
faithfulness check did not catch this, because checking "does this chunk_id
exist in retrieved_chunks" is a simple membership check, not a semantic
judgment call — and we were asking an LLM to do something code can do
perfectly and for free.

This is a hard, non-negotiable gate: if a citation references a chunk_id
not in retrieved_chunks, it is fabricated by definition, regardless of
whether the underlying fact happens to be true. This runs AFTER critic
approval and BEFORE the report ships, as a final safety net.
"""

import os
import sys
import json

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from src.agents.state import ThreatAnalysisState


def validate_citations(state: ThreatAnalysisState) -> ThreatAnalysisState:
    """
    Deterministic post-check: every citation's "source" field must match
    a chunk_id that was actually retrieved. Any citation that fails this
    is removed. If removing citations leaves claims unsupported, those
    claims are flagged in context_gaps rather than silently dropped.
    """
    draft  = state.get("draft_assessment") or ""
    chunks = state.get("retrieved_chunks") or []
    valid_chunk_ids = {c["chunk_id"] for c in chunks}

    try:
        assessment = json.loads(draft)
    except json.JSONDecodeError:
        print("[Citation Validator] Could not parse draft — skipping validation")
        return state

    citations = assessment.get("citations", [])
    valid_citations   = []
    fabricated_claims = []

    for citation in citations:
        source = citation.get("source", "")
        if source in valid_chunk_ids:
            valid_citations.append(citation)
        else:
            fabricated_claims.append(citation.get("claim", "unknown claim"))
            print(f"[Citation Validator] REMOVED fabricated citation: "
                  f"claim='{citation.get('claim', '')[:60]}' cited non-retrieved source='{source}'")

    if fabricated_claims:
        existing_gaps = assessment.get("context_gaps", "") or ""
        fabricated_note = (
            f"NOTE: {len(fabricated_claims)} claim(s) were removed because they cited "
            f"sources not actually retrieved in this analysis: {'; '.join(fabricated_claims[:3])}"
        )
        assessment["context_gaps"] = (
            f"{existing_gaps} | {fabricated_note}" if existing_gaps else fabricated_note
        )
        print(f"[Citation Validator] {len(fabricated_claims)} fabricated citation(s) stripped, "
              f"{len(valid_citations)} valid citation(s) retained")
    else:
        print(f"[Citation Validator] All {len(valid_citations)} citations verified against retrieved chunks ✓")

    assessment["citations"] = valid_citations

    return {
        **state,
        "draft_assessment": json.dumps(assessment, indent=2),
        "citations":        valid_citations,
    }


if __name__ == "__main__":
    # Quick standalone test with a fake state mimicking the Test 4 failure
    fake_state = {
        "retrieved_chunks": [
            {"chunk_id": "CVE-2026-23810_overview"},
            {"chunk_id": "CVE-2026-23812_overview"},
        ],
        "draft_assessment": json.dumps({
            "threat_id": "Multiple CVEs",
            "citations": [
                {"claim": "Real claim", "source": "CVE-2026-23810_overview"},
                {"claim": "CVE-2026-27446 has CVSS 9.8", "source": "CVE-2026-27446_cvss"},
                {"claim": "CVE-2026-21385 actively exploited", "source": "CVE-2026-21385_kev"},
            ],
            "context_gaps": "",
        }),
    }

    result = validate_citations(fake_state)
    print("\nFinal assessment after validation:")
    print(json.dumps(json.loads(result["draft_assessment"]), indent=2))
