"""
ThreatSight Agent State — shared state flowing through the LangGraph pipeline.

Every agent reads from this state and writes back to it.
LangGraph manages the flow — nothing gets lost between nodes.

Think of it like a baton in a relay race:
  Planner fills in the plan
  Retriever fills in the chunks
  Analyzer fills in the correlation notes
  Executor fills in the draft assessment
  Critic scores it and either passes or triggers a retry
  Guardrail does final safety checks
  Output goes to the user
"""

from typing import TypedDict, Optional


class ThreatAnalysisState(TypedDict):
    """
    Complete state object for one threat analysis run.
    Every field starts as None and gets populated by the relevant agent.
    """

    # ── INPUT ──────────────────────────────────────────────────────────
    # What the user typed — could be a CVE ID, raw report text, or question
    raw_input: str

    # Classified input type — set by Planner
    # "cve_id"      → user gave a specific CVE like "CVE-2024-21762"
    # "report_text" → user pasted a raw threat report
    # "stack_query" → user asked "are we affected given we run X"
    input_type: Optional[str]

    # ── PLANNER OUTPUT ─────────────────────────────────────────────────
    # List of subtasks the Planner decided need to be retrieved
    # e.g. ["get CVE overview", "get affected products", "find ATT&CK mapping"]
    subtasks: Optional[list]

    # CVE IDs extracted from the input (may be empty if input is a general question)
    extracted_cve_ids: Optional[list]

    # ATT&CK technique IDs the Planner identified as relevant
    # e.g. ["T1190", "T1059"] — filled in later by Analyzer if not in input
    attack_techniques: Optional[list]

    # ── RETRIEVER OUTPUT ───────────────────────────────────────────────
    # The actual retrieved chunks from hybrid search
    # Each chunk is a dict with: chunk_id, text, chunk_type, cve_id,
    #                             severity, base_score, rrf_score, final_rank
    retrieved_chunks: Optional[list]

    # ── ANALYZER OUTPUT ────────────────────────────────────────────────
    # Cross-source reasoning written by the Analyzer agent
    # e.g. "CVE maps to T1190 based on network vector and unauthenticated access"
    correlation_notes: Optional[str]

    # Severity context determined by Analyzer — not just raw CVSS but
    # what it means for the described environment
    severity_context: Optional[str]

    # ── EXECUTOR OUTPUT ────────────────────────────────────────────────
    # Full written assessment — this is what the user ultimately reads
    draft_assessment: Optional[str]

    # Structured citations — list of dicts with chunk_id and relevant quote
    citations: Optional[list]

    # ── CRITIC OUTPUT ──────────────────────────────────────────────────
    # RAGAS faithfulness score — 0.0 to 1.0
    # Measures: are all claims in draft_assessment grounded in retrieved_chunks?
    faithfulness_score: Optional[float]

    # True if the critic found ungrounded claims that need fixing
    revision_needed: Optional[bool]

    # Specific feedback from critic about what to fix
    # e.g. "Claim about patch availability not found in retrieved context"
    revision_feedback: Optional[str]

    # How many times the executor has been asked to revise (max 3)
    revision_count: Optional[int]

    # ── GUARDRAIL OUTPUT ───────────────────────────────────────────────
    # True if output touches safety-critical content needing human review
    safety_flag: Optional[bool]

    # Reason for safety flag if set
    safety_reason: Optional[str]

    # ── FINAL OUTPUT ───────────────────────────────────────────────────
    # The polished, verified assessment ready for the analyst
    final_assessment: Optional[str]

    # Final faithfulness score (from the last critic pass that passed)
    final_faithfulness_score: Optional[float]

    # Error message if something went wrong at any stage
    error: Optional[str]


def create_initial_state(user_input: str) -> ThreatAnalysisState:
    """
    Create a fresh state object for a new analysis run.
    All optional fields start as None — agents fill them in as they run.
    """
    return ThreatAnalysisState(
        raw_input=user_input,
        input_type=None,
        subtasks=None,
        extracted_cve_ids=None,
        attack_techniques=None,
        retrieved_chunks=None,
        correlation_notes=None,
        severity_context=None,
        draft_assessment=None,
        citations=None,
        faithfulness_score=None,
        revision_needed=None,
        revision_feedback=None,
        revision_count=0,
        safety_flag=None,
        safety_reason=None,
        final_assessment=None,
        final_faithfulness_score=None,
        error=None,
    )


if __name__ == "__main__":
    # Quick sanity check — state creates and all keys are accessible
    state = create_initial_state("CVE-2024-21762")

    print("State created successfully")
    print(f"raw_input:     {state['raw_input']}")
    print(f"revision_count: {state['revision_count']}")
    print(f"All other fields None: {all(state[k] is None for k in state if k not in ('raw_input', 'revision_count'))}")
    print(f"\nAll state keys: {list(state.keys())}")