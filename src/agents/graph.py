"""
ThreatSight LangGraph Orchestration (v2).

ADDED: citation_validator node runs deterministically after the critic
approves a report, before the run ends. This catches fabricated citations
(chunk_ids that don't exist in retrieved_chunks) that the LLM-based critic
demonstrated it can miss — see Test 4 finding: citations referencing
CVE-2026-27446_cvss and CVE-2026-21385_kev when neither was retrieved.

This is a zero-token, deterministic membership check — not another agent,
not another LLM call, just a final correctness gate before output ships.

Graph shape:

    START -> planner -> retriever -> analyzer -> executor -> critic
                                                      ^           |
                                                      |  (revise) |
                                                      +-----------+
                                                            | (pass or max retries)
                                                            v
                                                    citation_validator -> END
"""

import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.agents.state import ThreatAnalysisState, create_initial_state
from src.agents.planner import run_planner
from src.agents.retriever_agent import run_retriever_agent
from src.agents.analyzer import run_analyzer
from src.agents.executor import run_executor
from src.agents.critic import run_critic
from src.agents.citation_validator import validate_citations
from src.config import MAX_RETRIES


def should_revise(state: ThreatAnalysisState) -> str:
    """
    Conditional edge function — LangGraph calls this after the critic node
    to decide whether to loop back to the executor or proceed to final
    citation validation.
    """
    revision_count = state.get("revision_count") or 0

    if state.get("revision_needed") and revision_count <= MAX_RETRIES:
        return "revise"
    return "done"


def build_graph():
    """
    Build and compile the ThreatSight LangGraph.
    Returns a compiled graph ready to .invoke(initial_state).
    """
    from langgraph.graph import StateGraph, END

    workflow = StateGraph(ThreatAnalysisState)

    workflow.add_node("planner",            run_planner)
    workflow.add_node("retriever",          run_retriever_agent)
    workflow.add_node("analyzer",           run_analyzer)
    workflow.add_node("executor",           run_executor)
    workflow.add_node("critic",             run_critic)
    workflow.add_node("citation_validator", validate_citations)

    workflow.set_entry_point("planner")
    workflow.add_edge("planner",   "retriever")
    workflow.add_edge("retriever", "analyzer")
    workflow.add_edge("analyzer",  "executor")
    workflow.add_edge("executor",  "critic")

    workflow.add_conditional_edges(
        "critic",
        should_revise,
        {
            "revise": "executor",
            "done":   "citation_validator",
        },
    )

    # Citation validator always proceeds to END — it's a final correctness
    # gate, not part of the revision negotiation loop
    workflow.add_edge("citation_validator", END)

    return workflow.compile()


def run_threat_analysis(user_input: str, verbose: bool = True) -> ThreatAnalysisState:
    """
    Convenience function: build the graph, run it on one input, return final state.
    """
    graph         = build_graph()
    initial_state = create_initial_state(user_input)

    if verbose:
        print(f"\n{'='*60}")
        print(f"ThreatSight Analysis: {user_input}")
        print(f"{'='*60}\n")

    final_state = graph.invoke(initial_state)
    return final_state


if __name__ == "__main__":
    import json

    test_inputs = [
        "CVE-2026-21385",
        "we are seeing unusual outbound traffic from our network devices, possible exploitation attempt",
    ]

    for test_input in test_inputs:
        final_state = run_threat_analysis(test_input)

        print("\n" + "="*60)
        print("FINAL ASSESSMENT (via LangGraph + citation validation)")
        print("="*60)
        try:
            assessment = json.loads(final_state["draft_assessment"])
            print(json.dumps(assessment, indent=2))
        except Exception:
            print(final_state["draft_assessment"])

        print(f"\nFaithfulness score: {final_state.get('faithfulness_score')}")
        print(f"Revision count:     {final_state.get('revision_count')}")
        print(f"Citations (validated): {len(final_state.get('citations') or [])}")