"""
Planner Agent — decomposes the user input into a retrieval plan.

The Planner is the first agent in the pipeline. It reads the raw input,
figures out what type of query it is, extracts any CVE IDs mentioned,
and decides what subtasks the Retriever needs to run.

It does NOT retrieve anything itself — it only plans.
The cleaner the plan, the better the retrieval.
"""

import os
import sys
import re
import json

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from src.config import LLM_MODEL, LLM_TEMPERATURE, GROQ_API_KEY
from src.agents.state import ThreatAnalysisState


# ─────────────────────────────────────────────────────────────
# CVE ID extraction (no LLM needed — simple regex)
# ─────────────────────────────────────────────────────────────

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def extract_cve_ids(text: str) -> list:
    """Extract all CVE IDs from the input text using regex."""
    found = CVE_PATTERN.findall(text)
    # Normalise to uppercase
    return list({cve.upper() for cve in found})


# ─────────────────────────────────────────────────────────────
# Input classification (rule-based first, LLM as fallback)
# ─────────────────────────────────────────────────────────────

def classify_input(text: str) -> str:
    """
    Classify the user input into one of three types:
      cve_id      → input contains one or more CVE IDs
      report_text → input is a raw threat report / advisory paste
      stack_query → input asks about a specific tech stack's exposure
    """
    cve_ids = extract_cve_ids(text)
    if cve_ids:
        return "cve_id"

    # Stack query keywords
    stack_keywords = [
        "are we affected", "do we need to patch", "running", "using",
        "our environment", "our stack", "we use", "we run",
        "should we patch", "impacts us", "affects us",
    ]
    text_lower = text.lower()
    if any(kw in text_lower for kw in stack_keywords):
        return "stack_query"

    # Default: treat as raw report/advisory text
    return "report_text"


# ─────────────────────────────────────────────────────────────
# Planner LLM call
# ─────────────────────────────────────────────────────────────

PLANNER_SYSTEM_PROMPT = """You are the Planner agent in a cybersecurity threat intelligence system.
Your job is to read the user's input and create a structured retrieval plan.

You must respond with ONLY valid JSON — no explanation, no markdown, no preamble.

Output format:
{
  "input_type": "cve_id" | "report_text" | "stack_query",
  "extracted_cve_ids": ["CVE-XXXX-XXXXX", ...],
  "subtasks": [
    "get overview and description for <CVE or topic>",
    "find affected products and versions",
    "retrieve CVSS severity details",
    "find ATT&CK technique mapping",
    "get available patches and mitigations"
  ],
  "attack_techniques": ["T1190", "T1059"]
}

Rules:
- extracted_cve_ids: list of CVE IDs found in the input, empty list if none
- subtasks: 3 to 5 specific retrieval tasks based on what the user needs
- attack_techniques: list of likely ATT&CK technique IDs if identifiable, empty list if unknown
- Keep subtasks concrete and searchable — they become retrieval queries
"""


def run_planner(state: ThreatAnalysisState) -> ThreatAnalysisState:
    """
    Planner agent node for LangGraph.
    Reads raw_input, returns updated state with planning fields filled in.
    """
    from groq import Groq

    raw_input  = state["raw_input"]
    cve_ids    = extract_cve_ids(raw_input)
    input_type = classify_input(raw_input)

    # For simple CVE ID queries we can generate subtasks without an LLM call
    # This saves tokens and is faster for the common case
    if input_type == "cve_id" and cve_ids:
        cve_str  = ", ".join(cve_ids)
        subtasks = [
            f"get overview and severity for {cve_str}",
            f"find affected products and versions for {cve_str}",
            f"get CVSS score details for {cve_str}",
            f"find patches and mitigations for {cve_str}",
            f"find ATT&CK technique mapping for {cve_str}",
        ]
        return {
            **state,
            "input_type":        input_type,
            "extracted_cve_ids": cve_ids,
            "subtasks":          subtasks,
            "attack_techniques": [],   # Analyzer will fill this in
        }

    # For report_text and stack_query: use LLM to generate a richer plan
    try:
        client   = Groq(api_key=GROQ_API_KEY)
        response = client.chat.completions.create(
            model=LLM_MODEL,
            temperature=LLM_TEMPERATURE,
            messages=[
                {"role": "system", "content": PLANNER_SYSTEM_PROMPT},
                {"role": "user",   "content": f"Plan the analysis for this input:\n\n{raw_input}"},
            ],
            max_tokens=500,
        )

        content = response.choices[0].message.content.strip()

        # Strip markdown code fences if present
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
        content = content.strip()

        plan = json.loads(content)

        return {
            **state,
            "input_type":        plan.get("input_type", input_type),
            "extracted_cve_ids": plan.get("extracted_cve_ids", cve_ids),
            "subtasks":          plan.get("subtasks", []),
            "attack_techniques": plan.get("attack_techniques", []),
        }

    except Exception as e:
        # Fallback: use rule-based plan if LLM fails
        print(f"[Planner] LLM call failed ({e}) — using rule-based fallback")
        return {
            **state,
            "input_type":        input_type,
            "extracted_cve_ids": cve_ids,
            "subtasks":          [raw_input],   # use raw input as single retrieval query
            "attack_techniques": [],
        }


if __name__ == "__main__":
    from src.agents.state import create_initial_state

    test_inputs = [
        "CVE-2024-21762",
        "Analyze the recent Palo Alto PAN-OS command injection vulnerability CVE-2024-3400",
        "We are running FortiOS 7.2 on our VPN gateway — are we at risk?",
        "There has been a critical zero-day in network appliances allowing remote code execution without authentication",
    ]

    for test_input in test_inputs:
        print(f"\n{'='*60}")
        print(f"Input: {test_input}")
        state  = create_initial_state(test_input)
        result = run_planner(state)
        print(f"Type:       {result['input_type']}")
        print(f"CVE IDs:    {result['extracted_cve_ids']}")
        print(f"Subtasks:   {result['subtasks']}")
        print(f"Techniques: {result['attack_techniques']}")