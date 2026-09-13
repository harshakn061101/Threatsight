"""Executor Agent — writes the threat assessment."""
import os, sys, json, time
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from src.config import LLM_MODEL, LLM_TEMPERATURE, GROQ_API_KEY
from src.agents.state import ThreatAnalysisState

EXECUTOR_SYSTEM_PROMPT = """You are the Executor agent in a cybersecurity threat intelligence system.
Respond with ONLY valid JSON. No explanation, no markdown, no preamble.

{
  "threat_id": "CVE-XXXX-XXXXX",
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN",
  "cvss_score": "9.8 or N/A",
  "actively_exploited": true or false or null,
  "exploitation_note": "CONFIRMED active exploitation per CISA KEV — required action by [date], or: No active exploitation confirmed in provided context",
  "what_it_is": "2-3 sentences about the vulnerability",
  "realistic_attack_scenario": ["Step 1: ...", "Step 2: ...", "Step 3: ..."],
  "affected_systems": ["Vendor Product Version"],
  "immediate_actions": ["Priority 1 (do today): ...", "Priority 2: ...", "Priority 3: ..."],
  "attack_techniques": [{"id": "T1203", "name": "Exploitation for Client Execution", "relevance": "specific reason from context"}],
  "citations": [{"claim": "specific claim", "source": "chunk_id_from_SOURCE_labels"}],
  "confidence": "high|medium|low",
  "context_gaps": "what is missing from the provided context"
}

ATT&CK rules:
T1190 = NETWORK vector + NONE privileges (unauthenticated remote)
T1203 = LOCAL vector + memory corruption (firmware/client)
T1068 = escalating TO higher privilege — not for initial access
T1059 = post-exploitation command execution only
T1499 = denial of service only
If none fits: use []

Rules:
- actively_exploited true ONLY if _kev chunk in [SOURCE] labels below
- citations source: ONLY chunk_ids in [SOURCE: chunk_id] labels below
- Do not invent facts not in context"""


def build_context(state):
    chunks = state.get("retrieved_chunks") or []
    kev    = [c for c in chunks if c.get("chunk_type") == "kev"]
    other  = [c for c in chunks if c.get("chunk_type") != "kev"]
    text   = ""
    for c in (kev + other):
        flag = " ACTIVELY EXPLOITED" if c.get("metadata", {}).get("actively_exploited") else ""
        text += f"\n[SOURCE: {c['chunk_id']}]{flag}\n{c['text']}\n"
    feedback = f"\n\nCRITIC FEEDBACK:\n{state['revision_feedback']}\n" if state.get("revision_feedback") else ""
    rev = state.get("revision_count") or 0
    return f"""Original query: {state['raw_input']}
Analyzer: {state.get('correlation_notes', 'None')[:300]}
ATT&CK suggestions (verify): {state.get('attack_techniques', [])}

Context:
{text}{feedback}{"(Revision #" + str(rev) + ")" if rev > 0 else ""}"""


def run_executor(state):
    from groq import Groq
    rev = state.get("revision_count") or 0
    print(f"[Executor] {'Revision #' + str(rev) if rev > 0 else 'Writing assessment'}...")
    if not state.get("retrieved_chunks"):
        a = {"threat_id": state["raw_input"], "risk_level": "UNKNOWN", "cvss_score": "N/A",
             "actively_exploited": None, "exploitation_note": "No context retrieved",
             "what_it_is": "No relevant CVE data found.", "realistic_attack_scenario": [],
             "affected_systems": [], "immediate_actions": ["Verify CVE ID and date range"],
             "attack_techniques": [], "citations": [], "confidence": "low", "context_gaps": "No data"}
        return {**state, "draft_assessment": json.dumps(a, indent=2), "citations": []}

    client = Groq(api_key=GROQ_API_KEY)
    for attempt in range(3):
        try:
            r = client.chat.completions.create(
                model=LLM_MODEL, temperature=LLM_TEMPERATURE,
                extra_body={"include_reasoning": False},
                messages=[
                    {"role": "system", "content": EXECUTOR_SYSTEM_PROMPT},
                    {"role": "user",   "content": build_context(state)},
                ],
                max_tokens=3000,
            )
            content = (r.choices[0].message.content or "").strip()
            if not content:
                print(f"[Executor] Empty response attempt {attempt+1}/3, waiting 15s...")
                time.sleep(15); continue
            a = json.loads(content)
            return {**state, "draft_assessment": json.dumps(a, indent=2), "citations": a.get("citations", [])}
        except json.JSONDecodeError as e:
            print(f"[Executor] JSON error attempt {attempt+1}: {e}")
            if attempt < 2: time.sleep(5); continue
            return {**state, "draft_assessment": '{"error": "JSON parse failed"}', "citations": []}
        except Exception as e:
            if "rate_limit_exceeded" in str(e) and "per minute" in str(e):
                time.sleep(20*(attempt+1)); continue
            return {**state, "draft_assessment": f'{"error": "{e}"}', "citations": [], "error": str(e)}
    return {**state, "draft_assessment": '{"error": "Executor exhausted retries"}', "citations": []}
