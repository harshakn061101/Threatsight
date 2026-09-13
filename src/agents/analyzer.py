"""Analyzer Agent — correlates retrieved chunks."""
import os, sys, json, time
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from src.config import LLM_MODEL, LLM_TEMPERATURE, GROQ_API_KEY
from src.agents.state import ThreatAnalysisState

ANALYZER_SYSTEM_PROMPT = """You are the Analyzer agent. Respond with ONLY valid JSON.
{
  "correlation_notes": "2-3 sentences summarising key findings",
  "severity_context": "1-2 sentences on practical exploitability",
  "attack_techniques": ["T1190"],
  "key_findings": ["finding 1", "finding 2"]
}
ATT&CK: T1190=NETWORK+NONE, T1203=LOCAL+memory corruption, T1068=priv escalation, T1499=DoS
Base everything only on provided context. Empty list if techniques unclear."""


def run_analyzer(state):
    from groq import Groq
    chunks = state.get("retrieved_chunks") or []
    if not chunks:
        return {**state, "correlation_notes": "No chunks.", "severity_context": "Unknown."}
    context = "\n\n---\n\n".join(
        f"[{c['final_rank']}] {c['chunk_id']}\n{c['text']}" for c in chunks)
    client = Groq(api_key=GROQ_API_KEY)
    for attempt in range(3):
        try:
            r = client.chat.completions.create(
                model=LLM_MODEL, temperature=LLM_TEMPERATURE,
                extra_body={"include_reasoning": False},
                messages=[
                    {"role": "system", "content": ANALYZER_SYSTEM_PROMPT},
                    {"role": "user",   "content": f"Query: {state['raw_input']}\n\nContext:\n{context}"},
                ],
                max_tokens=800,
            )
            content = (r.choices[0].message.content or "").strip()
            if not content:
                print(f"[Analyzer] Empty response attempt {attempt+1}/3, waiting 15s...")
                time.sleep(15); continue
            result = json.loads(content)
            merged = list(set((state.get("attack_techniques") or []) + result.get("attack_techniques", [])))
            return {**state, "correlation_notes": result.get("correlation_notes", ""),
                    "severity_context": result.get("severity_context", ""), "attack_techniques": merged}
        except json.JSONDecodeError as e:
            print(f"[Analyzer] JSON error attempt {attempt+1}: {e}")
            if attempt < 2: time.sleep(5); continue
            return {**state, "correlation_notes": "Analysis failed.", "severity_context": "Unknown."}
        except Exception as e:
            if "rate_limit_exceeded" in str(e) and "per minute" in str(e):
                time.sleep(20*(attempt+1)); continue
            return {**state, "correlation_notes": f"Error: {e}", "severity_context": "Unknown."}
    return {**state, "correlation_notes": "Analyzer failed.", "severity_context": "Unknown."}
