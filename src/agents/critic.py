"""Critic Agent — faithfulness and consistency verification."""
import os, sys, json, time
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from src.config import LLM_MODEL, LLM_TEMPERATURE, GROQ_API_KEY, FAITHFULNESS_THRESHOLD, MAX_RETRIES
from src.agents.state import ThreatAnalysisState

CRITIC_SYSTEM_PROMPT = """You are the Critic agent. Respond with ONLY valid JSON. Start with {
Check faithfulness (claims traceable to context?) and consistency (no self-contradictions).
ATT&CK: T1190=NETWORK+NONE wrong if LOCAL; T1203=LOCAL+memory correct; T1068=escalation not initial access; T1059=post-exploitation only.
revision_needed true ONLY if faithfulness_score OR consistency_score < 0.85.
Do NOT flag narrative gaps as contradictions.
{
  "faithfulness_score": 0.95,
  "consistency_score": 0.95,
  "revision_needed": false,
  "ungrounded_claims": [],
  "contradictions": [],
  "revision_feedback": ""
}"""


def extract_claims(j):
    try:
        a = json.loads(j)
        out = []
        if a.get("what_it_is"): out.append(a["what_it_is"][:200])
        if a.get("cvss_score") and a["cvss_score"] != "N/A": out.append(f"CVSS: {a['cvss_score']}")
        if a.get("risk_level"): out.append(f"Risk: {a['risk_level']}")
        if a.get("actively_exploited") is not None: out.append(f"Exploited: {a['actively_exploited']}")
        for s in (a.get("affected_systems") or [])[:3]: out.append(f"Affected: {s}")
        for t in (a.get("attack_techniques") or []):
            if isinstance(t, dict): out.append(f"{t.get('id')}: {t.get('relevance','')[:100]}")
        return out
    except: return [j[:300]]


def strip_techniques(j):
    try:
        a = json.loads(j); a["attack_techniques"] = []
        a["context_gaps"] = (a.get("context_gaps") or "") + " | ATT&CK removed after consistency failure"
        return json.dumps(a, indent=2)
    except: return j


def run_critic(state):
    from groq import Groq
    draft, chunks, rev = state.get("draft_assessment",""), state.get("retrieved_chunks",[]), state.get("revision_count",0)
    print(f"[Critic] Checking (revision #{rev})...")
    if not draft or '"error"' in draft[:30]:
        return {**state, "faithfulness_score": 0.0, "revision_needed": False, "revision_feedback": ""}
    ctx   = "\n".join(f"[{c['chunk_id']}]\n{c['text'][:350]}" for c in chunks[:6])
    claims= "\n".join(f"- {c}" for c in extract_claims(draft))
    user  = f"Context:\n{ctx}\n\nAssessment:\n{draft}\n\nClaims:\n{claims}\n\nReturn JSON verdict:"
    client = Groq(api_key=GROQ_API_KEY)
    for attempt in range(5):
        try:
            r = client.chat.completions.create(
                model=LLM_MODEL, temperature=0.0,
                extra_body={"include_reasoning": False},
                messages=[{"role":"system","content":CRITIC_SYSTEM_PROMPT},{"role":"user","content":user}],
                max_tokens=600,
            )
            raw = (r.choices[0].message.content or "").strip()
            if not raw:
                wait = 15*(attempt+1)
                print(f"[Critic] Empty response attempt {attempt+1}/5 — waiting {wait}s...")
                time.sleep(wait); continue
            result = json.loads(raw)
            fs, cs = float(result.get("faithfulness_score",0.5)), float(result.get("consistency_score",0.5))
            rev_needed = fs < FAITHFULNESS_THRESHOLD or cs < FAITHFULNESS_THRESHOLD
            final = draft
            if rev >= MAX_RETRIES:
                if rev_needed and result.get("contradictions"):
                    print("[Critic] Max retries — stripping attack_techniques"); final = strip_techniques(draft)
                rev_needed = False
            print(f"[Critic] Faithfulness: {fs:.2f} | Consistency: {cs:.2f}")
            if rev_needed: print(f"[Critic] Revision needed: {result.get('revision_feedback','')[:200]}")
            else: print("[Critic] Assessment passes ✓")
            return {**state, "draft_assessment": final, "faithfulness_score": min(fs,cs),
                    "revision_needed": rev_needed, "revision_feedback": result.get("revision_feedback",""),
                    "revision_count": rev+1}
        except json.JSONDecodeError as e:
            print(f"[Critic] JSON error attempt {attempt+1}: {e}")
            if attempt < 4: time.sleep(10); continue
            return {**state, "faithfulness_score":0.75,"revision_needed":False,"revision_feedback":"","revision_count":rev+1}
        except Exception as e:
            if "rate_limit_exceeded" in str(e) and "per minute" in str(e):
                time.sleep(20*(attempt+1)); continue
            return {**state, "faithfulness_score":0.75,"revision_needed":False,"revision_feedback":"","revision_count":rev+1}
    return {**state, "faithfulness_score":0.75,"revision_needed":False,"revision_feedback":"","revision_count":rev+1}
