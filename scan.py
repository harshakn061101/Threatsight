"""
ThreatSight Scanner — asset-aware vulnerability scan.

Entry point for the asset-aware scanning mode. Takes a company profile,
matches it against the CVE corpus, runs the full 5-agent pipeline for
each matched CVE, and produces a prioritised scan report.

Usage:
    python scan.py                          # uses company_profile.json
    python scan.py --profile mycompany.json # custom profile
    python scan.py --top 5                  # only analyse top 5 by priority
    python scan.py --output reports/        # save full reports to folder

This is the workflow that makes ThreatSight a vulnerability management
tool rather than a CVE lookup assistant. The analyst does not need to
know which CVEs exist — the system finds what matters for their stack.
"""

import os
import sys
import json
import argparse
import time
from datetime import datetime

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.corpus.chunker import load_chunks
from src.corpus.nvd_fetcher import load_kev
from src.scanner.matcher import load_profile, match_assets_to_cves
from src.agents.graph import run_threat_analysis


def print_banner():
    print("\n" + "="*65)
    print("  ThreatSight — Asset-Aware Vulnerability Scanner")
    print("="*65)


def print_match_summary(matches: list, company: str):
    kev_count      = sum(1 for m in matches if m["actively_exploited"])
    critical_count = sum(1 for m in matches if m["severity"] == "CRITICAL")
    high_count     = sum(1 for m in matches if m["severity"] == "HIGH")

    print(f"\nCompany:          {company}")
    print(f"Scan time:        {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"CVEs matched:     {len(matches)}")
    print(f"  → Active exploitation (KEV): {kev_count}")
    print(f"  → Critical severity:         {critical_count}")
    print(f"  → High severity:             {high_count}")
    print()


def run_scan(profile_path: str, top_n: int = 10, output_dir: str = None) -> dict:
    print_banner()

    # Load data
    print("\n[1/4] Loading company profile...")
    profile = load_profile(profile_path)
    company = profile.get("company", "Unknown")
    print(f"      Company: {company} | Assets: {len(profile['assets'])}")

    print("[2/4] Loading CVE corpus and CISA KEV...")
    chunks = load_chunks()
    kev    = load_kev()

    print("[3/4] Matching assets against corpus...")
    all_matches = match_assets_to_cves(profile, chunks, kev)
    print_match_summary(all_matches, company)

    if not all_matches:
        print("No CVE matches found for this asset profile.")
        print("The corpus contains CVEs from the last 120 days.")
        print("Try broadening the asset profile or refreshing the corpus.")
        return {"company": company, "matches": [], "reports": []}

    # Deduplicate: keep only the highest-scoring entry per CVE ID
    # (same CVE can match multiple assets — only analyse it once,
    #  but report which assets are affected)
    seen_cves   = {}
    for m in all_matches:
        cve_id = m["cve_id"]
        if cve_id not in seen_cves:
            seen_cves[cve_id] = m
            seen_cves[cve_id]["affected_assets"] = [
                {"vendor": m["asset_vendor"], "product": m["asset_product"],
                 "exposure": m["asset_exposure"]}
            ]
        else:
            seen_cves[cve_id]["affected_assets"].append(
                {"vendor": m["asset_vendor"], "product": m["asset_product"],
                 "exposure": m["asset_exposure"]}
            )

    unique_matches = list(seen_cves.values())
    top_matches    = unique_matches[:top_n]

    print(f"[4/4] Running full agent analysis on top {len(top_matches)} CVEs...")
    print("      (Planner → Retriever → Analyzer → Executor → Critic → Validator)")
    print()

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    scan_results = []

    for i, match in enumerate(top_matches, 1):
        cve_id = match["cve_id"]
        print(f"  [{i}/{len(top_matches)}] Analysing {cve_id} "
              f"(Priority: {match['priority_score']}/100 | {match['urgency']})")

        try:
            final_state = run_threat_analysis(cve_id, verbose=False)
            assessment_raw = final_state.get("draft_assessment", "{}")

            try:
                assessment = json.loads(assessment_raw)
            except Exception:
                assessment = {"error": assessment_raw}

            result = {
                "cve_id":           cve_id,
                "asset_vendor":     match["asset_vendor"],
                "asset_product":    match["asset_product"],
                "asset_exposure":   match["asset_exposure"],
                "priority_score":   match["priority_score"],
                "priority_factors": match["priority_factors"],
                "urgency":          match["urgency"],
                "severity":         match["severity"],
                "base_score":       match["base_score"],
                "actively_exploited": match["actively_exploited"],
                "faithfulness_score": final_state.get("faithfulness_score"),
                "revision_count":     final_state.get("revision_count"),
                "assessment":         assessment,
            }
            scan_results.append(result)

            # Save individual report
            if output_dir:
                report_path = os.path.join(output_dir, f"{cve_id}.json")
                with open(report_path, "w") as f:
                    json.dump(result, f, indent=2)

            # Brief pause between CVEs to avoid TPM rate limits
            if i < len(top_matches):
                time.sleep(3)

        except Exception as e:
            print(f"    ERROR analysing {cve_id}: {e}")
            scan_results.append({
                "cve_id":         cve_id,
                "priority_score": match["priority_score"],
                "urgency":        match["urgency"],
                "error":          str(e),
            })

    # Build final scan report
    scan_report = {
        "company":        company,
        "scan_timestamp": datetime.now().isoformat(),
        "profile_path":   profile_path,
        "total_matches":  len(all_matches),
        "analysed":       len(scan_results),
        "summary": {
            "kev_count":      sum(1 for r in scan_results if r.get("actively_exploited")),
            "critical_count": sum(1 for r in scan_results if r.get("severity") == "CRITICAL"),
            "high_count":     sum(1 for r in scan_results if r.get("severity") == "HIGH"),
            "patch_24h":      sum(1 for r in scan_results if r.get("urgency") == "PATCH WITHIN 24 HOURS"),
            "patch_7d":       sum(1 for r in scan_results if r.get("urgency") == "PATCH WITHIN 7 DAYS"),
        },
        "results": scan_results,
        "all_matches_summary": [
            {
                "cve_id":         m["cve_id"],
                "priority_score": m["priority_score"],
                "severity":       m["severity"],
                "urgency":        m["urgency"],
                "actively_exploited": m["actively_exploited"],
                "asset":          f"{m['asset_vendor']} {m['asset_product']}",
            }
            for m in all_matches
        ],
    }

    # Save full scan report
    scan_report_path = "scan_report.json"
    if output_dir:
        scan_report_path = os.path.join(output_dir, "scan_report.json")
    with open(scan_report_path, "w") as f:
        json.dump(scan_report, f, indent=2)

    # Print terminal summary
    print("\n" + "="*65)
    print("SCAN COMPLETE")
    print("="*65)
    print(f"\nTotal CVEs matched to your stack: {len(all_matches)}")
    print(f"Full reports generated:           {len(scan_results)}")
    print()

    if scan_results:
        print("PRIORITY RANKING:")
        print("-"*65)
        for r in scan_results:
            if "error" in r:
                continue
            kev_tag = " ⚠ KEV" if r.get("actively_exploited") else ""
            a = r.get("assessment", {})
            affected = r.get("affected_assets", [{"vendor": r["asset_vendor"], "product": r["asset_product"]}])
            asset_str = ", ".join(f"{a.get('vendor', a.get('asset_vendor', '?'))} {a.get('product', a.get('asset_product', '?'))} ({a.get('exposure', a.get('asset_exposure', 'unknown'))})" for a in affected)
            print(f"[{r['priority_score']:3d}/100] {r['cve_id']}{kev_tag}")
            print(f"         Assets:   {asset_str}")
            print(f"         Severity: {r['severity']} (CVSS {r['base_score']})")
            print(f"         Action:   {r['urgency']}")
            if a.get("immediate_actions"):
                print(f"         → {a['immediate_actions'][0]}")
            print()

    print(f"Full scan report saved to: {scan_report_path}")
    return scan_report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ThreatSight Asset-Aware Vulnerability Scanner")
    parser.add_argument("--profile", default="company_profile.json", help="Path to company profile JSON")
    parser.add_argument("--top",     type=int, default=5,            help="Number of top CVEs to fully analyse")
    parser.add_argument("--output",  default="reports",              help="Directory to save reports")
    args = parser.parse_args()

    scan_report = run_scan(
        profile_path=args.profile,
        top_n=args.top,
        output_dir=args.output,
    )
