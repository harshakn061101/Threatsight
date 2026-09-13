"""
Asset Matcher — matches company asset profile against CVE corpus.

This is the engine that turns ThreatSight from a query tool into
a vulnerability management system. Instead of waiting for a human
to ask about a CVE, it automatically finds which CVEs in the corpus
affect the company's actual infrastructure.

Also computes a priority score (0-100) for each matched CVE based on:
  - CISA KEV active exploitation status  (+35 points)
  - CVSS base score                      (up to 25 points)
  - Network-facing attack vector         (+20 points)
  - No privileges required               (+15 points)
  - Asset is internet-facing             (+5 bonus)

This score tells the analyst what to patch first, not just what is
theoretically dangerous.
"""

import os
import sys
import json

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from src.corpus.chunker import load_chunks
from src.corpus.nvd_fetcher import load_kev


def load_profile(profile_path: str) -> dict:
    with open(profile_path, "r") as f:
        return json.load(f)


def compute_priority_score(cve_id: str, chunks: list, asset: dict, kev_lookup: dict) -> dict:
    """
    Compute a 0-100 priority score for a matched CVE + asset pair.
    Reads directly from chunk metadata and CVSS chunk text — no fragile text parsing.
    """
    score   = 0
    factors = []

    # Get all chunks for this CVE
    cve_chunks = [c for c in chunks if c.get("metadata", {}).get("cve_id") == cve_id]
    overview   = next((c for c in cve_chunks if c.get("chunk_type") == "overview"), None)
    cvss_chunk = next((c for c in cve_chunks if c.get("chunk_type") == "cvss"), None)
    kev_chunk  = next((c for c in cve_chunks if c.get("chunk_type") == "kev"), None)

    meta = (overview or cvss_chunk or {}).get("metadata", {})

    # CISA KEV: actively exploited — highest weight
    if kev_lookup.get(cve_id) or kev_chunk:
        score += 40
        kev    = kev_lookup.get(cve_id, {})
        due    = kev.get("dueDate", "N/A") if kev else "N/A"
        factors.append(f"✓ CISA KEV confirmed exploitation (+40) — due {due}")
    else:
        factors.append("✗ No CISA KEV entry (not confirmed exploited)")

    # CVSS score from metadata
    try:
        cvss = float(meta.get("base_score", 0) or 0)
    except (ValueError, TypeError):
        cvss = 0.0

    if cvss >= 9.0:
        score += 20
        factors.append(f"✓ CVSS {cvss} — Critical (+20)")
    elif cvss >= 7.0:
        score += 12
        factors.append(f"✓ CVSS {cvss} — High (+12)")
    elif cvss >= 4.0:
        score += 6
        factors.append(f"~ CVSS {cvss} — Medium (+6)")
    elif cvss > 0:
        score += 2
        factors.append(f"~ CVSS {cvss} — Low (+2)")
    else:
        factors.append("✗ CVSS score not available")

    # Attack vector and privileges from CVSS chunk text
    cvss_text = (cvss_chunk.get("text", "") if cvss_chunk else "").upper()
    overview_text = (overview.get("text", "") if overview else "").upper()
    combined_text = cvss_text + overview_text

    if "ATTACK VECTOR: NETWORK" in combined_text or "ATTACKVECTOR: NETWORK" in combined_text:
        score += 20
        factors.append("✓ Network attack vector — remotely exploitable (+20)")
    elif "NETWORK" in combined_text and ("VECTOR" in combined_text or "REMOTELY" in combined_text):
        score += 20
        factors.append("✓ Network attack vector — remotely exploitable (+20)")

    if "PRIVILEGES REQUIRED: NONE" in combined_text or "NO PRIVILEGES" in combined_text:
        score += 15
        factors.append("✓ No privileges required — unauthenticated exploit (+15)")
    elif "PRIVILEGES REQUIRED: LOW" in combined_text:
        score += 5
        factors.append("~ Low privileges required (+5)")

    # Internet-facing asset bonus
    if asset.get("exposure") == "internet-facing":
        score += 5
        factors.append("✓ Asset is internet-facing (+5)")

    # KEV always forces 24h urgency
    if kev_lookup.get(cve_id) or kev_chunk:
        urgency = "PATCH WITHIN 24 HOURS"
    elif score >= 70:
        urgency = "PATCH WITHIN 24 HOURS"
    elif score >= 50:
        urgency = "PATCH WITHIN 7 DAYS"
    elif score >= 30:
        urgency = "PATCH WITHIN 30 DAYS"
    else:
        urgency = "MONITOR AND SCHEDULE"

    return {
        "score":   min(score, 100),
        "factors": factors,
        "urgency": urgency,
    }


def match_assets_to_cves(profile: dict, chunks: list, kev_lookup: dict) -> list:
    """
    For each asset in the company profile, search all CVE chunks
    for mentions of that vendor/product. Returns a list of matches
    sorted by priority score descending.

    Matching strategy: checks the chunk text and metadata for the
    vendor name and product name from the asset profile.
    We use the 'affected_products' chunk type because that's where
    product names are explicitly listed — not the overview which
    might mention vendors in passing.
    """
    assets  = profile.get("assets", [])
    matches = []
    seen    = set()   # avoid duplicate CVE+asset pairs

    # Focus on affected_products and overview chunks for matching
    relevant_chunks = [
        c for c in chunks
        if c.get("chunk_type") in ("affected_products", "overview")
    ]

    for asset in assets:
        vendor  = asset.get("vendor", "").lower()
        product = asset.get("product", "").lower()

        for chunk in relevant_chunks:
            text    = chunk.get("text", "").lower()
            meta    = chunk.get("metadata", {})
            cve_id  = meta.get("cve_id", "")

            # Skip if we already matched this CVE for this asset
            dedup_key = f"{cve_id}::{vendor}::{product}"
            if dedup_key in seen:
                continue

            # Match: both vendor and product must appear in the chunk text
            vendor_match  = vendor in text
            product_match = product.replace("_", " ") in text or product in text

            if vendor_match and product_match:
                seen.add(dedup_key)

                priority = compute_priority_score(cve_id, chunks, asset, kev_lookup)

                matches.append({
                    "cve_id":         cve_id,
                    "asset_vendor":   asset["vendor"],
                    "asset_product":  asset["product"],
                    "asset_exposure": asset.get("exposure", "unknown"),
                    "asset_type":     asset.get("type", "unknown"),
                    "severity":       meta.get("severity", "N/A"),
                    "base_score":     meta.get("base_score", "N/A"),
                    "actively_exploited": bool(kev_lookup.get(cve_id)),
                    "priority_score": priority["score"],
                    "priority_factors": priority["factors"],
                    "urgency":        priority["urgency"],
                    "published":      meta.get("published", "N/A"),
                })

    # Sort by priority score descending — most urgent first
    matches.sort(key=lambda x: x["priority_score"], reverse=True)
    return matches


if __name__ == "__main__":
    import sys
    profile_path = sys.argv[1] if len(sys.argv) > 1 else "company_profile.json"

    print(f"Loading profile: {profile_path}")
    profile = load_profile(profile_path)
    print(f"Company: {profile['company']} | Assets: {len(profile['assets'])}")

    print("Loading corpus...")
    chunks = load_chunks()
    kev    = load_kev()

    print("Matching assets to CVEs...")
    matches = match_assets_to_cves(profile, chunks, kev)

    print(f"\nFound {len(matches)} CVE matches across {len(profile['assets'])} assets\n")
    for m in matches[:5]:
        print(f"[{m['priority_score']:3d}/100] {m['cve_id']} — {m['asset_vendor']} {m['asset_product']}")
        print(f"        Severity: {m['severity']} | KEV: {m['actively_exploited']} | {m['urgency']}")
