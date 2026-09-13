"""
CVE Chunker with CISA KEV enrichment.

The KEV chunk is the most valuable addition:
- "Is this being actively exploited?" is the first question every analyst asks
- NVD doesn't answer it. CISA KEV does.
- A CVE on the KEV list changes the risk rating from theoretical to confirmed threat.
"""

import os
import sys
import json

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.config import PROCESSED_DIR


def extract_cve_fields(raw_cve: dict) -> dict:
    cve_data = raw_cve.get("cve", {})
    cve_id   = cve_data.get("id", "UNKNOWN")

    descriptions = cve_data.get("descriptions", [])
    description  = next(
        (d["value"] for d in descriptions if d["lang"] == "en"),
        "No description available."
    )

    metrics  = cve_data.get("metrics", {})
    cvss_v31 = metrics.get("cvssMetricV31", [])
    cvss_v30 = metrics.get("cvssMetricV30", [])
    cvss_v2  = metrics.get("cvssMetricV2",  [])

    base_score = base_severity = attack_vector = cvss_version = "N/A"
    privileges_required = user_interaction = "N/A"

    for source_list, version in [(cvss_v31, "3.1"), (cvss_v30, "3.0"), (cvss_v2, "2.0")]:
        if source_list:
            cvss_data          = source_list[0].get("cvssData", {})
            base_score         = cvss_data.get("baseScore", "N/A")
            base_severity      = cvss_data.get("baseSeverity", "N/A")
            attack_vector      = cvss_data.get("attackVector", "N/A")
            cvss_version       = version
            privileges_required = cvss_data.get("privilegesRequired", "N/A")
            user_interaction   = cvss_data.get("userInteraction", "N/A")
            break

    weaknesses = cve_data.get("weaknesses", [])
    cwes = []
    for w in weaknesses:
        for desc in w.get("description", []):
            if desc.get("lang") == "en":
                cwes.append(desc.get("value", ""))

    configurations    = cve_data.get("configurations", [])
    affected_products = []
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable", False):
                    cpe   = match.get("criteria", "")
                    parts = cpe.split(":")
                    if len(parts) >= 5:
                        vendor  = parts[3]
                        product = parts[4]
                        version = parts[5] if len(parts) > 5 else "*"
                        # Skip wildcard-only entries — not useful
                        if product != "*":
                            affected_products.append(f"{vendor} {product} {version}")

    published  = cve_data.get("published", "Unknown")[:10]
    references = cve_data.get("references", [])
    ref_urls   = [r.get("url", "") for r in references[:5]]

    return {
        "cve_id":               cve_id,
        "description":          description,
        "base_score":           base_score,
        "base_severity":        base_severity,
        "attack_vector":        attack_vector,
        "privileges_required":  privileges_required,
        "user_interaction":     user_interaction,
        "cvss_version":         cvss_version,
        "cwes":                 cwes,
        "affected_products":    list(dict.fromkeys(affected_products))[:10],  # deduplicate
        "published":            published,
        "references":           ref_urls,
    }


def cve_to_chunks(raw_cve: dict, kev_lookup: dict = None) -> list[dict]:
    """
    Convert one raw CVE into searchable chunks.
    kev_lookup: dict mapping CVE ID → CISA KEV entry (optional).
    """
    fields     = extract_cve_fields(raw_cve)
    cve_id     = fields["cve_id"]
    kev_lookup = kev_lookup or {}
    kev_entry  = kev_lookup.get(cve_id)
    chunks     = []

    # ── Chunk 1: Overview ────────────────────────────────────────────
    # Includes exploitation status right in the overview — most important fact
    exploitation_status = "Not confirmed in CISA KEV"
    if kev_entry:
        exploitation_status = (
            f"ACTIVELY EXPLOITED — confirmed by CISA KEV. "
            f"Required action by {kev_entry.get('dueDate', 'N/A')}: "
            f"{kev_entry.get('requiredAction', 'See CISA advisory')}"
        )

    overview_text = f"""CVE ID: {cve_id}
Severity: {fields['base_severity']} (CVSS {fields['base_score']})
Published: {fields['published']}
Exploitation Status: {exploitation_status}
Summary: {fields['description']}
Attack Vector: {fields['attack_vector']}
Privileges Required: {fields['privileges_required']}
User Interaction Required: {fields['user_interaction']}
Weakness Type: {', '.join(fields['cwes']) if fields['cwes'] else 'Not specified'}"""

    chunks.append({
        "chunk_id":   f"{cve_id}_overview",
        "text":       overview_text,
        "chunk_type": "overview",
        "metadata": {
            "cve_id":           cve_id,
            "source":           "NVD",
            "chunk_type":       "overview",
            "severity":         fields["base_severity"],
            "base_score":       fields["base_score"],
            "published":        fields["published"],
            "actively_exploited": bool(kev_entry),
        }
    })

    # ── Chunk 2: Affected Products ────────────────────────────────────
    if fields["affected_products"]:
        products_text = f"""CVE ID: {cve_id} — Affected Products and Versions
The following products are confirmed vulnerable:
{chr(10).join(f'- {p}' for p in fields['affected_products'])}

Attack requires: {fields['attack_vector']} access, privileges: {fields['privileges_required']}, user interaction: {fields['user_interaction']}"""

        chunks.append({
            "chunk_id":   f"{cve_id}_affected",
            "text":       products_text,
            "chunk_type": "affected_products",
            "metadata": {
                "cve_id":     cve_id,
                "source":     "NVD",
                "chunk_type": "affected_products",
                "severity":   fields["base_severity"],
                "published":  fields["published"],
                "actively_exploited": bool(kev_entry),
            }
        })

    # ── Chunk 3: CVSS Detail ──────────────────────────────────────────
    cvss_text = f"""CVE ID: {cve_id} — Severity and Exploitability
CVSS Version: {fields['cvss_version']}
Base Score: {fields['base_score']} / 10.0
Severity Rating: {fields['base_severity']}
Attack Vector: {fields['attack_vector']}
Privileges Required: {fields['privileges_required']}
User Interaction: {fields['user_interaction']}

What the score means:
- NETWORK attack vector: exploitable remotely over the internet
- NONE privileges required: no login or account needed to exploit
- NONE user interaction: no victim action needed (fully automated attack possible)
- Critical (9.0-10.0): patch immediately, treat as emergency
- High (7.0-8.9): patch within days
- Medium (4.0-6.9): patch in next maintenance window"""

    chunks.append({
        "chunk_id":   f"{cve_id}_cvss",
        "text":       cvss_text,
        "chunk_type": "cvss",
        "metadata": {
            "cve_id":     cve_id,
            "source":     "NVD",
            "chunk_type": "cvss",
            "base_score": fields["base_score"],
            "severity":   fields["base_severity"],
            "published":  fields["published"],
            "actively_exploited": bool(kev_entry),
        }
    })

    # ── Chunk 4: KEV chunk (only if on CISA KEV list) ─────────────────
    # This chunk only exists for CVEs confirmed actively exploited.
    # When a retriever finds this chunk, the analyst knows immediately
    # this is not a theoretical risk.
    if kev_entry:
        kev_text = f"""CVE ID: {cve_id} — ACTIVE EXPLOITATION CONFIRMED
Source: CISA Known Exploited Vulnerabilities (KEV) Catalog

This vulnerability is being actively exploited in the wild.
CISA has mandated remediation for US federal agencies.

Vulnerability Name: {kev_entry.get('vulnerabilityName', 'N/A')}
Vendor/Project: {kev_entry.get('vendorProject', 'N/A')}
Product: {kev_entry.get('product', 'N/A')}
Date Added to KEV: {kev_entry.get('dateAdded', 'N/A')}
Required Action: {kev_entry.get('requiredAction', 'N/A')}
Due Date (federal agencies): {kev_entry.get('dueDate', 'N/A')}
Known Ransomware Campaign: {kev_entry.get('knownRansomwareCampaignUse', 'Unknown')}
Notes: {kev_entry.get('notes', 'None')}"""

        chunks.append({
            "chunk_id":   f"{cve_id}_kev",
            "text":       kev_text,
            "chunk_type": "kev",
            "metadata": {
                "cve_id":     cve_id,
                "source":     "CISA_KEV",
                "chunk_type": "kev",
                "severity":   fields["base_severity"],
                "published":  fields["published"],
                "actively_exploited": True,
                "kev_due_date": kev_entry.get("dueDate", ""),
            }
        })

    # ── Chunk 5: References ───────────────────────────────────────────
    if fields["references"]:
        refs_text = f"""CVE ID: {cve_id} — Official References and Patches
{chr(10).join(f'- {r}' for r in fields['references'])}

Check these sources for vendor patches, workarounds, and technical advisories."""

        chunks.append({
            "chunk_id":   f"{cve_id}_references",
            "text":       refs_text,
            "chunk_type": "references",
            "metadata": {
                "cve_id":     cve_id,
                "source":     "NVD",
                "chunk_type": "references",
                "severity":   fields["base_severity"],
                "published":  fields["published"],
                "actively_exploited": bool(kev_entry),
            }
        })

    return chunks


def process_cve_list(raw_cves: list[dict], kev_lookup: dict = None) -> list[dict]:
    all_chunks = []
    kev_lookup = kev_lookup or {}
    kev_hits   = 0

    for i, raw_cve in enumerate(raw_cves):
        cve_data = raw_cve.get("cve", {})
        cve_id   = cve_data.get("id", "")
        if cve_id in kev_lookup:
            kev_hits += 1
        chunks = cve_to_chunks(raw_cve, kev_lookup)
        all_chunks.extend(chunks)
        if (i + 1) % 100 == 0:
            print(f"  Processed {i+1}/{len(raw_cves)} CVEs → {len(all_chunks)} chunks")

    print(f"\nTotal: {len(raw_cves)} CVEs → {len(all_chunks)} chunks")
    print(f"CISA KEV matches in corpus: {kev_hits} CVEs confirmed actively exploited")
    return all_chunks


def save_chunks(chunks: list[dict], filename: str = "cve_chunks.json") -> str:
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    filepath = os.path.join(PROCESSED_DIR, filename)
    with open(filepath, "w") as f:
        json.dump(chunks, f, indent=2)
    print(f"Saved {len(chunks)} chunks to {filepath}")
    return filepath


def load_chunks(filename: str = "cve_chunks.json") -> list[dict]:
    filepath = os.path.join(PROCESSED_DIR, filename)
    if not os.path.exists(filepath):
        return []
    with open(filepath, "r") as f:
        chunks = json.load(f)
    print(f"Loaded {len(chunks)} chunks from {filepath}")
    return chunks


if __name__ == "__main__":
    from src.corpus.nvd_fetcher import fetch_cve_by_id
    from src.corpus.nvd_fetcher import fetch_cisa_kev

    kev = fetch_cisa_kev()
    raw = fetch_cve_by_id("CVE-2024-21762")
    if raw:
        chunks = cve_to_chunks(raw, kev)
        print(f"\nGenerated {len(chunks)} chunks for CVE-2024-21762")
        for c in chunks:
            print(f"\n--- {c['chunk_id']} ---")
            print(c["text"][:300])