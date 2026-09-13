"""
NVD Fetcher + CISA KEV enrichment.

Two data sources:
1. NVD API — CVE details, CVSS scores, affected products
2. CISA KEV — which CVEs are confirmed actively exploited in the wild

CISA KEV is a single JSON file, no rate limit, no API key.
It's the most important enrichment: if a CVE is on KEV,
it's not theoretical risk — attackers are using it today.
"""

import requests
import json
import time
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.config import NVD_API_BASE, NVD_RESULTS_PER_PAGE, RAW_DIR


# ── CISA KEV ─────────────────────────────────────────────────

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_cisa_kev() -> dict:
    """
    Download the CISA Known Exploited Vulnerabilities catalog.
    Returns a dict mapping CVE ID → KEV entry for fast lookup.
    Single JSON file, no rate limit, ~1200+ CVEs.
    """
    print("Fetching CISA KEV catalog...")
    try:
        response = requests.get(CISA_KEV_URL, timeout=30)
        response.raise_for_status()
        data         = response.json()
        vuln_list    = data.get("vulnerabilities", [])
        # Build lookup dict: CVE-ID → entry
        kev_lookup   = {v["cveID"]: v for v in vuln_list}
        print(f"  CISA KEV: {len(kev_lookup)} actively exploited CVEs loaded")
        return kev_lookup
    except Exception as e:
        print(f"  CISA KEV fetch failed: {e} — continuing without KEV data")
        return {}


def save_kev(kev_lookup: dict, filename: str = "cisa_kev.json") -> str:
    os.makedirs(RAW_DIR, exist_ok=True)
    filepath = os.path.join(RAW_DIR, filename)
    with open(filepath, "w") as f:
        json.dump(kev_lookup, f, indent=2)
    print(f"CISA KEV saved to {filepath}")
    return filepath


def load_kev(filename: str = "cisa_kev.json") -> dict:
    filepath = os.path.join(RAW_DIR, filename)
    if not os.path.exists(filepath):
        return {}
    with open(filepath, "r") as f:
        kev = json.load(f)
    print(f"CISA KEV loaded: {len(kev)} entries")
    return kev


# ── NVD Fetcher ───────────────────────────────────────────────

def fetch_cve_by_id(cve_id: str) -> dict | None:
    params = {"cveId": cve_id}
    for attempt in range(3):
        try:
            response = requests.get(NVD_API_BASE, params=params, timeout=60)
            response.raise_for_status()
            data            = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            if vulnerabilities:
                return vulnerabilities[0]
            return None
        except requests.exceptions.Timeout:
            print(f"  Timeout attempt {attempt+1}/3 — retrying in 10s...")
            time.sleep(10)
        except Exception as e:
            print(f"Failed to fetch {cve_id}: {e}")
            return None
    return None


def fetch_recent_cves(days_back: int = 120, max_cves: int = 500) -> list[dict]:
    from datetime import datetime, timedelta, timezone

    end_date   = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=days_back)
    start_str  = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    end_str    = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")

    print(f"Fetching CVEs from {start_str} to {end_str}")

    all_cves    = []
    start_index = 0

    while len(all_cves) < max_cves:
        params = {
            "pubStartDate":   start_str,
            "pubEndDate":     end_str,
            "startIndex":     start_index,
            "resultsPerPage": min(NVD_RESULTS_PER_PAGE, max_cves - len(all_cves)),
        }

        print(f"  Fetching batch at index {start_index}...")
        success = False

        for attempt in range(3):
            try:
                response = requests.get(NVD_API_BASE, params=params, timeout=60)
                response.raise_for_status()
                data    = response.json()
                success = True
                break
            except requests.exceptions.Timeout:
                print(f"    Timeout attempt {attempt+1}/3 — waiting 15s...")
                time.sleep(15)
            except requests.exceptions.RequestException as e:
                print(f"    Request error: {e}")
                time.sleep(10)

        if not success:
            print("  All retries failed — stopping fetch.")
            break

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            break

        all_cves.extend(vulnerabilities)
        total_available = data.get("totalResults", 0)
        print(f"  Got {len(vulnerabilities)} CVEs — total: {len(all_cves)} / {total_available}")

        if start_index + len(vulnerabilities) >= total_available:
            break

        start_index += len(vulnerabilities)
        time.sleep(6)

    print(f"\nTotal CVEs fetched: {len(all_cves)}")
    return all_cves


def save_raw_cves(cves: list[dict], filename: str = "nvd_raw.json") -> str:
    os.makedirs(RAW_DIR, exist_ok=True)
    filepath = os.path.join(RAW_DIR, filename)
    with open(filepath, "w") as f:
        json.dump(cves, f, indent=2)
    print(f"Saved {len(cves)} CVEs to {filepath}")
    return filepath


def load_raw_cves(filename: str = "nvd_raw.json") -> list[dict]:
    filepath = os.path.join(RAW_DIR, filename)
    if not os.path.exists(filepath):
        print(f"No cached CVEs found at {filepath}")
        return []
    with open(filepath, "r") as f:
        cves = json.load(f)
    print(f"Loaded {len(cves)} CVEs from {filepath}")
    return cves


if __name__ == "__main__":
    # Test both sources
    print("Testing NVD fetcher...")
    cve = fetch_cve_by_id("CVE-2024-21762")
    if cve:
        cve_data = cve.get("cve", {})
        print(f"CVE ID: {cve_data.get('id')}")

    print("\nTesting CISA KEV...")
    kev = fetch_cisa_kev()
    if kev:
        sample = list(kev.items())[:2]
        for cve_id, entry in sample:
            print(f"  {cve_id}: {entry.get('vulnerabilityName', 'N/A')}")
            print(f"    Due date: {entry.get('dueDate', 'N/A')}")
            print(f"    Required action: {entry.get('requiredAction', 'N/A')[:80]}")