#!/usr/bin/env python3
"""
explr.py - CVE Exploit & POC Finder

Usage:
    python3 explr.py CVE-2023-12345
"""

import requests
from bs4 import BeautifulSoup
import argparse
import os
import signal
import sys
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

def print_banner():
    banner = r"""


███████╗██╗  ██╗██████╗ ██╗     ██████╗ 
██╔════╝╚██╗██╔╝██╔══██╗██║     ██╔══██╗
█████╗   ╚███╔╝ ██████╔╝██║     ██████╔╝
██╔══╝   ██╔██╗ ██╔══╝  ██║     ██╔══██╗
███████╗██╔╝ ██╗██║     ██████╗ ██║  ██╗
╚══════╝╚═╝  ╚═╝╚═╝     ╚═════╝ ╚═╝  ╚═╝
     🔎  EXPLR  🔎   v1.0
    HTN Exploitation Helper Toolkit
"""
    print(banner)

# -------- CONFIG -------- #
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ExploitScraper/2.0"
HEADERS = {"User-Agent": USER_AGENT}
LOG_DIR = "explr_results"
os.makedirs(LOG_DIR, exist_ok=True)
MAX_THREADS = 5

# Supported file extensions for GitHub POC detection
POC_EXTENSIONS = [".py", ".sh", ".txt", ".rb", ".pl", ".exe"]

# Graceful exit on Ctrl+C
def signal_handler(sig, frame):
    print("\n[!] Ctrl+C detected. Exiting gracefully...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# -------- SCRAPER FUNCTIONS -------- #



def search_circl_lu(cve_id):
    """Scrape CIRCL LU for CVE"""
    results = []
    url = f"https://www.circl.lu/exploit/{cve_id}/"
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            results.append(url)
    except Exception:
        pass
    return results


def search_github(cve_id):
    """Search GitHub for repos & detect POC files"""
    results = []
    url = f"https://github.com/search?q={cve_id}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            results.append(url)
            # Optional: parse POC filenames from repo pages (simplified)
            soup = BeautifulSoup(r.text, "html.parser")
            for link in soup.find_all("a", href=True):
                href = link['href']
                if any(href.endswith(ext) for ext in POC_EXTENSIONS):
                    full_url = f"https://github.com{href}"
                    results.append(full_url)
    except Exception:
        pass
    return results


def search_grepapp(cve_id, outdir=None):
    """Search grep.app API for references to CVE and save results in plain text"""
    results = []
    url = f"https://grep.app/api/search?f.lang=Markdown&f.lang=JSON&f.lang=YAML&f.lang=Python&f.lang=JavaScript&q={cve_id}"  # fetch up to 50 hits
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json"
    }

    try:
        r = requests.get(url, headers=headers, timeout=15)
        r.raise_for_status()
        data = r.json()

        hits = data.get("hits", {}).get("hits", [])
        if not hits:
            print("[!] No hits found on grep.app")
            return []

        for idx, hit in enumerate(hits):
            owner_id = hit.get("owner_id", "unknown-owner")
            repo = hit.get("repo", "unknown-repo")
            path = hit.get("path", "unknown-path")
            branch = hit.get("branch", "unknown-branch")
            snippet = hit.get("content", {}).get("snippet", "")
            entry = f"[{idx+1}] Owner ID: {owner_id}\nRepo: {repo}\nBranch: {branch}\nPath: {path}\nSnippet:\n{snippet}\n"
            entry += "-"*60 + "\n"
            results.append(entry)

        # Save results to TXT
        if not outdir:
            outdir = LOG_DIR
        os.makedirs(outdir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        grep_file = os.path.join(outdir, f"{cve_id.replace('/', '_')}-grepapp-{ts}.txt")
        with open(grep_file, "w", encoding="utf-8") as f:
            f.writelines(results)

        print(f"[+] Grep.app results saved to: {grep_file}")

    except Exception as e:
        print(f"[!] Error querying grep.app: {e}")

    return results





# -------- LOGGING -------- #
def log_results(cve_id, results, outdir=None):
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    if not outdir:
        outdir = LOG_DIR
    os.makedirs(outdir, exist_ok=True)
    filename = os.path.join(outdir, f"{cve_id.replace('/', '_')}-{ts}.json")
    with open(filename, "w") as f:
        json.dump({"cve": cve_id, "results": results}, f, indent=4)
    print(f"[+] Results saved to: {filename}")

# -------- MAIN FUNCTION -------- #
def main():
    print_banner()
    parser = argparse.ArgumentParser(description="CVE Exploit & POC Finder")
    parser.add_argument("cve", help="CVE ID (e.g., CVE-2023-12345)")
    parser.add_argument("-o", "--outdir", help="Output directory for results")
    args = parser.parse_args()

    cve_id = args.cve
    outdir = args.outdir

    print(f"[+] Searching for exploits/POCs for {cve_id}...\n")

    # Scrapers for JSON (exclude grepapp)
    scrapers = {
        "github": search_github
    }

    all_results = {}

    # -------- Multithreaded scraping -------- #
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_source = {executor.submit(func, cve_id): name for name, func in scrapers.items()}

        for future in as_completed(future_to_source):
            source = future_to_source[future]
            try:
                urls = future.result()
                all_results[source] = urls
            except Exception as e:
                all_results[source] = []
                print(f"[!] Error scraping {source}: {e}")

    # Print JSON results
    for source, urls in all_results.items():
        print(f"\n[{source.upper()}] Found {len(urls)} results:")
        for u in urls:
            print(f" - {u}")

    # Log JSON results
    log_results(cve_id, all_results, outdir)

    # -------- Grep.app results (separate) -------- #
    print("\n[+] Searching grep.app (separate output)...")
    search_grepapp(cve_id, outdir)
if __name__ == "__main__":
    main()
