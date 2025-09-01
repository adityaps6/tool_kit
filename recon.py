#!/usr/bin/env python3
import subprocess
import argparse
import os
import re
import concurrent.futures

# -------- Helper Functions -------- #

def run_cmd(command, outfile=None):
    """Run a shell command and save output if outfile is provided."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=600)
        output = result.stdout + result.stderr
        if outfile:
            with open(outfile, "w") as f:
                f.write(output)
        return output
    except Exception as e:
        return str(e)


def nmap_scan(target, outdir):
    print("[*] Running Nmap Scan...")
    outfile = os.path.join(outdir, "nmap.txt")
    cmd = f"nmap -sC -sV -T4 -Pn -oN {outfile} {target}"
    run_cmd(cmd)
    with open(outfile) as f:
        return f.read()


def run_dirsearch(target, outdir):
    print("[*] Running Dirsearch...")
    outfile = os.path.join(outdir, "dirsearch.txt")
    cmd = f"dirsearch -u http://{target} -o {outfile} --plain-text-report={outfile}"
    run_cmd(cmd)


def run_ffuf_dir(target, outdir):
    print("[*] Running FFuF Directory Search...")
    outfile = os.path.join(outdir, "ffuf_dir.txt")
    cmd = f"ffuf -w /usr/share/wordlists/dirb/common.txt -u http://{target}/FUZZ -o {outfile} -of md"
    run_cmd(cmd)


def run_ffuf_subs(target, outdir):
    print("[*] Running FFuF Subdomain Enumeration...")
    outfile = os.path.join(outdir, "ffuf_subs.txt")
    cmd = f"ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://FUZZ.{target} -o {outfile} -of md"
    run_cmd(cmd)


def run_nikto(target, outdir):
    print("[*] Running Nikto...")
    outfile = os.path.join(outdir, "nikto.txt")
    cmd = f"nikto -h {target} -o {outfile}"
    run_cmd(cmd)


def run_whatweb(target, outdir):
    print("[*] Detecting Web Technologies (WhatWeb)...")
    outfile = os.path.join(outdir, "whatweb.txt")
    cmd = f"whatweb {target} --log-verbose={outfile}"
    run_cmd(cmd)


def run_snmp_enum(target, outdir):
    print("[*] Running SNMP Enumeration...")
    outfile = os.path.join(outdir, "snmpwalk.txt")
    cmd = f"snmpwalk -v2c -c public {target} > {outfile}"
    run_cmd(cmd)


def run_smb_enum(target, outdir):
    print("[*] Running SMB Enumeration...")
    outfile = os.path.join(outdir, "smb.txt")
    cmd = f"smbmap -H {target} > {outfile}"
    run_cmd(cmd)


def run_ftp_enum(target, outdir):
    print("[*] Running FTP Enumeration...")
    outfile = os.path.join(outdir, "ftp.txt")
    cmd = f"nmap -p21 --script ftp-anon {target} -oN {outfile}"
    run_cmd(cmd)


# -------- Main Orchestrator -------- #

def main():
    parser = argparse.ArgumentParser(description="Custom Recon Script")
    parser.add_argument("target", help="Target IP or Domain")
    parser.add_argument("-o", "--outdir", default="results", help="Output directory")
    args = parser.parse_args()

    target = args.target
    outdir = args.outdir
    os.makedirs(outdir, exist_ok=True)

    # Step 1: Nmap scan
    nmap_output = nmap_scan(target, outdir)

    # Step 2: Detect open ports & trigger specific enumeration
    open_ports = re.findall(r"(\d+)/tcp\s+open\s+(\S+)", nmap_output)

    # Run in parallel where possible
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []

        for port, service in open_ports:
            if service in ["http", "https"]:
                futures.append(executor.submit(run_dirsearch, target, outdir))
                futures.append(executor.submit(run_ffuf_dir, target, outdir))
                futures.append(executor.submit(run_nikto, target, outdir))
                futures.append(executor.submit(run_whatweb, target, outdir))

            if service == "snmp":
                futures.append(executor.submit(run_snmp_enum, target, outdir))

            if service == "microsoft-ds" or service == "smb":
                futures.append(executor.submit(run_smb_enum, target, outdir))

            if service == "ftp":
                futures.append(executor.submit(run_ftp_enum, target, outdir))

        # Subdomain enumeration only if domain input
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", target):  
            futures.append(executor.submit(run_ffuf_subs, target, outdir))

        for f in futures:
            f.result()  # wait for completion

    print(f"\n[+] Recon complete! Results stored in: {outdir}/")


if __name__ == "__main__":
    main()