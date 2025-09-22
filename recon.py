# Facing some issues with recon.py which are being looked at. THe script will be updated soon for better 
# performnace more clear output. Slight error in the workinf of dirsearch was identified and is being loooked at.
#!/usr/bin/env python3
import subprocess
import argparse
import os
import re
import concurrent.futures
import sys
import nmap

# -------- Helper Functions -------- #

def print_banner():
    banner = r"""
 _____  ______  _____   ____  _   _ 
|  __ \|  ____|/ ____| / __ \| \ | |
| |__) | |__  | |     | |  | |  \| |
|  _  /|  __| | |     | |  | | . ` |
| | \ \| |____| |____ | |__| | |\  |
|_|  \_\______|\_____| \____/|_| \_|

              🔎 RECON v1.0🔎
"""
    print(banner)


def run_cmd(command, outfile=None, quiet=False):
    """Run a shell command and save output if outfile is provided. Suppress output if quiet=True."""
    try:
        # Use same args in both modes but keep semantics for quiet flag
        if quiet:
            result = subprocess.run(
                command, shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=600
            )
        else:
            result = subprocess.run(
                command, shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=600
            )
        # Combine stdout and stderr so tools that print to stderr are captured
        output = ""
        if result.stdout:
            output += result.stdout
        if result.stderr:
            # Put stderr after stdout but keep separation for readability
            if output and not output.endswith("\n"):
                output += "\n"
            output += "[stderr]\n" + result.stderr

        # If an outfile path is provided, write the combined output there.
        if outfile:
            # use append mode for commands that may write via shell redirection too, but
            # to preserve previous behavior we will overwrite file by default.
            with open(outfile, "w") as f:
                f.write(output)

        return output
    except subprocess.TimeoutExpired:
        return f"[!] Command timed out: {command}"
    except Exception as e:
        return f"[!] Error running command: {command} | {str(e)}"



# -------- Recon Functions (quiet=True to suppress messages) -------- #

import nmap

def nmap_scan(target, outdir):
    print("[*] Running Nmap Scan using python-nmap API...")
    outfile = os.path.join(outdir, "nmap.txt")

    nm = nmap.PortScanner()
    # Equivalent of: nmap -sC -sV -T4 -Pn -p- -A
    nm.scan(target, arguments='-sC -sV -T4 -Pn -p- -A')

    results = []
    for host in nm.all_hosts():
        results.append("="*60)
        results.append(f"Nmap scan report for {host}")
        results.append(f"Host state: {nm[host].state()}")
        results.append("="*60)

        for proto in nm[host].all_protocols():
            results.append(f"\nProtocol: {proto}")
            ports = sorted(nm[host][proto].keys())

            for port in ports:
                service = nm[host][proto][port]
                line = f"{port}/{proto}\t{service['state']}\t{service['name']}"
                
                # Add optional fields if available
                if 'product' in service or 'version' in service:
                    line += f"\t{service.get('product','')} {service.get('version','')}"
                if 'extrainfo' in service and service['extrainfo']:
                    line += f" ({service['extrainfo']})"
                if 'cpe' in service and service['cpe']:
                    line += f"\tCPE: {service['cpe']}"
                
                results.append(line)

                # Include NSE script results
                if 'script' in service:
                    results.append("  [*] NSE Script Results:")
                    for script_name, script_output in service['script'].items():
                        results.append(f"    - {script_name}: {script_output}")

    output = "\n".join(results)
    with open(outfile, "w") as f:
        f.write(output)

    print(f"[+] NMAP Scan Results saved to: {outfile}")
    return output



def run_dirsearch(target, outdir):
    outfile = os.path.join(outdir, "dirsearch.txt")
    cmd = f"dirsearch -u http://{target} -e php,html,js -o {outfile}"
    run_cmd(cmd, quiet=True)
    print(f"[+] dirsearch Results saved to: {outfile}")


def run_ffuf_dir(target, outdir):
    outfile = os.path.join(outdir, "ffuf_dir.txt")
    cmd = f"ffuf -w /usr/share/wordlists/dirb/common.txt -u http://{target}/FUZZ -o {outfile} -of md"
    run_cmd(cmd, quiet=True)
    print(f"[+] FFUF_dir Results saved to: {outfile}")


def run_ffuf_subs(target, outdir):
    outfile = os.path.join(outdir, "ffuf_subs.txt")
    cmd = f"ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://FUZZ.{target} -o {outfile} -of md"
    run_cmd(cmd, quiet=True)
    print(f"[+] FFUF_subdomain Results saved to: {outfile}")


def run_nikto(target, outdir):
    outfile = os.path.join(outdir, "nikto.txt")
    cmd = f"nikto -h {target} -o {outfile}"
    run_cmd(cmd, quiet=True)
    print(f"[+] Nikto Results saved to: {outfile}")


def run_whatweb(target, outdir):
    outfile = os.path.join(outdir, "whatweb.txt")
    cmd = f"whatweb {target} --log-verbose={outfile}"
    run_cmd(cmd, quiet=True)
    print(f"[+] Whatweb Results saved to: {outfile}")


def run_snmp_enum(target, outdir):
    outfile = os.path.join(outdir, "snmpwalk.txt")
    cmd = f"snmpwalk -v2c -c public {target} > {outfile}"
    run_cmd(cmd, quiet=True)
    print(f"[+] SNMP Results saved to: {outfile}")


def run_smb_enum(target, outdir):
    outfile = os.path.join(outdir, "smb.txt")
    cmd = f"smbmap -H {target} > {outfile}"
    run_cmd(cmd, quiet=True)
    print(f"[+] SMB Results saved to: {outfile}")


def run_ftp_enum(target, outdir):
    outfile = os.path.join(outdir, "ftp.txt")
    cmd = f"nmap -p21 --script ftp-anon {target} -oN {outfile}"
    run_cmd(cmd, quiet=True)
    print(f"[+] FTP_enum Results saved to: {outfile}")


# -------- Main Orchestrator -------- #

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Custom Recon Script with Multithreading")
    parser.add_argument("target", help="Target IP or Domain")
    parser.add_argument("-o", "--outdir", default="results", help="Output directory")
    parser.add_argument("-T", "--threads", type=int, default=5, help="Number of concurrent threads")
    args = parser.parse_args()

    target = args.target
    outdir = args.outdir
    max_threads = args.threads
    os.makedirs(outdir, exist_ok=True)

    # Step 1: Nmap scan
    nmap_output = nmap_scan(target, outdir)

    # Step 2: Detect open ports & trigger specific enumeration
    open_ports = re.findall(r"(\d+)/tcp\s+open\s+(\S+)", nmap_output)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = []

            for port, service in open_ports:
                if service in ["http", "https"]:
                    futures.append(executor.submit(run_dirsearch, target, outdir))
                    futures.append(executor.submit(run_ffuf_dir, target, outdir))
                    futures.append(executor.submit(run_nikto, target, outdir))
                    futures.append(executor.submit(run_whatweb, target, outdir))

                if service == "snmp":
                    futures.append(executor.submit(run_snmp_enum, target, outdir))

                if service in ["microsoft-ds", "smb"]:
                    futures.append(executor.submit(run_smb_enum, target, outdir))

                if service == "ftp":
                    futures.append(executor.submit(run_ftp_enum, target, outdir))

            # Subdomain enumeration only if domain input
            if not re.match(r"^\d+\.\d+\.\d+\.\d+$", target):
                futures.append(executor.submit(run_ffuf_subs, target, outdir))

            # Wait for all tasks to complete
            for f in concurrent.futures.as_completed(futures):
                try:
                    f.result()
                except Exception:
                    pass  # silently ignore thread errors

    except KeyboardInterrupt:
        print("\n[!] Ctrl+C detected. Exiting gracefully...")
        sys.exit(0)

    print(f"\n[+] Recon complete! Results stored in: {outdir}/")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Ctrl+C detected. Exiting...")
        sys.exit(0)
