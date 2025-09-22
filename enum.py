#!/usr/bin/env python3
"""
enumerator.py (updated)

Features added:
 - Integrates amass and subfinder for subdomain enumeration when available.
 - Optional asynchronous DNS resolution for discovered subdomains (--resolve).
 - Immediate incremental logging; resolution results appended later (non-blocking).
 - Deduplication of logged discoveries (in-memory for this run).

Usage:
    python3 enumerator.py --target example.com --modes subdomains,dirs --concurrency 4 --resolve

Notes:
 - Requires Python 3.8+
 - External tools (best-effort): gobuster, ffuf, dirsearch, amass, subfinder
"""
import argparse
import asyncio
import shutil
import re
import os
from pathlib import Path
import time
from datetime import datetime
import sys
import socket

# --- Configuration / heuristics ---
WORDLIST_PATHS = [
    "/usr/share/seclists",
    "/usr/share/SecLists",
    "/usr/share/wordlists",
    "/opt/seclists",
    str(Path.home() / "wordlists"),
]

MAX_WORDLIST_SIZE_BYTES = 50 * 1024 * 1024  # ignore lists larger than 50MB by default
CONCURRENT_JOBS_DEFAULT = 4

# --- Utilities ---
def find_wordlists(mode: str):
    """
    Walk candidate paths and collect wordlist files appropriate for mode.
    mode in ("subdomains","dirs")
    Heuristics explained in original script.
    """
    candidates = []
    seen = set()
    patterns_sub = re.compile(r"(sub|subdomain|host|dns|vhost|virtual)", re.I)
    patterns_dir = re.compile(r"(dir|directory|common|word|raft|discover|busted|fuzz|big|common|top)", re.I)

    for base in WORDLIST_PATHS:
        p = Path(base)
        if not p.exists():
            continue
        for f in p.rglob("*"):
            if not f.is_file():
                continue
            if f.name.endswith((".gz", ".xz", ".bz2")):
                continue
            try:
                size = f.stat().st_size
            except OSError:
                continue
            if size == 0 or size > MAX_WORDLIST_SIZE_BYTES:
                continue
            key = str(f.resolve())
            if key in seen:
                continue
            seen.add(key)

            name = f.name.lower()
            if mode == "subdomains":
                if patterns_sub.search(name) or len(name.split(".")) == 1 or size < 20000:
                    candidates.append(str(f))
            elif mode == "dirs":
                if patterns_dir.search(name) or "common" in name or name.endswith("words") or size > 2000:
                    candidates.append(str(f))
    candidates = sorted(candidates, key=lambda p: os.path.getsize(p))
    return candidates


def ensure_dirs():
    Path("enum_result").mkdir(parents=True, exist_ok=True)
    Path("enum_direct").mkdir(parents=True, exist_ok=True)


def timestamped_filename(prefix: str, target: str):
    t = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    safe_target = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
    return f"{prefix}/{safe_target}_{t}.txt"


def is_tool_installed(name):
    return shutil.which(name) is not None


# --- Parsers for tool output (kept and extended) ---
def parse_gobuster_dns_line(line: str):
    m = re.search(r"Found:\s*(\S+)", line)
    if m:
        return m.group(1).strip()
    m = re.search(r"([A-Za-z0-9\.-]+\.[A-Za-z]{2,})", line)
    return m.group(1).strip() if m else None


def parse_gobuster_dir_line(line: str):
    m = re.search(r"(/\S+)\s+\(Status:\s*([0-9]{3})\)", line)
    if m:
        return m.group(1).strip(), m.group(2)
    m2 = re.search(r"^\[.+\]\s+(\S+)\s+\[([0-9]{3})\]", line)
    if m2:
        return m2.group(1).strip(), m2.group(2)
    return None


def parse_ffuf_line(line: str):
    m = re.search(r"(https?://\S+)\s+\[Status:\s*([0-9]{3})", line)
    if m:
        return m.group(1), m.group(2)
    m2 = re.search(r"(/\S+)\s+\(([0-9]{3})\)", line)
    if m2:
        return m2.group(1), m2.group(2)
    return None


GENERIC_HOST_REGEX = re.compile(
    r"\b([a-zA-Z0-9][a-zA-Z0-9\-\_]{0,62}\.)+[A-Za-z]{2,63}\b"
)


# --- Async DNS resolution (non-blocking) ---
async def resolve_and_log(host: str, log_path: str):
    """
    Resolve `host` to IP addresses asynchronously and append a resolution line to the given log.
    This runs in the event loop (uses loop.getaddrinfo). No blocking wait for discoveries.
    """
    try:
        loop = asyncio.get_event_loop()
        # getaddrinfo can return duplicates; gather addresses
        infos = await loop.getaddrinfo(host, None, proto=0)
        ips = []
        for inf in infos:
            sockaddr = inf[4]
            ip = sockaddr[0]
            ips.append(ip)
        ips = sorted(set(ips))
    except Exception as e:
        ips = []
    ts = datetime.utcnow().isoformat() + "Z"
    entry = f"{ts}\t{host}\tRESOLVED\t{','.join(ips) if ips else 'NONE'}\n"
    # append resolution result
    with open(log_path, "a", buffering=1) as f:
        f.write(entry)
        f.flush()


# --- Stream reader with dedupe and optional resolver ---
async def stream_and_parse(proc, parse_mode, log_path, base_target, seen_set, resolve_enabled):
    """
    Read stdout lines from proc and parse discoveries. Append the discovery immediately if new.
    If resolve_enabled and a subdomain is discovered, schedule an async resolver that appends a resolution line later.
    """
    loop = asyncio.get_event_loop()
    # Keep the file open for repeated appends for efficiency
    with open(log_path, "a", buffering=1) as log_f:
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            try:
                text = line.decode(errors="ignore").rstrip()
            except Exception:
                text = str(line)
            found = None
            # parse based on mode
            if parse_mode == "subdomains":
                dom = parse_gobuster_dns_line(text)
                if dom:
                    found = dom
                else:
                    m = GENERIC_HOST_REGEX.search(text)
                    if m:
                        found = m.group(0)
                if found:
                    # normalize: lower
                    found = found.strip().lower()
                    if found not in seen_set:
                        seen_set.add(found)
                        ts = datetime.utcnow().isoformat() + "Z"
                        entry = f"{ts}\t{found}\n"
                        log_f.write(entry)
                        log_f.flush()
                        # schedule resolution if requested
                        if resolve_enabled:
                            # create a background task to resolve and append resolution result
                            loop.create_task(resolve_and_log(found, log_path))
            elif parse_mode == "dirs":
                g = parse_gobuster_dir_line(text)
                logged = None
                if g:
                    path, status = g
                    url = base_target if base_target.startswith("http://") or base_target.startswith("https://") else "http://" + base_target
                    full = url.rstrip("/") + path
                    logged = f"{full} {status}"
                else:
                    ff = parse_ffuf_line(text)
                    if ff:
                        url, status = ff
                        logged = f"{url} {status}"
                    else:
                        m = re.search(r"(/\S+)\s+\(?([0-9]{3})\)?", text)
                        if m:
                            path, status = m.group(1), m.group(2)
                            url = (base_target if base_target.startswith("http") else "http://" + base_target).rstrip("/") + path
                            logged = f"{url} {status}"
                if logged:
                    if logged not in seen_set:
                        seen_set.add(logged)
                        ts = datetime.utcnow().isoformat() + "Z"
                        entry = f"{ts}\t{logged}\n"
                        log_f.write(entry)
                        log_f.flush()
    await proc.wait()


# --- Runner wrapper ---
async def run_command_and_stream(cmd, parse_mode, log_path, base_target, seen_set, resolve_enabled):
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
    except FileNotFoundError:
        print(f"[!] Tool missing: {cmd[0]} - skipping this invocation.")
        return
    await stream_and_parse(proc, parse_mode, log_path, base_target, seen_set, resolve_enabled)


# --- Launchers for supported tools ---
async def launch_gobuster_dns(wordlist, domain, log_path, seen_set, resolve_enabled):
    cmd = ["gobuster", "dns", "-d", domain, "-w", wordlist, "-q"]
    print(f"[+] Starting gobuster dns with {wordlist}")
    await run_command_and_stream(cmd, "subdomains", log_path, domain, seen_set, resolve_enabled)


async def launch_gobuster_dir(wordlist, base_url, log_path, seen_set, resolve_enabled):
    url = base_url if base_url.startswith("http://") or base_url.startswith("https://") else "http://" + base_url
    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q"]
    print(f"[+] Starting gobuster dir with {wordlist}")
    await run_command_and_stream(cmd, "dirs", log_path, url, seen_set, resolve_enabled)


async def launch_ffuf(wordlist, base_url, log_path, seen_set, resolve_enabled):
    url = base_url if base_url.startswith("http://") or base_url.startswith("https://") else "http://" + base_url
    target = url.rstrip("/") + "/FUZZ"
    cmd = ["ffuf", "-u", target, "-w", wordlist, "-mc", "all", "-s"]
    print(f"[+] Starting ffuf with {wordlist}")
    await run_command_and_stream(cmd, "dirs", log_path, url, seen_set, resolve_enabled)


async def launch_dirsearch(wordlist, base_url, log_path, seen_set, resolve_enabled):
    url = base_url if base_url.startswith("http://") or base_url.startswith("https://") else "http://" + base_url
    ds_bin = shutil.which("dirsearch") or shutil.which("dirsearch.py")
    if ds_bin:
        cmd = [ds_bin, "-u", url, "-w", wordlist, "--simple-report", "/dev/stdout"]
    else:
        cmd = ["python3", "-m", "dirsearch", "-u", url, "-w", wordlist, "--simple-report", "/dev/stdout"]
    print(f"[+] Starting dirsearch with {wordlist}")
    await run_command_and_stream(cmd, "dirs", log_path, url, seen_set, resolve_enabled)


# New: amass and subfinder launchers
async def launch_amass(domain, log_path, seen_set, resolve_enabled):
    # amass enum -d example.com -silent
    cmd = ["amass", "enum", "-d", domain, "-silent"]
    print(f"[+] Starting amass enum for {domain}")
    await run_command_and_stream(cmd, "subdomains", log_path, domain, seen_set, resolve_enabled)


async def launch_subfinder(domain, log_path, seen_set, resolve_enabled):
    # subfinder -d example.com -silent
    cmd = ["subfinder", "-d", domain, "-silent"]
    print(f"[+] Starting subfinder for {domain}")
    await run_command_and_stream(cmd, "subdomains", log_path, domain, seen_set, resolve_enabled)


# --- Orchestration ---
async def enumerate_target(target, modes, concurrency, resolve_enabled):
    ensure_dirs()
    sub_log = timestamped_filename("enum_result", target)
    dir_log = timestamped_filename("enum_direct", target)

    print(f"[+] Subdomain log: {sub_log}")
    print(f"[+] Directory log: {dir_log}")

    sublists = find_wordlists("subdomains") if "subdomains" in modes else []
    dirlists = find_wordlists("dirs") if "dirs" in modes else []

    if "subdomains" in modes and not sublists:
        print("[!] No system subdomain lists found; using small built-in candidate list.")
        small = Path("inline_subs.txt")
        small.write_text("\n".join(["www", "dev", "test", "stage", "staging", "api", "mail", "web"]))
        sublists = [str(small)]
    if "dirs" in modes and not dirlists:
        print("[!] No system directory lists found; using small built-in candidate list.")
        small = Path("inline_dirs.txt")
        small.write_text("\n".join(["admin", "login", "uploads", "assets", "images", "css", "js"]))
        dirlists = [str(small)]

    sem = asyncio.Semaphore(concurrency)
    tasks = []

    async def sem_spawn(coro):
        async with sem:
            await coro

    # Dedup sets per run
    seen_subdomains = set()
    seen_dirs = set()

    # Subdomain jobs
    if "subdomains" in modes:
        # amass & subfinder if available
        if is_tool_installed("amass"):
            tasks.append(asyncio.create_task(sem_spawn(launch_amass(target, sub_log, seen_subdomains, resolve_enabled))))
        else:
            print("[!] amass not found; skipping amass jobs.")

        if is_tool_installed("subfinder"):
            tasks.append(asyncio.create_task(sem_spawn(launch_subfinder(target, sub_log, seen_subdomains, resolve_enabled))))
        else:
            print("[!] subfinder not found; skipping subfinder jobs.")

        # fallback to gobuster dns using selected wordlists (if gobuster available)
        if is_tool_installed("gobuster"):
            for wl in sublists:
                tasks.append(asyncio.create_task(sem_spawn(launch_gobuster_dns(wl, target, sub_log, seen_subdomains, resolve_enabled))))
        else:
            print("[!] gobuster not found; gobuster dns skipped if amass/subfinder missing.")

    # Directory jobs
    if "dirs" in modes:
        if is_tool_installed("gobuster"):
            for wl in dirlists:
                tasks.append(asyncio.create_task(sem_spawn(launch_gobuster_dir(wl, target, dir_log, seen_dirs, resolve_enabled))))
        else:
            print("[!] gobuster not found; skipping gobuster dir jobs.")
        if is_tool_installed("ffuf"):
            for wl in dirlists:
                tasks.append(asyncio.create_task(sem_spawn(launch_ffuf(wl, target, dir_log, seen_dirs, resolve_enabled))))
        else:
            print("[!] ffuf not found; ffuf jobs skipped.")
        if is_tool_installed("dirsearch") or shutil.which("dirsearch.py"):
            for wl in dirlists:
                tasks.append(asyncio.create_task(sem_spawn(launch_dirsearch(wl, target, dir_log, seen_dirs, resolve_enabled))))
        else:
            print("[!] dirsearch not found; skipping.")

    if not tasks:
        print("[!] No scanning jobs scheduled (missing tools or modes). Exiting.")
        return

    print(f"[+] Launched {len(tasks)} jobs (concurrency={concurrency}). Press Ctrl-C to abort.")
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        print("[!] Tasks cancelled.")
    except KeyboardInterrupt:
        print("[!] Interrupted by user. Attempting graceful shutdown...")
    finally:
        print("[+] Enumeration finished (or stopped).")
        print(f"[+] Subdomains saved to {sub_log}")
        print(f"[+] Directories saved to {dir_log}")


# --- CLI entrypoint ---
def parse_args():
    p = argparse.ArgumentParser(description="Concurrent enumerator (subdomains + dirs) using system wordlists")
    p.add_argument("--target", "-t", required=True, help="Target domain or IP (if IP hosts site, include scheme optionally)")
    p.add_argument("--modes", "-m", default="subdomains,dirs", help="Comma-separated modes: subdomains,dirs (default both)")
    p.add_argument("--concurrency", "-c", type=int, default=CONCURRENT_JOBS_DEFAULT, help="Max concurrent jobs")
    p.add_argument("--resolve", "-r", action="store_true", help="Resolve discovered subdomains to IPs and append results")
    return p.parse_args()


def main():
    args = parse_args()
    modes = [m.strip().lower() for m in args.modes.split(",") if m.strip()]
    allowed = {"subdomains", "dirs"}
    modes = [m for m in modes if m in allowed]
    if not modes:
        print("[!] No valid modes selected. Choose from subdomains,dirs")
        sys.exit(1)

    print(f"[+] Target: {args.target}")
    print(f"[+] Modes: {modes}")
    print(f"[+] Concurrency: {args.concurrency}")
    print(f"[+] Resolve enabled: {args.resolve}")

    try:
        asyncio.run(enumerate_target(args.target, modes, args.concurrency, args.resolve))
    except KeyboardInterrupt:
        print("[!] User cancelled.")


if __name__ == "__main__":
    main()
