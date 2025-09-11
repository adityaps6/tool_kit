# 🛠️ Recon & Exploitation Toolkit

This repository contains two powerful Python-based tools designed to **automate reconnaissance, enumeration, exploitation, and vulnerability testing**.  
The goal is to streamline workflows for **penetration testers, red teamers, and CTF players**, reducing repetitive tasks and speeding up the process of finding attack paths.

---

## 📌 Tools Overview

### 🔎 recon.py
`recon.py` automates **reconnaissance and enumeration** by chaining multiple tools together. It scans a target, identifies services, and runs targeted enumeration modules.  

**Key Features**
- Automated **Nmap** scans (`-sC -sV`)  
- Web enumeration (`dirsearch`, `ffuf`, `nikto`, `whatweb`)  
- Service-specific modules (SMB, SNMP, FTP)  
- Subdomain enumeration (for domains)  
- Parallel execution with `ThreadPoolExecutor`  
- Organized outputs saved under `results/`  

---

### 💥 pwny.py
`pwny.py` focuses on **exploitation assistance** by automating CVE lookups, exploit generation, and basic web vuln testing.  

**Key Features**
- **Auto-CVE Fetcher**  
  - Query public CVE databases (`cve.circl.lu`)  
  - Rank CVEs by severity, remote/local, and authentication  
- **Exploit Launcher**  
  - Predefined templates (Tomcat RCE, PHP LFI, etc.)  
  - Auto-fill with target IP/port, path, and payload  
- **Web Vulnerability Tester**  
  - Quick payload injection for XSS, SQLi, LFI, RFI, and Command Injection  
  - Simple detection heuristics + logging to `logs/`  

---

### 🧩 explr.py

`explr.py` is a **CVE Exploit & POC Finder** that automates searching multiple sources for proof-of-concept exploits and references to a given CVE. It saves results in JSON and plain text formats, including detailed grep.app hits.

**Key Features**

- Multi-source CVE search:

- GitHub for repos and POC files (.py, .sh, .txt, .rb, .pl, .exe)

- grep.app for code references across multiple languages (Python, JavaScript, YAML, JSON, Markdown)

  - Owner ID tracking for grep.app results

  - Multi-threaded searches for faster results

  - Output saved in organized folders (explr_results/ by default)

  - Separate TXT output for grep.app hits with snippets and branch info

---

## ⚡ Usage

### 🔎 recon.py
```bash
# Basic usage
python3 recon.py <target>

# Specify output directory
python3 recon.py <target> -o results/htb_machine

# Run with more threads
python3 recon.py <target> -o results/ -T 10

---
```

### 💥 pwny.py
```bash

chmod +x pwny.py

# Fetch CVEs for a product/version
./pwny.py cve apache 2.4.49

# Generate exploit from template
./pwny.py exploit tomcat_rce --target 10.10.10.10 --path testapp --payload "<% out.println('pwned'); %>"

# Test for common web vulnerabilities
./pwny.py webtest http://10.10.10.10/index.php

---
```
### 🧩 explr.py
```bash
# Basic CVE search and results are by default stored in explr_results directory
python3 explr.py CVE-2023-12345

# Specify a custom output directory
python3 explr.py CVE-2023-12345 -o my_results/

---
```
### 🧩 enum.py

`enumpy` is a new tool under development to enhance and perform enumeration more efficiently.