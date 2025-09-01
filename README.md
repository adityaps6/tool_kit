# Recon & Enumeration Toolkit

This repository is a growing collection of tools designed to **automate reconnaissance, enumeration, exploitation, and related workflows** in a much simpler and more efficient way. The goal is to speed up repetitive tasks during penetration testing, Capture the Flag (CTF) competitions, and red team engagements.

---

## 📌 recon.py

`recon.py` is a Python-based automation script that orchestrates common recon and enumeration tasks against a given target. Instead of manually running multiple tools, this script chains them together, organizes results, and saves you valuable time.

### ✨ Features
- **Automated Nmap Scan**  
  - Service/version detection (`-sC -sV`)  
  - Output neatly saved in `results/nmap.txt`

- **Web Enumeration** (if HTTP/HTTPS detected)  
  - `dirsearch` for hidden directories  
  - `ffuf` for directory fuzzing  
  - `nikto` for vulnerability scanning  
  - `whatweb` for web technology detection  

- **Service-Specific Enumeration**  
  - **SNMP** → `snmpwalk`  
  - **SMB** → `smbmap`  
  - **FTP** → `nmap ftp-anon`  

- **Subdomain Enumeration** (if input is a domain)  
  - `ffuf` with top subdomains wordlist

- **Parallel Execution**  
  - Leverages `ThreadPoolExecutor` to run multiple scans concurrently  

- **Organized Output**  
  - All results saved into a chosen output directory (`results/` by default)  

---

## ⚡ Usage

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/recon-toolkit.git
cd recon-toolkit
