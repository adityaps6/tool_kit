import os

WORDLIST_PATHS = [
    os.path.expanduser("~/SecLists"),
    "/usr/share/wordlists",
    "/usr/share/seclists",
]

MAX_WORDLIST_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB

def find_wordlists(mode):
    results = []
    for base in WORDLIST_PATHS:
        if not os.path.isdir(base):
            continue
        for root, _, files in os.walk(base):
            for fname in files:
                path = os.path.join(root, fname)
                if not os.path.isfile(path):
                    continue
                # skip compressed archives
                if path.endswith((".gz", ".bz2", ".xz", ".zip", ".7z")):
                    continue
                try:
                    size = os.path.getsize(path)
                except OSError:
                    continue
                if size > MAX_WORDLIST_SIZE_BYTES:
                    continue
                lowname = fname.lower()
                if mode == "subdomains":
                    if any(k in lowname for k in ("sub", "subdomain", "host", "dns", "names")) or size < 500_000:
                        results.append(path)
                elif mode == "dirs":
                    if any(k in lowname for k in ("dir", "common", "word", "raft", "busted")):
                        results.append(path)
    return sorted(results, key=os.path.getsize)

if __name__ == "__main__":
    subs = find_wordlists("subdomains")
    dirs = find_wordlists("dirs")

    print("\n=== Subdomain wordlists ===")
    for wl in subs:
        print(wl)

    print("\n=== Directory wordlists ===")
    for wl in dirs:
        print(wl)
