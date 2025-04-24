# vuln_pattern_sweeper.py - Pattern-based static analyzer for vuln leads

import re
import argparse
from pathlib import Path

# 🧨 Patterns to detect
PATTERNS = {
    "static_buffer": re.compile(r"\b(?:char|uint8_t|unsigned char)\s+\w+\s*\[\s*\d+\s*\]"),
    "memcpy_call": re.compile(r"\bmemcpy\s*\(.*\)"),
    "ntohs_parse": re.compile(r"ntohs\s*\(.*\)"),
    "raw_uint16_cast": re.compile(r"\*\s*\(\s*uint16_t\s*\*\)\s*\(.*\)"),
    "option_length_usage": re.compile(r"\boption_length\b"),
    "no_bounds_check": re.compile(r"memcpy\s*\(\s*[^,]+,[^,]+,\s*ntohs\(.*\)\s*\)")
}

# 🔍 Scan a file and return matched lines

def scan_file(file_path):
    results = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            for idx, line in enumerate(lines):
                matches = []
                for key, pattern in PATTERNS.items():
                    if pattern.search(line):
                        matches.append(key)
                if matches:
                    results.append({
                        "file": str(file_path),
                        "line": idx + 1,
                        "code": line.strip(),
                        "tags": matches
                    })
    except Exception as e:
        print(f"[!] Error reading {file_path}: {e}")
    return results

# 🚀 Entry point

def main():
    parser = argparse.ArgumentParser(description="🛡️ Static analyzer for vuln-like C patterns")
    parser.add_argument("--target", type=str, required=True, help="Target file or directory to scan")
    args = parser.parse_args()

    path = Path(args.target)
    files = []
    if path.is_file():
        files = [path] if path.suffix in [".c", ".cpp"] else []
    else:
        files = list(path.rglob("*.c")) + list(path.rglob("*.cpp"))

    all_matches = []
    for f in files:
        all_matches.extend(scan_file(f))

    for match in all_matches:
        print(f"\n📄 {match['file']}:{match['line']}")
        print(f"   🧠 Code: {match['code']}")
        print(f"   🏷️ Tags: {', '.join(match['tags'])}")

    if not all_matches:
        print("✅ No patterns matched. Looks clean (or tricky).")
    else:
        print("\n🚨 Manual review suggested for flagged files!")

if __name__ == "__main__":
    main()