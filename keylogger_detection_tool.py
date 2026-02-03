import os
import sys
import re
import json
import hashlib
import argparse
import subprocess
from datetime import datetime

#!/usr/bin/env python3
"""
Keylogger Detection Tool
- Scans running processes, autoruns, scheduled tasks, and common paths for suspicious artifacts.
- Designed for Windows (falls back to process scan on other OSes).
"""


# Optional dependencies
try:
    import psutil
except Exception:
    psutil = None

if os.name == "nt":
    try:
        import winreg
    except Exception:
        winreg = None
else:
    winreg = None

SUSPICIOUS_PATTERNS = [
    r"key[-_ ]?log(?:ger|ging)?",
    r"keystroke",
    r"key ?capture",
    r"keyhook",
    r"key ?hook",
    r"keyboard.*hook",
    r"pw(?:word)?logger",
    r"credential.*steal",
    r"logger",
    r"hookdll",
]
SUSPICIOUS_RE = re.compile("|".join(SUSPICIOUS_PATTERNS), re.IGNORECASE)

COMMON_SCAN_DIRS = [
    os.environ.get("ProgramFiles", r"C:\Program Files"),
    os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
    os.path.join(os.environ.get("USERPROFILE", r"C:\Users\Default"), "AppData"),
    r"C:\Windows\System32",
]

REG_RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
] if winreg else []

def sha256_of_file(path, max_read=10*1024*1024):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            total = 0
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
                total += len(chunk)
                if total >= max_read:
                    break
        return h.hexdigest()
    except Exception:
        return None

def scan_processes():
    findings = []
    if not psutil:
        return findings
    for p in psutil.process_iter(attrs=["pid", "name", "exe", "cmdline", "username"]):
        info = p.info
        text_fields = " ".join(filter(None, [info.get("name") or "", " ".join(info.get("cmdline") or [])]))
        if SUSPICIOUS_RE.search(text_fields):
            findings.append({
                "type": "process",
                "pid": info.get("pid"),
                "name": info.get("name"),
                "exe": info.get("exe"),
                "cmdline": info.get("cmdline"),
                "username": info.get("username"),
                "matched_text": text_fields,
            })
        else:
            # also check loaded modules/DLL names (best-effort)
            try:
                mods = []
                for m in p.memory_maps():
                    path = getattr(m, "path", None)
                    if path and SUSPICIOUS_RE.search(os.path.basename(path)):
                        mods.append(path)
                if mods:
                    findings.append({
                        "type": "process_modules",
                        "pid": info.get("pid"),
                        "name": info.get("name"),
                        "exe": info.get("exe"),
                        "matched_modules": mods,
                    })
            except Exception:
                continue
    return findings

def scan_autoruns():
    findings = []
    if not winreg:
        return findings
    for hive, keypath in REG_RUN_KEYS:
        try:
            with winreg.OpenKey(hive, keypath, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(k, i)
                        i += 1
                        entry = {"name": name, "value": value, "registry_key": keypath}
                        if SUSPICIOUS_RE.search(name) or SUSPICIOUS_RE.search(value):
                            findings.append({"type": "autorun", **entry})
                        else:
                            # try to extract executable path
                            m = re.search(r'(?:"([^"]+)"|([^\s]+))', value)
                            path = (m.group(1) if m and m.group(1) else (m.group(2) if m else None))
                            if path and os.path.isfile(path) and SUSPICIOUS_RE.search(os.path.basename(path)):
                                entry["exe_path"] = path
                                findings.append({"type": "autorun", **entry})
                    except OSError:
                        break
        except Exception:
            continue
    # Startup folders
    try:
        user_start = os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
        common_start = os.path.join(os.environ.get("ProgramData", ""), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
        for folder in [user_start, common_start]:
            if os.path.isdir(folder):
                for fname in os.listdir(folder):
                    full = os.path.join(folder, fname)
                    if SUSPICIOUS_RE.search(fname) or (os.path.isfile(full) and SUSPICIOUS_RE.search(os.path.basename(full))):
                        findings.append({"type": "startup_folder", "path": full, "folder": folder})
    except Exception:
        pass
    return findings

def scan_schtasks():
    findings = []
    try:
        proc = subprocess.run(["schtasks", "/query", "/fo", "LIST", "/v"], capture_output=True, text=True, timeout=10)
        out = proc.stdout
        # Split per task
        tasks = out.split("\n\n")
        for t in tasks:
            if not t.strip():
                continue
            if SUSPICIOUS_RE.search(t):
                # try to extract TaskName and actions
                name_match = re.search(r"TaskName:\s*(.+)", t)
                action_match = re.search(r"Actions:\s*(.+)", t)
                findings.append({
                    "type": "scheduled_task",
                    "raw": t.strip(),
                    "task_name": name_match.group(1).strip() if name_match else None,
                    "actions": action_match.group(1).strip() if action_match else None,
                })
    except Exception:
        pass
    return findings

def scan_files(paths, max_files=1000):
    findings = []
    count = 0
    for base in paths:
        if not base or not os.path.exists(base):
            continue
        for root, dirs, files in os.walk(base):
            for f in files:
                count += 1
                name = f
                full = os.path.join(root, f)
                if SUSPICIOUS_RE.search(name):
                    findings.append({
                        "type": "file",
                        "path": full,
                        "name": name,
                        "sha256": sha256_of_file(full),
                    })
                if count >= max_files:
                    return findings
    return findings

def run_scan(args):
    results = {"meta": {"started": datetime.utcnow().isoformat() + "Z", "args": vars(args)}, "findings": []}
    results["findings"].extend(scan_processes())
    if args.quick:
        results["meta"]["mode"] = "quick"
    else:
        results["findings"].extend(scan_autoruns())
        results["findings"].extend(scan_schtasks())
        if args.full:
            results["findings"].extend(scan_files(args.paths, max_files=args.max_files))
        results["meta"]["mode"] = "full" if args.full else "standard"
    results["meta"]["finished"] = datetime.utcnow().isoformat() + "Z"
    return results

def parse_args():
    p = argparse.ArgumentParser(description="Keylogger detection tool (Windows-focused).")
    p.add_argument("--quick", action="store_true", help="Quick scan (processes only).")
    p.add_argument("--full", action="store_true", help="Include file system scan (can be slow).")
    p.add_argument("--paths", nargs="*", default=COMMON_SCAN_DIRS, help="Paths to scan for suspicious filenames.")
    p.add_argument("--max-files", type=int, default=2000, help="Maximum files to inspect during file scan.")
    p.add_argument("--output", "-o", help="Write JSON results to file.")
    return p.parse_args()

def main():
    args = parse_args()
    results = run_scan(args)
    out = json.dumps(results, indent=2)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out)
        except Exception as e:
            print("Failed to write output:", e, file=sys.stderr)
    print(out)

if __name__ == "__main__":
    main()