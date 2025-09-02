#!/usr/bin/env python3
"""
Process Anomaly Detector (Training)
- Flags simple suspicious signals:
  * System processes running from user-writable directories
  * Unusual parent-child combos (e.g., office apps spawning shells)
  * Processes with network connections from temp folders

Outputs a table and writes CSV to ./results/process_flags.csv
"""
import psutil, os, csv, pathlib

SUS_PARENTS = {"WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE","outlook.exe","chrome.exe","firefox.exe"}
SHELLS = {"cmd.exe","powershell.exe","bash","sh","zsh"}
USER_DIR_HINTS = ["\\Users\\", "/home/"]
TEMP_HINTS = ["\\AppData\\Local\\Temp", "/tmp", "/var/tmp"]

def is_user_dir(path):
    p = (path or "").lower()
    return any(h in p for h in USER_DIR_HINTS)

def is_temp(path):
    p = (path or "").lower()
    return any(h in p for h in TEMP_HINTS)

def main():
    results=[]
    for p in psutil.process_iter(['pid','name','exe','ppid','username']):
        try:
            info = p.info
            parent = ""
            try:
                parent = psutil.Process(info['ppid']).name() if info.get('ppid') else ""
            except Exception:
                parent = ""
            exe = info.get('exe') or ""
            # Rule 1: shell spawned by office/browser
            if parent in SUS_PARENTS and info['name'] in SHELLS:
                results.append(("parent_shell", info['pid'], info['name'], parent, exe))
            # Rule 2: shell from user dir
            if info['name'].lower() in (n.lower() for n in SHELLS) and is_user_dir(exe):
                results.append(("shell_in_userdir", info['pid'], info['name'], parent, exe))
            # Rule 3: temp binary with inet conns
            if is_temp(exe):
                for c in p.connections(kind='inet'):
                    if c.raddr:
                        results.append(("temp_with_net", info['pid'], info['name'], parent, exe))
                        break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if not results:
        print("[✓] No simple anomalies flagged.")
    else:
        print("type,pid,name,parent,exe")
        for r in results:
            print(",".join(str(x) for x in r))

    pathlib.Path("results").mkdir(exist_ok=True)
    with open("results/process_flags.csv","w",newline="") as f:
        w=csv.writer(f)
        w.writerow(["type","pid","name","parent","exe"])
        for r in results: w.writerow(r)
    print("[*] CSV written to results/process_flags.csv")

if __name__ == "__main__":
    main()
