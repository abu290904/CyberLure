"""
Cowrie Log Parser & Feature Extractor
Reads cowrie.json (JSONL), extracts per-session features for ML
Author: Abdul Ahad
"""

import json
import pandas as pd
import numpy as np
import os
from collections import defaultdict

# ── Suspicious command keyword lists ─────────────────────────────────────────
RECON_KEYWORDS       = ["uname","whoami","id","passwd","hostname","ifconfig","ip addr","cat /etc","ls /","df -h","free -m","cpuinfo"]
PERSISTENCE_KEYWORDS = ["wget","curl","chmod","crontab","useradd","chpasswd","echo >>",">> /etc","bash -i","nc -e","mkfifo"]
MINING_KEYWORDS      = ["xmrig","minerd","miner","stratum","monero","cryptonight","pool.","xmr.","hashrate"]
LATERAL_KEYWORDS     = ["ssh-keyscan","known_hosts","id_rsa","nmap","arp -a","ping -c","for i in","seq 1 254"]
EXFIL_KEYWORDS       = [".pem","id_rsa","shadow","bash_history","tar czf",".tgz","scp ","rsync "]


def keyword_count(text: str, keywords: list) -> int:
    text = text.lower()
    return sum(1 for kw in keywords if kw in text)


def parse_logs(log_path: str) -> pd.DataFrame:
    """Parse JSONL cowrie log → per-session feature DataFrame."""
    print(f"[*] Parsing {log_path} ...")

    sessions = defaultdict(lambda: {
        "src_ip": None,
        "country": "Unknown",
        "login_attempts": 0,
        "login_success": 0,
        "commands": [],
        "connect_time": None,
        "duration": 0,
        "dst_port": 22,
    })

    with open(log_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue

            sid = ev.get("session", "unknown")
            eid = ev.get("eventid", "")

            if eid == "cowrie.session.connect":
                sessions[sid]["src_ip"]       = ev.get("src_ip")
                sessions[sid]["country"]      = ev.get("country", "Unknown")
                sessions[sid]["connect_time"] = ev.get("timestamp")
                sessions[sid]["dst_port"]     = ev.get("dst_port", 22)

            elif eid == "cowrie.login.failed":
                sessions[sid]["login_attempts"] += 1
                if sessions[sid]["src_ip"] is None:
                    sessions[sid]["src_ip"] = ev.get("src_ip")

            elif eid == "cowrie.login.success":
                sessions[sid]["login_attempts"] += 1
                sessions[sid]["login_success"]  = 1
                if sessions[sid]["src_ip"] is None:
                    sessions[sid]["src_ip"] = ev.get("src_ip")

            elif eid == "cowrie.command.input":
                sessions[sid]["commands"].append(ev.get("input", ""))

            elif eid == "cowrie.session.closed":
                sessions[sid]["duration"] = ev.get("duration", 0)

    print(f"[+] {len(sessions)} sessions found")

    rows = []
    for sid, s in sessions.items():
        all_cmds = " ".join(s["commands"])
        rows.append({
            "session_id":        sid,
            "src_ip":            s["src_ip"] or "0.0.0.0",
            "country":           s["country"],
            "login_attempts":    s["login_attempts"],
            "login_success":     s["login_success"],
            "num_commands":      len(s["commands"]),
            "session_duration":  s["duration"],
            "dst_port":          s["dst_port"],
            "recon_score":       keyword_count(all_cmds, RECON_KEYWORDS),
            "persistence_score": keyword_count(all_cmds, PERSISTENCE_KEYWORDS),
            "mining_score":      keyword_count(all_cmds, MINING_KEYWORDS),
            "lateral_score":     keyword_count(all_cmds, LATERAL_KEYWORDS),
            "exfil_score":       keyword_count(all_cmds, EXFIL_KEYWORDS),
            "has_download":      int(any(k in all_cmds.lower() for k in ["wget","curl"])),
            "has_chmod":         int("chmod" in all_cmds.lower()),
            "has_cron":          int("cron" in all_cmds.lower()),
            "has_useradd":       int("useradd" in all_cmds.lower()),
            "raw_commands":      all_cmds[:500],
        })

    df = pd.DataFrame(rows)
    print(f"[+] Feature extraction complete — {len(df)} rows, {len(df.columns)} columns")
    return df


def save_features(df: pd.DataFrame, out_path: str = "data/features.csv"):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    df.to_csv(out_path, index=False)
    print(f"[+] Features saved to {out_path}")


if __name__ == "__main__":
    df = parse_logs("logs/cowrie.json")
    save_features(df, "data/features.csv")
    print(df.describe())
