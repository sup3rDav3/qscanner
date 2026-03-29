# qscanner

A lightweight Python port scanner built for penetration testers. No third-party dependencies — pure standard library.

Scans a single host or a list of hosts across key ports, with deep checks on FTP and SSH, and a clean risk summary at the end.

---

## Features

- **3-stage pre-scan pipeline** — DNS resolution → reachability check → port scan
- **FTP anonymous login test** — detects anonymous access and directory listing exposure
- **SSH auth method detection** — identifies password authentication via OpenSSH client probe, with automatic fallback for legacy servers (OpenSSH 4.x)
- **Banner grabbing** — captures service banners on all open ports
- **Host file support** — scan a single host or a list of hosts from a file
- **Clear status labels** — `[OPEN]` / `[CLOSED]` / `[UNREACHABLE]` / `[DNS FAILURE]`
- **Risk summary** — consolidated findings across all hosts at the end
- **Elapsed time** — shows total scan duration
- **No dependencies** — pure Python standard library (optional: `ssh-audit` for richer SSH analysis)

---

## Ports Scanned

| Port | Service |
|------|---------|
| 21 | FTP (+ anonymous login check) |
| 22 | SSH (+ auth method detection) |
| 23 | Telnet |
| 1433 | MSSQL |
| 3308 | MySQL (alt) |
| 3309 | MySQL (alt) |
| 3389 | RDP |

---

## Usage

**Single host:**
```bash
python3 qscanner.py 192.168.1.100
```

**Host file:**
```bash
python3 qscanner.py -f hosts.txt
```

**Host file format** — one entry per line, `#` for comments:
```
# Lab targets
192.168.1.152   # Metasploitable2
192.168.1.101   # web server
# 10.0.0.6      skipped
```

---

## Example Output

```
Penetration Testing Port Scanner
Targets : 4 host(s)
Ports   : 21, 22, 23, 1433, 3308, 3309, 3389
Started : 2026-03-29 14:41:02

────────────────────────────────────────────────────────────
  Stage 1 — DNS Resolution
────────────────────────────────────────────────────────────
  [RESOLVED]     192.168.1.152
  [DNS FAILURE]  doesntexist.local
                 [Errno -2] Name or service not known

────────────────────────────────────────────────────────────
  Stage 2 — Reachability Check
────────────────────────────────────────────────────────────
  (ICMP ping first, TCP probe fallback if ping is blocked)
  Probing 192.168.1.152 … [REACHABLE]
  Probing 10.0.0.99 … [UNREACHABLE]

────────────────────────────────────────────────────────────
  Stage 3 — Port Scan
────────────────────────────────────────────────────────────
     21  [OPEN]    FTP
           Banner : 220 (vsFTPd 2.3.4)
           [!] Anonymous FTP login ALLOWED
               Directory listing available (0 items)
     22  [OPEN]    SSH
           Banner : SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1
           [i] Accepted auth methods: publickey, password
           [!] Password authentication ENABLED — brute-force risk
           [+] Public-key authentication enabled
     23  [OPEN]    Telnet
           Banner : ���� ��#��'
           [!] Telnet is cleartext — credentials transmitted unencrypted
   3389  [CLOSED]  RDP

────────────────────────────────────────────────────────────
  Scan Complete — Summary
────────────────────────────────────────────────────────────
  Hosts in list             : 4
  [DNS FAILURE]             : 1  (doesntexist.local)
  [UNREACHABLE]             : 1  (10.0.0.99)
  Hosts scanned             : 2
  Hosts with open ports     : 1
  Total open ports found    : 3

  Risks identified (3 total):
    • 192.168.1.152  —  Anonymous FTP access enabled (port 21)
    • 192.168.1.152  —  SSH password authentication enabled (port 22)
    • 192.168.1.152  —  Telnet open, cleartext protocol (port 23)

  Completed in : 23.3s
```

---

## Optional: ssh-audit

For richer SSH analysis (cipher strength, key exchange algorithms, CVE cross-referencing), install `ssh-audit`:

```bash
pip install ssh-audit --break-system-packages
```

The scanner will automatically use it if available, falling back to the OpenSSH client probe if not.

---

## Requirements

- Python 3.6+
- OpenSSH client (`ssh`) — for SSH auth method detection
- Root/sudo — required for ICMP ping on some systems (falls back to TCP probe automatically if ping fails)

---

## Legal

This tool is intended for use on systems you own or have explicit written permission to test. Unauthorised scanning may be illegal in your jurisdiction. The author accepts no liability for misuse.
