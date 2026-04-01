#!/usr/bin/env python3
"""
Penetration Testing Port Scanner

Scans ports 21, 22, 23, 1433, 3308, 3309, 3389 with enhanced checks:
- Port 21 (FTP): tests anonymous login
- Port 22 (SSH): detects accepted authentication methods

Pre-scan pipeline (per host):
1. DNS resolution  — skip with [DNS FAILURE] if hostname won't resolve
2. Reachability    — skip with [UNREACHABLE] if host doesn't respond
3. Port scan       — [OPEN] / [CLOSED] with deep checks on ports 21 & 22

Changes vs v1:
  • FTP anonymous-login findings now appear in the final risk summary
    (with the directory-listing note, e.g. "12 items exposed")
  • Hosts are scanned in parallel — hosts take ~¼ of the original time

Usage:
  python3 qscanner.py 192.168.1.100          # single host
  python3 qscanner.py -f hosts.txt           # host file

Host file format (one entry per line, # = comment):
  192.168.1.100
  192.168.1.101   # web server
  # 10.0.0.6      skipped
"""

import socket
import ftplib
import subprocess
import sys
import os
import re
import concurrent.futures
from datetime import datetime
import time

# ── Configuration ──────────────────────────────────────────────────────────────

TARGET_PORTS = [21, 22, 23, 1433, 3308, 3309, 3389]

PORT_SERVICES = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    1433: "MSSQL",
    3308: "MySQL (alt)",
    3309: "MySQL (alt)",
    3389: "RDP",
}

CONNECT_TIMEOUT = 3   # seconds for TCP port connect
BANNER_TIMEOUT  = 2   # seconds to wait for a service banner
PING_TIMEOUT    = 1   # seconds per ping attempt
PING_COUNT      = 2   # number of ICMP echo requests to send

# Fallback TCP ports tried when ICMP ping is blocked/unavailable
# Kept short — just the two most universally open ports
REACHABILITY_PROBE_PORTS = [80, 443]
REACHABILITY_TCP_TIMEOUT = 1  # tight timeout for reachability probes (not full port scan)

# Max hosts processed concurrently in Stage 2 (reachability) and Stage 3 (scan)
PARALLEL_HOSTS = 20

# ── ANSI colours ───────────────────────────────────────────────────────────────

try:
    COLOUR = os.name != "nt" or "ANSICON" in os.environ
except Exception:
    COLOUR = False

R   = "\033[91m" if COLOUR else ""
G   = "\033[92m" if COLOUR else ""
Y   = "\033[93m" if COLOUR else ""
B   = "\033[94m" if COLOUR else ""
C   = "\033[96m" if COLOUR else ""
W   = "\033[97m" if COLOUR else ""
DIM = "\033[2m"  if COLOUR else ""
RST = "\033[0m"  if COLOUR else ""

# ── Pre-scan helpers ───────────────────────────────────────────────────────────

def dns_resolve(host: str) -> tuple:
    """
    Resolve hostname to IP. Returns (ip, error).
    Bare IPv4 addresses pass straight through without a lookup.
    """
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        return host, None
    try:
        ip = socket.gethostbyname(host)
        return ip, None
    except socket.gaierror as e:
        return None, str(e)


def icmp_ping(ip: str) -> bool:
    """
    Send ICMP echo requests using the system ping binary.
    Returns True if at least one reply is received.
    """
    if os.name == "nt":
        cmd = ["ping", "-n", str(PING_COUNT), "-w", str(PING_TIMEOUT * 1000), ip]
    else:
        cmd = ["ping", "-c", str(PING_COUNT), "-W", str(PING_TIMEOUT), ip]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=PING_TIMEOUT * PING_COUNT + 2)
        return result.returncode == 0
    except Exception:
        return False


def tcp_reachability(ip: str) -> bool:
    """
    Fallback reachability check via TCP connect on common ports.
    Uses a short timeout — we just need a SYN-ACK or RST, not a full handshake.
    """
    for port in REACHABILITY_PROBE_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=REACHABILITY_TCP_TIMEOUT):
                return True
        except Exception:
            continue
    return False


def is_reachable(ip: str) -> bool:
    """
    Returns True if the host responds to ICMP ping OR any TCP probe port.
    Tries ICMP first (fast), falls back to TCP if ping fails.
    """
    if icmp_ping(ip):
        return True
    return tcp_reachability(ip)

# ── Scan helpers ───────────────────────────────────────────────────────────────

def strip_telnet_iac(data: bytes) -> bytes:
    """
    Strip Telnet IAC (Interpret As Command) negotiation sequences.
    These are 3-byte sequences: IAC (0xFF) + command (0xFB-0xFE) + option,
    or 2-byte sequences: IAC + SE/NOP/etc (0xF0-0xFA).
    Servers send these immediately on connect before any human-readable text.
    """
    IAC = 0xFF
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == IAC and i + 1 < len(data):
            cmd = data[i + 1]
            if 0xFB <= cmd <= 0xFE and i + 2 < len(data):
                i += 3  # IAC + WILL/WONT/DO/DONT + option
            elif 0xF0 <= cmd <= 0xFA:
                i += 2  # IAC + SE/NOP/DM/BRK/etc
            else:
                i += 2  # IAC + unknown, skip both
        else:
            out.append(data[i])
            i += 1
    return bytes(out)


def grab_banner(host: str, port: int) -> str:
    """Attempt to read a plain-text service banner."""
    try:
        with socket.create_connection((host, port), timeout=BANNER_TIMEOUT) as s:
            s.settimeout(BANNER_TIMEOUT)
            data = s.recv(1024)
            if port == 23:
                data = strip_telnet_iac(data)
            return data.decode(errors="replace").strip()
    except Exception:
        return ""


def tcp_connect(host: str, port: int) -> bool:
    """Return True if a TCP connection to host:port succeeds."""
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT):
            return True
    except Exception:
        return False

# ── Port-specific deep checks ──────────────────────────────────────────────────

def check_ftp(host: str) -> dict:
    """
    Probe FTP (port 21):
    1. Grab the server banner.
    2. Attempt anonymous login (user: anonymous / pass: anonymous@example.com).
    """
    result = {"banner": "", "anonymous_login": False, "anonymous_note": ""}
    result["banner"] = grab_banner(host, 21)

    try:
        ftp = ftplib.FTP()
        ftp.connect(host, 21, timeout=CONNECT_TIMEOUT)
        ftp.login("anonymous", "anonymous@example.com")
        result["anonymous_login"] = True

        try:
            ftp.set_pasv(True)
            lines = []
            ftp.dir(".", lines.append)
            if lines:
                visible = [l for l in lines if not l.endswith(" .") and not l.endswith(" ..")]
                result["anonymous_note"] = f"Directory listing available ({len(visible)} items)"
                result["dir_listing"] = lines
            else:
                names = ftp.nlst()
                if names:
                    result["anonymous_note"] = f"Directory listing available ({len(names)} items)"
                    result["dir_listing"] = names
                else:
                    result["anonymous_note"] = "Login succeeded — directory is empty or listing blocked"
        except Exception as e:
            result["anonymous_note"] = f"Login succeeded but listing failed: {str(e)[:60]}"

        ftp.quit()

    except ftplib.error_perm as e:
        result["anonymous_note"] = f"Rejected: {str(e)[:60]}"
    except Exception as e:
        result["anonymous_note"] = f"Error: {str(e)[:60]}"

    return result


def check_ssh(host: str) -> dict:
    """
    Probe SSH (port 22):
    1. Grab the SSH version banner.
    2. Detect accepted auth methods via ssh-audit (preferred) or OpenSSH client trick.
    """
    result = {
        "banner":       "",
        "auth_methods": [],
        "password_auth": None,
        "pubkey_auth":   None,
        "note":          "",
    }
    result["banner"] = grab_banner(host, 22)

    # Try ssh-audit first
    try:
        proc = subprocess.run(
            ["ssh-audit", "--no-colors", host],
            capture_output=True, text=True, timeout=15
        )
        output = proc.stdout + proc.stderr
        if output:
            methods = []
            if "password" in output.lower():
                methods.append("password")
                result["password_auth"] = True
            if "publickey" in output.lower() or "public key" in output.lower():
                methods.append("publickey")
                result["pubkey_auth"] = True
            if "keyboard-interactive" in output.lower():
                methods.append("keyboard-interactive")
            result["auth_methods"] = methods
            result["note"] = "Detected via ssh-audit"
            return result
    except FileNotFoundError:
        pass
    except Exception:
        pass

    # Fallback: OpenSSH PreferredAuthentications=none trick.
    # Tried twice — modern defaults first, then with legacy host key algorithms
    # for older servers (e.g. OpenSSH 4.x).
    ssh_attempts = [
        [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=5",
            "-o", "PreferredAuthentications=none",
            "-p", "22",
            f"pentest_probe@{host}",
        ],
        [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=5",
            "-o", "PreferredAuthentications=none",
            "-o", "HostKeyAlgorithms=+ssh-rsa,ssh-dss",
            "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
            "-p", "22",
            f"pentest_probe@{host}",
        ],
    ]

    for cmd in ssh_attempts:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            stderr = proc.stderr.lower()

            if "no matching host key type" in stderr or "unable to negotiate" in stderr:
                continue

            if "permission denied" in stderr:
                match = re.search(r"permission denied\s*\(([^)]+)\)", stderr)
                if match:
                    methods = [m.strip() for m in match.group(1).split(",")]
                    result["auth_methods"]  = methods
                    result["password_auth"] = "password" in methods
                    result["pubkey_auth"]   = "publickey" in methods
                    result["note"]          = "Detected via SSH client probe"
                    return result
        except FileNotFoundError:
            result["note"] = "ssh client not found; install OpenSSH or ssh-audit"
            return result
        except Exception as e:
            result["note"] = f"SSH probe error: {str(e)[:60]}"

    if not result["note"]:
        result["note"] = "Could not determine auth methods (install ssh-audit for reliable detection)"
    return result

# ── Port scanner ───────────────────────────────────────────────────────────────

def scan_port(host: str, port: int) -> dict:
    """Scan a single port and return a result dict."""
    service = PORT_SERVICES.get(port, "Unknown")
    open_   = tcp_connect(host, port)

    entry = {
        "port":    port,
        "service": service,
        "open":    open_,
        "banner":  "",
        "details": {},
    }

    if not open_:
        return entry

    if port not in (21, 22):
        entry["banner"] = grab_banner(host, port)

    if port == 21:
        entry["details"] = check_ftp(host)
        entry["banner"]  = entry["details"].pop("banner", "")
    elif port == 22:
        entry["details"] = check_ssh(host)
        entry["banner"]  = entry["details"].pop("banner", "")

    return entry


def scan_host(host: str, resolved_ip: str) -> list:
    """Scan all target ports for a single host in parallel."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(TARGET_PORTS)) as pool:
        futures = {pool.submit(scan_port, resolved_ip, p): p for p in TARGET_PORTS}
        results = [f.result() for f in concurrent.futures.as_completed(futures)]
    results.sort(key=lambda r: r["port"])
    return results


def _scan_one(host: str, dns_map: dict) -> tuple:
    """Worker used by the parallel-host pool: returns (host, ip, results)."""
    ip, _ = dns_map[host]
    return host, ip, scan_host(host, ip)

# ── Output helpers ─────────────────────────────────────────────────────────────

def section(text: str) -> None:
    width = 62
    print(f"\n{C}{'─' * width}{RST}")
    print(f"{C}  {text}{RST}")
    print(f"{C}{'─' * width}{RST}")


def print_port_result(r: dict) -> None:
    port    = r["port"]
    service = r["service"]
    open_   = r["open"]
    banner_ = r.get("banner", "")
    details = r.get("details", {})

    status = f"{G}[OPEN]  {RST}" if open_ else f"{DIM}[CLOSED]{RST}"
    print(f"\n  {W}{port:5d}{RST}  {status}  {C}{service}{RST}")

    if not open_:
        return

    if banner_:
        print(f"         {DIM}Banner : {banner_.splitlines()[0][:78]}{RST}")

    if port == 21 and details:
        anon    = details.get("anonymous_login", False)
        note    = details.get("anonymous_note", "")
        listing = details.get("dir_listing", [])
        if anon:
            print(f"         {R}[!] Anonymous FTP login ALLOWED{RST}")
            print(f"         {R}    {note}{RST}")
            if listing:
                print(f"         {DIM}    Directory contents:{RST}")
                for entry in listing[:10]:
                    print(f"         {DIM}      {entry}{RST}")
                if len(listing) > 10:
                    print(f"         {DIM}      … and {len(listing) - 10} more{RST}")
        else:
            print(f"         {G}[+] Anonymous FTP login denied{RST}")
            if note:
                print(f"         {DIM}    {note}{RST}")

    if port == 22 and details:
        methods = details.get("auth_methods", [])
        pw      = details.get("password_auth")
        pk      = details.get("pubkey_auth")
        note    = details.get("note", "")
        if methods:
            print(f"         {B}[i] Accepted auth methods: {', '.join(methods)}{RST}")
        if pw is True:
            print(f"         {R}[!] Password authentication ENABLED — brute-force risk{RST}")
        elif pw is False:
            print(f"         {G}[+] Password authentication disabled{RST}")
        if pk is True:
            print(f"         {G}[+] Public-key authentication enabled{RST}")
        elif pk is False:
            print(f"         {Y}[~] Public-key authentication not detected{RST}")
        if not methods and note:
            print(f"         {Y}[~] {note}{RST}")

    if port == 23:
        print(f"         {R}[!] Telnet is cleartext — credentials transmitted unencrypted{RST}")

    if port == 3389 and open_:
        print(f"         {Y}[~] RDP exposed — ensure NLA is enforced and access is restricted{RST}")


def print_host_block(host: str, resolved_ip: str, results: list) -> None:
    open_ports = [r for r in results if r["open"]]
    ip_label   = f" → {resolved_ip}" if resolved_ip != host else ""
    section(f"Host: {host}{ip_label}  ({len(open_ports)}/{len(TARGET_PORTS)} open)")
    for r in results:
        print_port_result(r)

# ── Risk collection ────────────────────────────────────────────────────────────

def collect_risks(results: list, host: str) -> list:
    """
    Return a list of risk dicts: {host, port, severity, message}.
    severity: "CRITICAL" | "HIGH" | "MEDIUM"

    FIX: FTP anonymous-login findings now include the directory-listing note
    so the final summary shows e.g. "Directory listing available (12 items)".
    """
    risks = []

    for r in results:
        if not r["open"]:
            continue

        details = r.get("details", {})

        if r["port"] == 21 and details.get("anonymous_login"):
            note = details.get("anonymous_note", "")
            msg  = "Anonymous FTP access enabled (port 21)"
            if note:
                msg += f" — {note}"
            risks.append({"host": host, "port": 21, "severity": "CRITICAL", "message": msg})

        if r["port"] == 22 and details.get("password_auth"):
            risks.append({
                "host": host, "port": 22, "severity": "HIGH",
                "message": "SSH password authentication enabled (port 22) — brute-force risk",
            })

        if r["port"] == 23:
            risks.append({
                "host": host, "port": 23, "severity": "HIGH",
                "message": "Telnet open, cleartext protocol (port 23)",
            })

        if r["port"] == 3389:
            risks.append({
                "host": host, "port": 3389, "severity": "MEDIUM",
                "message": "RDP exposed (port 3389) — verify NLA enforcement",
            })

    return risks

# ── File loader ────────────────────────────────────────────────────────────────

def load_hosts(filepath: str) -> list:
    """Load hosts from a file, skipping blank lines and # comments."""
    hosts = []
    try:
        with open(filepath) as f:
            for line in f:
                host = line.split("#")[0].strip()
                if host:
                    hosts.append(host)
    except FileNotFoundError:
        print(f"{R}Error: file not found: {filepath}{RST}")
        sys.exit(1)
    except Exception as e:
        print(f"{R}Error reading file: {e}{RST}")
        sys.exit(1)
    if not hosts:
        print(f"{R}Error: no valid hosts found in {filepath}{RST}")
        sys.exit(1)
    return hosts

# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Single host : python3 qscanner.py <host>")
        print("  Host file   : python3 qscanner.py -f hosts.txt")
        print()
        print("Host file format (one per line, # = comment):")
        print("  192.168.1.100")
        print("  192.168.1.101   # web server")
        sys.exit(1)

    if sys.argv[1] in ("-f", "--file"):
        if len(sys.argv) < 3:
            print(f"{R}Error: -f requires a filename.{RST}")
            sys.exit(1)
        hosts = load_hosts(sys.argv[2])
    else:
        hosts = [sys.argv[1]]

    print(f"\n{W}Penetration Testing Port Scanner{RST}")
    print(f"Targets  : {C}{len(hosts)} host(s){RST}")
    print(f"Ports    : {', '.join(str(p) for p in TARGET_PORTS)}")
    print(f"Workers  : {PARALLEL_HOSTS} parallel host(s)")
    print(f"Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    start_time = time.monotonic()

    # ── Stage 1: DNS pre-check ────────────────────────────────────────────────
    section("Stage 1 — DNS Resolution")

    dns_map       = {}
    dns_fail_list = []

    def _resolve_one(host):
        return host, *dns_resolve(host)

    with concurrent.futures.ThreadPoolExecutor(max_workers=PARALLEL_HOSTS) as pool:
        for host, ip, err in pool.map(_resolve_one, hosts):
            dns_map[host] = (ip, err)

    # Print in original order
    for host in hosts:
        ip, err = dns_map[host]
        if err:
            dns_fail_list.append(host)
            print(f"  {R}[DNS FAILURE]{RST}  {host}")
            print(f"  {DIM}{err}{RST}")
        else:
            label = f" → {ip}" if ip != host else ""
            print(f"  {G}[RESOLVED]   {RST}  {host}{label}")

    resolved_hosts = [h for h in hosts if dns_map[h][0] is not None]
    if not resolved_hosts:
        print(f"\n{R}No hosts resolved. Nothing to scan.{RST}\n")
        sys.exit(1)

    # ── Stage 2: Reachability check — all hosts probed in parallel ────────────
    section("Stage 2 — Reachability Check")
    print(f"  {DIM}(ICMP ping first, TCP probe fallback — {PARALLEL_HOSTS} hosts in parallel){RST}\n")

    reachable_map     = {}   # host -> bool
    reachable_hosts   = []
    unreachable_hosts = []

    def _probe_one(host):
        ip, _ = dns_map[host]
        return host, is_reachable(ip)

    with concurrent.futures.ThreadPoolExecutor(max_workers=PARALLEL_HOSTS) as pool:
        for host, reachable in pool.map(_probe_one, resolved_hosts):
            reachable_map[host] = reachable

    # Print and bucket in original order
    for host in resolved_hosts:
        if reachable_map[host]:
            reachable_hosts.append(host)
            print(f"  {G}[REACHABLE]  {RST}  {host}")
        else:
            unreachable_hosts.append(host)
            print(f"  {Y}[UNREACHABLE]{RST}  {host}")

    if not reachable_hosts:
        print(f"\n{Y}No hosts responded. Nothing to scan.{RST}\n")
        sys.exit(1)

    if unreachable_hosts:
        print(f"\n  {Y}Skipping {len(unreachable_hosts)} unreachable host(s).{RST}")

    # ── Stage 3: Port scan — hosts run in parallel ────────────────────────────
    section("Stage 3 — Port Scan")
    print(f"  {DIM}Scanning {len(reachable_hosts)} host(s) with up to {PARALLEL_HOSTS} in parallel …{RST}\n")

    scan_results_ordered = {}   # host -> (ip, results) — filled as futures complete
    all_risks  = []
    scan_stats = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=PARALLEL_HOSTS) as pool:
        futures = {pool.submit(_scan_one, h, dns_map): h for h in reachable_hosts}
        done = 0
        for future in concurrent.futures.as_completed(futures):
            done += 1
            host, ip, results = future.result()
            scan_results_ordered[host] = (ip, results)
            open_count = sum(1 for r in results if r["open"])
            print(f"  {DIM}[{done}/{len(reachable_hosts)}] {host} — {open_count} open port(s){RST}")

    # Print results in original input order so output is deterministic
    for host in reachable_hosts:
        ip, results = scan_results_ordered[host]
        print_host_block(host, ip, results)
        all_risks.extend(collect_risks(results, host))
        scan_stats.append((host, sum(1 for r in results if r["open"])))

    # ── Summary ───────────────────────────────────────────────────────────────
    section("Scan Complete — Summary")

    col          = 26
    total        = len(hosts)
    dns_fails    = len(dns_fail_list)
    unreachable  = len(unreachable_hosts)
    scanned      = len(reachable_hosts)
    hosts_w_open = sum(1 for _, o in scan_stats if o > 0)
    total_open   = sum(o for _, o in scan_stats)

    print(f"  {'Hosts in list':<{col}}: {total}")
    print(f"  {'[DNS FAILURE]':<{col}}: "
          f"{(R if dns_fails else G)}{dns_fails}{RST}"
          + (f"  ({', '.join(dns_fail_list)})" if dns_fail_list else ""))
    print(f"  {'[UNREACHABLE]':<{col}}: "
          f"{(Y if unreachable else G)}{unreachable}{RST}"
          + (f"  ({', '.join(unreachable_hosts)})" if unreachable_hosts else ""))
    print(f"  {'Hosts scanned':<{col}}: {scanned}")
    print(f"  {'Hosts with open ports':<{col}}: {hosts_w_open}")
    print(f"  {'Total open ports found':<{col}}: {total_open}")

    if all_risks:
        print(f"\n  Risks identified ({len(all_risks)} total):")
        for risk in all_risks:
            print(f"    {R}•{RST} {risk['host']} — {risk['message']}")
    elif scanned:
        print(f"\n  {G}No critical misconfigurations detected.{RST}")

    elapsed = time.monotonic() - start_time
    print(f"\n  Completed in : {elapsed:.1f}s\n")


if __name__ == "__main__":
    main()
