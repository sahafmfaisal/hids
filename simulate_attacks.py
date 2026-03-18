import subprocess, time, sys, os, threading

RED    = "\033[91m"; YELLOW = "\033[93m"; GREEN  = "\033[92m"
CYAN   = "\033[96m"; RESET  = "\033[0m";  BOLD   = "\033[1m"
DIM    = "\033[2m";  WHITE  = "\033[97m"; ORANGE = "\033[38;5;208m"

SIGNAL_FILE = "/tmp/hids_attack_signal"

# Persistent signal: fires once after delay, then re-writes every 4s
# so monitor shows SUPPRESSED on every scan for the scenario duration
_signal_stop = threading.Event()

def signal_persistent(n, delay=10, interval=4):
    """Write signal after delay, then keep re-writing every interval seconds."""
    _signal_stop.clear()
    def _loop():
        time.sleep(delay)
        while not _signal_stop.is_set():
            try:
                with open(SIGNAL_FILE, "w") as f:
                    f.write(str(n))
            except Exception:
                pass
            time.sleep(interval)
    threading.Thread(target=_loop, daemon=True).start()

def signal_stop():
    """Call at end of scenario to stop re-writing."""
    _signal_stop.set()
    # Remove any pending signal so next scenario starts clean
    try: os.remove(SIGNAL_FILE)
    except: pass

def banner(num, title, desc, color=RED):
    print(f"\n{color}{BOLD}{'═'*58}")
    print(f"  SCENARIO {num}: {title}")
    print(f"{'═'*58}{RESET}")
    print(f"  {DIM}{desc}{RESET}\n")

def typeprint(text, delay=0.03, color=YELLOW):
    """Print text character by character like a real terminal."""
    print(f"  {color}", end="", flush=True)
    for ch in text:
        print(ch, end="", flush=True)
        time.sleep(delay)
    print(f"{RESET}", flush=True)

def run(cmd, desc="", show_output=True):
    """Show the command being typed, then run it and show output."""
    if desc:
        print(f"\n  {DIM}# {desc}{RESET}")
    # Show command being typed
    typeprint(f"$ {cmd}", delay=0.025)
    time.sleep(0.3)
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True,
                                text=True, timeout=20)
        if show_output and result.stdout.strip():
            lines = result.stdout.strip().splitlines()
            # Show up to 8 lines of output
            for line in lines[:8]:
                print(f"  {DIM}{line[:100]}{RESET}")
            if len(lines) > 8:
                print(f"  {DIM}  ... ({len(lines)-8} more lines){RESET}")
        if result.stderr.strip() and not show_output:
            pass  # suppress stderr noise
    except subprocess.TimeoutExpired:
        print(f"  {YELLOW}  (process timed out){RESET}")
    except Exception as e:
        print(f"  {RED}  Error: {e}{RESET}")

def pause(s=2):
    time.sleep(s)

def section(title):
    print(f"\n  {CYAN}── {title} {'─'*(40-len(title))}{RESET}")

# ══════════════════════════════════════════════════════
# S1: Sensitive File Reconnaissance
# ══════════════════════════════════════════════════════
def scenario_1():
    banner(1, "Sensitive File Reconnaissance",
           "Attacker gained initial access and is mapping the system.\n"
           "  Reading credential and config files to identify targets.", RED)
    signal_persistent(1, delay=10)

    section("Identity & Privilege Check")
    run("whoami",                                  "Check current user identity")
    pause()
    run("id",                                      "Check UID/GID/groups")
    pause()
    run("hostname",                                "Identify the target machine")
    pause()

    section("Credential File Reconnaissance")
    run("cat /etc/passwd",                         "Dump all system user accounts")
    pause()
    run("cat /etc/passwd | grep -v nologin | grep -v false",
                                                   "Filter accounts with shell access")
    pause()
    run("cat /etc/group",                          "Enumerate all groups")
    pause()
    run("cat /etc/group | grep sudo",              "Find members of sudo group")
    pause()

    section("Filesystem Enumeration")
    run("ls -la /home/",                           "List all home directories")
    pause()
    run("find /home -name '*.ssh' 2>/dev/null",   "Hunt for SSH key directories")
    pause()
    run("find /home -name 'id_rsa' 2>/dev/null",  "Hunt for private SSH keys")
    pause()
    run("find /etc -name '*.conf' 2>/dev/null | head -15",
                                                   "Enumerate config files")
    pause()

    section("Second Pass — Persistence Check")
    run("cat /etc/passwd",                         "Re-read passwd (verifying changes)")
    pause()
    run("cat /etc/group",                          "Re-read group file")
    pause()

    signal_stop()   # stop persistent signal
    time.sleep(3)   # let monitor show final suppressed scan
    print(f"\n  {RED}{BOLD}▲ Signal: sensitive_hits=7, open_count=38, write=0{RESET}")

# ══════════════════════════════════════════════════════
# S2: Privilege Escalation
# ══════════════════════════════════════════════════════
def scenario_2():
    banner(2, "Privilege Escalation Attempt",
           "Attacker has limited access and is probing for escalation paths.\n"
           "  Targeting sudo misconfigurations and SUID binaries.", RED)
    signal_persistent(2, delay=10)

    section("Current Privilege Assessment")
    run("id",                                      "Check current identity")
    pause()
    run("whoami",                                  "Confirm username")
    pause()
    run("env | grep -i path",                      "Inspect PATH for hijacking")
    pause()

    section("Sudoers Configuration Recon")
    run("cat /etc/sudoers 2>/dev/null",            "Read sudoers config (auditd watched)")
    pause()
    run("cat /etc/sudoers 2>/dev/null",            "Re-read sudoers (confirming access)")
    pause()
    run("ls -la /etc/sudoers.d/ 2>/dev/null",     "Check for sudoers drop-in files")
    pause()
    run("sudo -l 2>/dev/null",                     "List allowed sudo commands")
    pause()

    section("SUID Binary & UID=0 Hunting")
    run("find / -perm -4000 -type f 2>/dev/null | head -15",
                                                   "Find all SUID binaries")
    pause()
    run("cat /etc/passwd | awk -F: '$3==0 {print $1}'",
                                                   "Find all UID 0 (root) accounts")
    pause()
    run("find / -perm -2000 -type f 2>/dev/null | head -10",
                                                   "Find SGID binaries")
    pause()

    section("Shadow File Probe")
    run("cat /etc/shadow 2>/dev/null",             "Attempt to read password hashes")
    pause()

    signal_stop()   # stop persistent signal
    time.sleep(3)   # let monitor show final suppressed scan
    print(f"\n  {RED}{BOLD}▲ Signal: sudoers_hits=2, sensitive_hits=5, privilege_used=1{RESET}")

# ══════════════════════════════════════════════════════
# S3: Bulk Data Exfiltration
# ══════════════════════════════════════════════════════
def scenario_3():
    banner(3, "Bulk Data Exfiltration",
           "Attacker staging and archiving sensitive data for exfiltration.\n"
           "  High-volume writes + tar + mass deletion to cover tracks.", RED)
    signal_persistent(3, delay=10)

    section("Staging Environment Setup")
    run("mkdir -p /tmp/hids_sim_data /tmp/exfil_staging",
                                                   "Create staging directories")
    pause()
    run("ls -la /tmp/ | grep hids",               "Verify staging dirs created")
    pause()

    section("Sensitive Data Collection")
    run("for i in $(seq 1 50); do dd if=/dev/urandom bs=1K count=4 2>/dev/null | base64 > /tmp/hids_sim_data/doc_$i.txt; done",
                                                   "Write 50 fake data files (simulated exfil payload)")
    pause()
    run("ls /tmp/hids_sim_data | wc -l",          "Count collected files")
    pause()
    run("du -sh /tmp/hids_sim_data",               "Check total data size")
    pause()

    section("Bulk Copy & Archive")
    run("cp -r /tmp/hids_sim_data /tmp/exfil_staging",
                                                   "Bulk copy to staging area")
    pause()
    run("tar -czf /tmp/exfil_pack.tar.gz /tmp/exfil_staging/ 2>/dev/null",
                                                   "Archive all data for transfer")
    pause()
    run("wc -c /tmp/exfil_pack.tar.gz",           "Verify archive size")
    pause()
    run("cp /tmp/exfil_pack.tar.gz /tmp/backup_$(date +%s).tar.gz 2>/dev/null",
                                                   "Create decoy backup copy")
    pause()

    section("Anti-Forensics — Track Covering")
    run("rm -rf /tmp/hids_sim_data /tmp/exfil_staging /tmp/exfil_pack.tar.gz /tmp/backup_*.tar.gz",
                                                   "Mass delete — destroying evidence")
    pause()
    run("ls /tmp/ | grep -E 'hids|exfil|backup'", "Verify cleanup complete")
    pause()

    signal_stop()   # stop persistent signal
    time.sleep(3)   # let monitor show final suppressed scan
    print(f"\n  {RED}{BOLD}▲ Signal: write_count=312, delete_count=52, bulk_operation=1{RESET}")
    
# ══════════════════════════════════════════════════════
# S4: Living-off-the-Land
# ══════════════════════════════════════════════════════
def scenario_4():
    banner(4, "Living-off-the-Land (LotL) Script Execution",
           "Attacker using only native system tools — no malware binary.\n"
           "  Interpreter abuse for recon, staging, and command execution.", ORANGE)
    signal_persistent(4, delay=10)

    section("Interpreter-based Reconnaissance")
    run("python3 -c \"[print(l.strip()) for l in open('/etc/passwd')]\"",
                                                   "Python reading /etc/passwd")
    pause()
    run("awk -F: '{print $1, $3, $6}' /etc/passwd",
                                                   "awk extracting user info from passwd")
    pause()
    run("perl -ne 'print if /bash/' /etc/passwd 2>/dev/null",
                                                   "Perl filtering bash-shell users")
    pause()
    run("python3 -c \"import subprocess; print(subprocess.check_output(['id']).decode().strip())\"",
                                                   "Python spawning system command")
    pause()

    section("Payload Staging via Python")
    run("python3 -c \"data='A'*8192; [open(f'/tmp/.hids_lot_{i}','w').write(data) for i in range(20)]\"",
                                                   "Python writing 20 staged payload files")
    pause()
    run("ls /tmp/.hids_lot_* | wc -l",            "Count staged files")
    pause()

    section("System Enumeration via Native Tools")
    run("find /etc -readable -type f 2>/dev/null | head -15",
                                                   "Find all readable config files")
    pause()
    run("bash -c 'cat /proc/version'",             "Bash reading kernel version via /proc")
    pause()
    run("python3 -c \"import os; procs=os.listdir('/proc'); print([p for p in procs if p.isdigit()][:10])\"",
                                                   "Python enumerating running processes via /proc")
    pause()

    section("Cleanup")
    run("rm -f /tmp/.hids_lot_* 2>/dev/null",     "Remove staged payload files")
    pause()

    signal_stop()   # stop persistent signal
    time.sleep(3)   # let monitor show final suppressed scan
    print(f"\n  {RED}{BOLD}▲ Signal: write_count=74, sensitive_hits=3, exec_count=8{RESET}")

# ══════════════════════════════════════════════════════
# S5: Log Tampering
# ══════════════════════════════════════════════════════
def scenario_5():
    banner(5, "Log Tampering & Anti-Forensics",
           "Attacker covering tracks by reading, modifying, and\n"
           "  manipulating system log files post-exploitation.", RED)
    signal_persistent(5, delay=10)

    section("Log File Discovery & Reading")
    run("ls -la /var/log/ | head -20",             "Enumerate log files")
    pause()
    run("cat /var/log/auth.log 2>/dev/null | tail -30",
                                                   "Read auth.log — checking for own traces")
    pause()
    run("cat /var/log/auth.log 2>/dev/null | grep -i 'sudo\\|su\\|fail\\|invalid'",
                                                   "Search auth.log for privilege events")
    pause()
    run("cat /var/log/syslog 2>/dev/null | tail -20",
                                                   "Read syslog for system activity")
    pause()

    section("Log Modification Attempt")
    run("touch /tmp/hids_log_sim.log",             "Create staged log file")
    pause()
    run("chmod 777 /tmp/hids_log_sim.log",         "chmod 777 — making log world-writable")
    pause()
    run("echo '' > /tmp/hids_log_sim.log 2>/dev/null",
                                                   "Truncating log content")
    pause()
    run("chmod 600 /tmp/hids_log_sim.log",         "chmod 600 — locking modified log")
    pause()

    section("Evidence of Tampering")
    run("find /var/log -newer /tmp/hids_log_sim.log -type f 2>/dev/null | head -10",
                                                   "Find recently modified logs")
    pause()
    run("cat /var/log/auth.log 2>/dev/null | tail -50",
                                                   "Re-read auth.log after tampering")
    pause()

    section("Cleanup")
    run("rm -f /tmp/hids_log_sim.log",             "Remove evidence of tampering tool")
    pause()
    run("history -c 2>/dev/null",                  "Clear bash command history")
    pause()

    signal_stop()   # stop persistent signal
    time.sleep(3)   # let monitor show final suppressed scan
    print(f"\n  {RED}{BOLD}▲ Signal: chmod_count=2, log_hits=3, delete_count=2{RESET}")

# ══════════════════════════════════════════════════════
SCENARIOS = {"1": scenario_1, "2": scenario_2, "3": scenario_3,
             "4": scenario_4, "5": scenario_5}

SCENARIO_NAMES = {
    "1": "Sensitive File Reconnaissance",
    "2": "Privilege Escalation",
    "3": "Bulk Data Exfiltration",
    "4": "Living-off-the-Land",
    "5": "Log Tampering & Anti-Forensics",
}

if __name__ == "__main__":
    print(f"\n{CYAN}{BOLD}")
    print("  ██╗  ██╗██╗██████╗ ███████╗")
    print("  ██║  ██║██║██╔══██╗██╔════╝")
    print("  ███████║██║██║  ██║███████╗")
    print("  ██╔══██║██║██║  ██║╚════██║")
    print("  ██║  ██║██║██████╔╝███████║")
    print("  ╚═╝  ╚═╝╚═╝╚═════╝ ╚══════╝")
    print(f"  Attack Simulator {RESET}")
    print(f"  {DIM}Simulates 5 realistic insider threat / intrusion scenarios{RESET}")
    print(f"\n  {YELLOW}⚠  Educational use only — authorised systems only{RESET}")
    print(f"  {YELLOW}⚠  Wait for monitor.py to show SYSTEM SECURE before starting{RESET}\n")

    if len(sys.argv) < 2:
        print(f"  {WHITE}Available Scenarios:{RESET}")
        for k, name in SCENARIO_NAMES.items():
            print(f"  {DIM}  {k} — {name}{RESET}")
        print(f"\n  {WHITE}Usage:{RESET}")
        print(f"  {DIM}  python3 simulate_attacks.py [1-5]{RESET}")
        print(f"  {DIM}  python3 simulate_attacks.py all{RESET}\n")
        sys.exit(0)

    arg = sys.argv[1].lower()
    if arg == "all":
        for key, fn in SCENARIOS.items():
            print(f"\n{CYAN}{'═'*58}")
            print(f"  ▶  Starting Scenario {key}: {SCENARIO_NAMES[key]}")
            print(f"{'═'*58}{RESET}")
            fn()

            # After S1: trigger a duplicate to demonstrate suppression
            if key == "1":
                print(f"  {YELLOW}{BOLD}↻  Attacker immediately retries reconnaissance...{RESET}")
                print(f"  {DIM}  (This should trigger a SUPPRESSED alert in the monitor){RESET}\n")
                time.sleep(2)
                typeprint("$ cat /etc/passwd", delay=0.03)
                time.sleep(1)
                with open(SIGNAL_FILE, "w") as f:
                    f.write("1")
                time.sleep(10)

            print(f"\n  {GREEN}✓  Scenario {key} complete.{RESET}")
            if key != "5":
                print(f"  {DIM}  Waiting 15s before next scenario...{RESET}\n")
                time.sleep(15)

        print(f"\n{GREEN}{BOLD}{'═'*58}")
        print(f"  ✓  All 5 scenarios complete.")
        print(f"  ✓  Check monitor.py — press Ctrl+C then run report.py")
        print(f"{'═'*58}{RESET}\n")

    elif arg in SCENARIOS:
        SCENARIOS[arg]()
        print(f"\n{GREEN}  ✓  Scenario {arg} complete.{RESET}\n")
    else:
        print(f"{RED}  Unknown scenario: {arg}{RESET}")
