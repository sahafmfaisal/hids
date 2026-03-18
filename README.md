# HIDS — Host-Based Intrusion Detection System

> ML-powered syscall behavioural analysis with a full analytics dashboard.
> Detects insider threats in real time — runs entirely on your local machine.

[![Linux](https://img.shields.io/badge/platform-Linux-blue)](https://github.com/sahafmfaisal/hids)
[![Python](https://img.shields.io/badge/python-3.8+-green)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-orange)](LICENSE)

---

## Install (one command)

```bash
curl -fsSL https://raw.githubusercontent.com/sahafmfaisal/hids/main/get-hids.sh | sudo bash
```

Or with `wget`:

```bash
wget -qO- https://raw.githubusercontent.com/sahafmfaisal/hids/main/get-hids.sh | sudo bash
```

That's it. No configuration. No Docker. No dependencies to install manually.

Then open **http://localhost:5000** in your browser.

---

## CLI

After install, `hids` is available globally:

```
hids status      — service health + alert stats
hids start       — start monitor + dashboard
hids stop        — stop all services
hids restart     — restart everything
hids open        — open dashboard in browser
hids logs        — tail live monitor logs
hids demo        — run 5 attack scenarios
hids update      — pull latest version
hids uninstall   — remove completely
```

---

## Dashboard

Four views at **http://localhost:5000**:

| View | Contents |
|---|---|
| **Live** | Real-time alerts, 11-feature vector bars, syscall sparkline, live event feed |
| **Analytics** | 48h frequency chart, severity donut, 60-day heatmap, threat breakdown table |
| **History** | Full filterable alert log with MITRE ATT&CK tags |
| **Sessions** | Every monitor session — duration, scans, alerts, syscalls |

---

## How it works

```
Startup (24s)   →  Calibrates idle syscall baseline
Every 2 seconds →  Collects 11 behavioural features from /proc + auditd
                →  RF+SVM ensemble classifies feature vector
                →  Alert fired if anomalous (with MITRE mapping)
                →  Duplicate alerts suppressed within 10s dedup window
                →  All data stored in SQLite (/var/lib/hids/hids.db)
```

### Detected Threats

| Threat | Signal | MITRE ATT&CK |
|---|---|---|
| Sensitive File Reconnaissance | Repeated reads of /etc/passwd, /etc/shadow | T1087 |
| Privilege Escalation | Sudoers access + privilege context change | T1078 |
| Data Exfiltration + Cleanup | Bulk writes + mass deletion | T1560 |
| Living-off-the-Land | Native interpreter abuse + staging | T1059 |
| Log Tampering | chmod on logs + log file reads | T1070 |

---

## Requirements

- **OS**: Linux (Debian, Ubuntu, Fedora, Arch, openSUSE)
- **Python**: 3.8+
- **Root access**: required for auditd + systemd
- **Disk**: ~100MB

All other dependencies installed automatically.

---

## File layout

```
/opt/hids/              ← installed application
  core/
    monitor.py          ← detection daemon
    db.py               ← SQLite persistence
    train.py            ← ML trainer
    model.pkl           ← trained model
  web/
    app.py              ← Flask dashboard
    templates/
      dashboard.html
  bin/
    hids                ← CLI tool
  simulate_attacks.py   ← attack demo

/var/lib/hids/
  hids.db               ← all alerts, sessions, stats (SQLite)
  state.json            ← live state polled by dashboard

/var/log/hids/
  monitor.log
  dashboard.log

/usr/local/bin/hids     ← global CLI command
```

---

## Uninstall

```bash
sudo hids uninstall
```

---

## For developers

```bash
git clone https://github.com/sahafmfaisal/hids
cd hids
sudo bash get-hids.sh    # full install from local copy
```

Or run components manually:

```bash
# Terminal 1 — monitor daemon
sudo HIDS_DB=/tmp/hids.db HIDS_STATE=/tmp/state.json \
  python3 core/monitor.py

# Terminal 2 — dashboard
HIDS_DB=/tmp/hids.db HIDS_STATE=/tmp/state.json \
  python3 web/app.py
```

---

## License

MIT — free to use, modify, distribute.
