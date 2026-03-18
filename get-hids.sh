#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  HIDS — Host-Based Intrusion Detection System
#  Global installer — works on any Debian/Ubuntu/Fedora/Arch Linux
#
#  USAGE (one command, no download needed):
#    curl -fsSL https://raw.githubusercontent.com/sahafmfaisal/hids/main/get-hids.sh | sudo bash
#
#  Or with wget:
#    wget -qO- https://raw.githubusercontent.com/sahafmfaisal/hids/main/get-hids.sh | sudo bash
#
#  After install, the `hids` command is available globally:
#    hids start      — start monitor + dashboard
#    hids stop       — stop services
#    hids status     — show service health
#    hids open       — open dashboard in browser
#    hids demo       — run attack simulation
#    hids logs       — tail live monitor logs
#    hids update     — update to latest version
#    hids uninstall  — remove everything
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

# ── Config ─────────────────────────────────────────────────────────────────────
REPO="https://github.com/sahafmfaisal/hids"
RAW="https://raw.githubusercontent.com/sahafmfaisal/hids/main"
TARBALL="https://github.com/sahafmfaisal/hids/archive/refs/heads/main.tar.gz"
INSTALL_DIR="/opt/hids"
DATA_DIR="/var/lib/hids"
LOG_DIR="/var/log/hids"
VENV_DIR="/opt/hids-venv"
CLI_PATH="/usr/local/bin/hids"
PORT=5000
VERSION="2.0.0"

# ── Colours ────────────────────────────────────────────────────────────────────
R='\033[0;31m' G='\033[0;32m' C='\033[0;36m'
Y='\033[1;33m' B='\033[1m'   D='\033[2m' N='\033[0m'

step(){ echo -e "\n  ${C}▶${N}  ${B}$1${N}"; }
ok()  { echo -e "  ${G}✓${N}  $1"; }
warn(){ echo -e "  ${Y}⚠${N}  $1"; }
fail(){ echo -e "\n  ${R}✗  ERROR: $1${N}\n"; exit 1; }
info(){ echo -e "  ${D}  $1${N}"; }

banner(){
  clear
  echo -e "${C}${B}"
  cat << 'ART'

    ██╗  ██╗██╗██████╗ ███████╗
    ██║  ██║██║██╔══██╗██╔════╝
    ███████║██║██║  ██║███████╗
    ██╔══██║██║██║  ██║╚════██║
    ██║  ██║██║██████╔╝███████║
    ╚═╝  ╚═╝╚═╝╚═════╝ ╚══════╝

ART
  echo -e "${N}${B}    Host-Based Intrusion Detection System${N}  ${D}v${VERSION}${N}"
  echo -e "    ${D}ML-powered syscall behavioural analysis${N}\n"
  echo -e "    ${D}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}\n"
}

# ── Root check ─────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && fail "Run as root:  curl -fsSL ${RAW}/get-hids.sh | sudo bash"

banner

echo -e "  This installer will:"
echo -e "  ${D}  • Install HIDS to ${INSTALL_DIR}${N}"
echo -e "  ${D}  • Create a Python virtual environment${N}"
echo -e "  ${D}  • Register systemd services (auto-start on boot)${N}"
echo -e "  ${D}  • Install the \`hids\` CLI command globally${N}"
echo -e "  ${D}  • Open dashboard at http://localhost:${PORT}${N}"
echo ""

# ── Detect distro ──────────────────────────────────────────────────────────────
step "Detecting system..."
if   command -v apt-get &>/dev/null; then DISTRO=apt
elif command -v dnf     &>/dev/null; then DISTRO=dnf
elif command -v pacman  &>/dev/null; then DISTRO=pacman
elif command -v zypper  &>/dev/null; then DISTRO=zypper
else fail "Unsupported distro. Install manually: python3 pip3 auditd git"; fi
ok "Distro: ${DISTRO}  |  Kernel: $(uname -r)  |  Arch: $(uname -m)"

# ── Install system deps ────────────────────────────────────────────────────────
step "Installing system dependencies..."
case $DISTRO in
  apt)
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
      python3 python3-pip python3-venv git curl auditd audispd-plugins lsof > /dev/null
    ;;
  dnf)
    dnf install -y -q python3 python3-pip git curl audit > /dev/null
    ;;
  pacman)
    pacman -Sy --noconfirm python python-pip git curl audit > /dev/null
    ;;
  zypper)
    zypper install -y -q python3 python3-pip git curl audit > /dev/null
    ;;
esac
ok "System packages ready"

# ── Download HIDS source ───────────────────────────────────────────────────────
step "Downloading HIDS v${VERSION}..."
rm -rf /tmp/hids-download
mkdir -p /tmp/hids-download

if command -v git &>/dev/null; then
  git clone --depth 1 --quiet "$REPO" /tmp/hids-download/hids 2>/dev/null && \
    SRC="/tmp/hids-download/hids" || \
    { warn "git clone failed, trying tarball..."; SRC=""; }
fi

if [[ -z "${SRC:-}" ]]; then
  curl -fsSL "$TARBALL" | tar -xz -C /tmp/hids-download
  SRC="$(ls -d /tmp/hids-download/hids-*/)"
fi

ok "Source downloaded to ${SRC}"

# ── Install files ──────────────────────────────────────────────────────────────
step "Installing to ${INSTALL_DIR}..."
rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$LOG_DIR"
cp -r "$SRC/." "$INSTALL_DIR/"
rm -rf /tmp/hids-download
ok "Files installed"

# ── Python venv ────────────────────────────────────────────────────────────────
step "Setting up Python virtual environment..."
rm -rf "$VENV_DIR"
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install -q --upgrade pip
"$VENV_DIR/bin/pip" install -q flask scikit-learn pandas joblib numpy
ok "Python environment ready at ${VENV_DIR}"
PYTHON="$VENV_DIR/bin/python3"

# ── Train model ────────────────────────────────────────────────────────────────
step "Training ML model (Random Forest + SVM ensemble)..."
cd "$INSTALL_DIR"
HIDS_DB="$DATA_DIR/hids.db" "$PYTHON" core/train.py 2>&1 | tail -2
ok "Model trained and saved"

# ── Create service user ────────────────────────────────────────────────────────
step "Creating service user..."
if ! id -u hids &>/dev/null; then
  useradd -r -s /usr/sbin/nologin -d "$INSTALL_DIR" hids
fi
chown -R hids:hids "$DATA_DIR" "$LOG_DIR"
chmod 755 "$INSTALL_DIR"
ok "Service user 'hids' ready"

# ── Auditd rules ───────────────────────────────────────────────────────────────
step "Configuring auditd rules..."
mkdir -p /etc/audit/rules.d
cat > /etc/audit/rules.d/hids.rules << 'RULES'
## HIDS monitoring rules
-w /etc/shadow        -p r -k hids
-w /etc/sudoers       -p r -k hids
-w /etc/sudoers.d     -p r -k hids
-w /etc/passwd        -p r -k hids
-w /etc/group         -p r -k hids
-w /etc/crontab       -p r -k hids
-w /etc/cron.d        -p r -k hids
-w /var/log/auth.log  -p r -k hids
-w /var/log/syslog    -p r -k hids
-a always,exit -F arch=b64 -S unlink,unlinkat,rmdir   -F auid>=1000 -k hids_delete
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat  -F auid>=1000 -k hids_chmod
RULES
{ augenrules --load > /dev/null 2>&1 || auditctl -R /etc/audit/rules.d/hids.rules 2>/dev/null; } || true
{ systemctl enable auditd && systemctl restart auditd; } > /dev/null 2>&1 || true
ok "Auditd rules loaded"

# ── Systemd services ───────────────────────────────────────────────────────────
step "Registering systemd services..."

cat > /etc/systemd/system/hids-monitor.service << EOF
[Unit]
Description=HIDS Monitor Daemon
After=network.target auditd.service
Wants=auditd.service
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
Environment=HIDS_DB=${DATA_DIR}/hids.db
Environment=HIDS_STATE=${DATA_DIR}/state.json
Environment=PYTHONPATH=${INSTALL_DIR}
ExecStart=${PYTHON} ${INSTALL_DIR}/core/monitor.py
Restart=on-failure
RestartSec=5
StandardOutput=append:${LOG_DIR}/monitor.log
StandardError=append:${LOG_DIR}/monitor.log

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/hids-dashboard.service << EOF
[Unit]
Description=HIDS Web Dashboard
After=network.target hids-monitor.service
Wants=hids-monitor.service

[Service]
Type=simple
User=hids
WorkingDirectory=${INSTALL_DIR}/web
Environment=HIDS_DB=${DATA_DIR}/hids.db
Environment=HIDS_STATE=${DATA_DIR}/state.json
Environment=PYTHONPATH=${INSTALL_DIR}
ExecStart=${PYTHON} ${INSTALL_DIR}/web/app.py
Restart=on-failure
RestartSec=5
StandardOutput=append:${LOG_DIR}/dashboard.log
StandardError=append:${LOG_DIR}/dashboard.log

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable hids-monitor hids-dashboard > /dev/null
systemctl restart hids-monitor hids-dashboard
ok "Services registered and started"

# ── Install hids CLI ───────────────────────────────────────────────────────────
step "Installing 'hids' CLI command..."
cp "$INSTALL_DIR/bin/hids" "$CLI_PATH"
chmod +x "$CLI_PATH"
ok "'hids' command available globally"

# ── Open firewall if needed ───────────────────────────────────────────────────
if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow "$PORT/tcp" > /dev/null 2>&1
  warn "UFW: port ${PORT} opened"
fi
if command -v firewall-cmd &>/dev/null; then
  firewall-cmd --permanent --add-port="${PORT}/tcp" > /dev/null 2>&1
  firewall-cmd --reload > /dev/null 2>&1
  warn "firewalld: port ${PORT} opened"
fi

# ── Done ───────────────────────────────────────────────────────────────────────
LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "")

echo ""
echo -e "${G}${B}"
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║                                                  ║"
echo "  ║   ✓   HIDS installed successfully!              ║"
echo "  ║                                                  ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo -e "${N}"
echo -e "  ${B}Open your browser:${N}"
echo -e "    ${C}http://localhost:${PORT}${N}"
[[ -n "$LOCAL_IP" ]] && \
  echo -e "    ${C}http://${LOCAL_IP}:${PORT}${N}  ${D}← from other devices on your network${N}"
echo ""
echo -e "  ${B}CLI commands:${N}"
echo -e "    ${D}hids status     — check if services are running${N}"
echo -e "    ${D}hids stop       — stop all services${N}"
echo -e "    ${D}hids start      — start all services${N}"
echo -e "    ${D}hids open       — open dashboard in browser${N}"
echo -e "    ${D}hids demo       — run attack simulation${N}"
echo -e "    ${D}hids logs       — tail live monitor logs${N}"
echo -e "    ${D}hids update     — update to latest version${N}"
echo -e "    ${D}hids uninstall  — remove everything${N}"
echo ""
