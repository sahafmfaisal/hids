#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
#  HIDS — Host-Based Intrusion Detection System
#  One-command installer for Debian/Ubuntu-based Linux systems
#
#  Usage:  sudo bash install.sh
#          sudo bash install.sh --uninstall
# ═══════════════════════════════════════════════════════════════════════
set -e

INSTALL_DIR="/opt/hids"
DATA_DIR="/var/lib/hids"
LOG_DIR="/var/log/hids"
SVC_USER="hids"
PORT=5000

R='\033[0;31m' G='\033[0;32m' C='\033[0;36m' Y='\033[1;33m' B='\033[1m' N='\033[0m' D='\033[2m'

step(){ echo -e "  ${C}▶${N}  $1"; }
ok()  { echo -e "  ${G}✓${N}  $1"; }
warn(){ echo -e "  ${Y}⚠${N}  $1"; }
fail(){ echo -e "  ${R}✗${N}  $1"; exit 1; }

banner(){
  echo -e "\n${C}${B}"
  echo "  ██╗  ██╗██╗██████╗ ███████╗"
  echo "  ██║  ██║██║██╔══██╗██╔════╝"
  echo "  ███████║██║██║  ██║███████╗"
  echo "  ██╔══██║██║██║  ██║╚════██║"
  echo "  ██║  ██║██║██████╔╝███████║"
  echo "  ╚═╝  ╚═╝╚═╝╚═════╝ ╚══════╝${N}"
  echo -e "  ${B}Host-Based Intrusion Detection System${N} ${N}\n"
}

uninstall(){
  banner
  echo -e "  ${Y}Uninstalling HIDS...${N}\n"
  systemctl stop  hids-monitor hids-dashboard 2>/dev/null || true
  systemctl disable hids-monitor hids-dashboard 2>/dev/null || true
  rm -f /etc/systemd/system/hids-monitor.service
  rm -f /etc/systemd/system/hids-dashboard.service
  systemctl daemon-reload
  rm -rf "$INSTALL_DIR" "$DATA_DIR"
  # Remove auditd rules
  rm -f /etc/audit/rules.d/hids.rules
  augenrules --load 2>/dev/null || true
  # Keep logs
  echo -e "\n  ${G}✓  HIDS uninstalled. Logs kept at ${LOG_DIR}${N}\n"
  exit 0
}

[[ "${1}" == "--uninstall" ]] && uninstall
[[ $EUID -ne 0 ]] && fail "Run as root:  sudo bash install.sh"

banner

# ── 1. Detect distro ─────────────────────────────────────────────────────────
if command -v apt-get &>/dev/null; then PKG=apt
elif command -v dnf &>/dev/null;   then PKG=dnf
elif command -v pacman &>/dev/null; then PKG=pacman
else fail "Unsupported distro — install manually: python3 pip3 auditd flask scikit-learn"; fi

# ── 2. System packages ────────────────────────────────────────────────────────
step "Installing system dependencies (this may take a minute)..."
if [[ $PKG == apt ]]; then
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    python3 python3-pip python3-venv auditd audispd-plugins lsof curl > /dev/null
elif [[ $PKG == dnf ]]; then
  dnf install -y -q python3 python3-pip audit > /dev/null
elif [[ $PKG == pacman ]]; then
  pacman -Sy --noconfirm python python-pip audit > /dev/null
fi
ok "System packages installed"

# ── 3. Python venv ────────────────────────────────────────────────────────────
step "Setting up Python virtual environment..."
python3 -m venv /opt/hids-venv
/opt/hids-venv/bin/pip install -q --upgrade pip
/opt/hids-venv/bin/pip install -q flask scikit-learn pandas joblib numpy
ok "Python environment ready"
PYTHON=/opt/hids-venv/bin/python3

# ── 4. Create directories and user ───────────────────────────────────────────
step "Creating directories and service user..."
mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$LOG_DIR"
if ! id -u "$SVC_USER" &>/dev/null; then
  useradd -r -s /usr/sbin/nologin -d "$INSTALL_DIR" "$SVC_USER"
fi
ok "Directories and user ready"

# ── 5. Copy files ─────────────────────────────────────────────────────────────
step "Installing HIDS files to ${INSTALL_DIR}..."
cp -r core/. "$INSTALL_DIR/core/"
cp -r web/.  "$INSTALL_DIR/web/"
cp simulate_attacks.py "$INSTALL_DIR/"
chown -R root:root "$INSTALL_DIR"
chown -R "$SVC_USER:$SVC_USER" "$DATA_DIR" "$LOG_DIR"
chmod -R 755 "$INSTALL_DIR"
ok "Files installed"

# ── 6. Train model ────────────────────────────────────────────────────────────
step "Training ML model (RF+SVM ensemble)..."
cd "$INSTALL_DIR"
HIDS_DB="$DATA_DIR/hids.db" $PYTHON core/train.py >> "$LOG_DIR/install.log" 2>&1
ok "Model trained and saved"

# ── 7. Auditd rules ───────────────────────────────────────────────────────────
step "Configuring auditd monitoring rules..."
cat > /etc/audit/rules.d/hids.rules << 'EOF'
-w /etc/shadow        -p r -k hids
-w /etc/sudoers       -p r -k hids
-w /etc/sudoers.d     -p r -k hids
-w /etc/passwd        -p r -k hids
-w /etc/group         -p r -k hids
-w /etc/crontab       -p r -k hids
-w /etc/cron.d        -p r -k hids
-w /var/log/auth.log  -p r -k hids
-w /var/log/syslog    -p r -k hids
-a always,exit -F arch=b64 -S unlink,unlinkat,rmdir    -F auid>=1000 -k hids_delete
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat   -F auid>=1000 -k hids_chmod
EOF
augenrules --load > /dev/null 2>&1 || auditctl -R /etc/audit/rules.d/hids.rules 2>/dev/null || true
systemctl enable auditd 2>/dev/null && systemctl restart auditd 2>/dev/null || true
ok "Auditd rules loaded"

# ── 8. Systemd services ───────────────────────────────────────────────────────
step "Registering systemd services..."

cat > /etc/systemd/system/hids-monitor.service << EOF
[Unit]
Description=HIDS Monitor Daemon
After=network.target auditd.service
Wants=auditd.service

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
Environment=HIDS_DB=${DATA_DIR}/hids.db
Environment=HIDS_STATE=${DATA_DIR}/state.json
ExecStart=${PYTHON} ${INSTALL_DIR}/core/monitor.py
Restart=always
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

[Service]
Type=simple
User=${SVC_USER}
WorkingDirectory=${INSTALL_DIR}/web
Environment=HIDS_DB=${DATA_DIR}/hids.db
Environment=HIDS_STATE=${DATA_DIR}/state.json
ExecStart=${PYTHON} ${INSTALL_DIR}/web/app.py
Restart=always
RestartSec=5
StandardOutput=append:${LOG_DIR}/dashboard.log
StandardError=append:${LOG_DIR}/dashboard.log

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable hids-monitor hids-dashboard
systemctl start  hids-monitor hids-dashboard
ok "Services registered and started"

# ── 9. Open firewall port if ufw/firewalld present ───────────────────────────
if command -v ufw &>/dev/null && ufw status | grep -q active; then
  ufw allow "$PORT/tcp" > /dev/null 2>&1 && warn "UFW: opened port $PORT"
fi

# ── 10. Done ──────────────────────────────────────────────────────────────────
LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo ""
echo -e "${G}${B}  ╔════════════════════════════════════════════╗"
echo -e "  ║   ✓  HIDS installed and running!           ║"
echo -e "  ╚════════════════════════════════════════════╝${N}"
echo ""
echo -e "  ${C}Open your browser:${N}"
echo -e "    ${B}http://localhost:${PORT}${N}"
[[ -n "$LOCAL_IP" ]] && echo -e "    ${B}http://${LOCAL_IP}:${PORT}${N}  ${D}(from other devices)${N}"
echo ""
echo -e "  ${Y}Commands:${N}"
echo -e "  ${D}  sudo systemctl status hids-monitor${N}"
echo -e "  ${D}  sudo systemctl status hids-dashboard${N}"
echo -e "  ${D}  sudo journalctl -u hids-monitor -f${N}"
echo -e "  ${D}  sudo bash install.sh --uninstall${N}"
echo ""
echo -e "  ${Y}Demo / testing:${N}"
echo -e "  ${D}  cd ${INSTALL_DIR} && python3 simulate_attacks.py all${N}"
echo ""
