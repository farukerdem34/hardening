#!/bin/bash

sudo apt-get update -y >/dev/null 2>&1

export DEBIAN_FRONTEND=noninteractive
TMP_DIR=/tmp
LOG_DIR=/var/log/ubuntu-hardener
LOG_FILE=${LOG_FILE:-"$LOG_DIR/harden-$(date +%s).log"}
SSHD_CONFIG_FILE="/etc/ssh/sshd_config"
SSH_PORT=1911
BACKUP_DIR=$TMP_DIR/backup

# Default verbosity
VERBOSITY_LEVEL=1

# Parse command line arguments
for arg in "$@"; do
  case $arg in
  -v)
    VERBOSITY_LEVEL=1
    shift
    ;;
  -vv)
    VERBOSITY_LEVEL=2
    shift
    ;;
  -vvv)
    VERBOSITY_LEVEL=3
    shift
    ;;
  --no-gui)
    NO_GUI=1
    shift
    ;;
  *) ;;
  esac
done

# Check if whiptail is available
if ! command -v whiptail &>/dev/null && [[ -z "$NO_GUI" ]]; then
  echo "Installing whiptail for better user interface..."
  sudo apt-get install -y whiptail
fi

# Whiptail dimensions
HEIGHT=20
WIDTH=78
CHOICE_HEIGHT=4

log() {
  local level=$1
  local message=$2
  if [[ $VERBOSITY_LEVEL -ge $level ]]; then
    echo "[$(date)] $message" | sudo tee -a "$LOG_FILE"
  fi
}

show_message() {
  if [[ -z "$NO_GUI" ]] && command -v whiptail &>/dev/null; then
    whiptail --title "Ubuntu Hardening Script" --msgbox "$1" $HEIGHT $WIDTH
  else
    echo "$1"
    read -p "Press Enter to continue..."
  fi
}

show_info() {
  if [[ -z "$NO_GUI" ]] && command -v whiptail &>/dev/null; then
    whiptail --title "Information" --msgbox "$1" $HEIGHT $WIDTH
  else
    echo "INFO: $1"
  fi
}

get_input() {
  local prompt="$1"
  local default="$2"

  if [[ -z "$NO_GUI" ]] && command -v whiptail &>/dev/null; then
    whiptail --title "Input Required" --inputbox "$prompt" $HEIGHT $WIDTH "$default" 3>&1 1>&2 2>&3
  else
    read -p "$prompt [$default]: " input
    echo "${input:-$default}"
  fi
}

get_yes_no() {
  local prompt="$1"

  if [[ -z "$NO_GUI" ]] && command -v whiptail &>/dev/null; then
    if whiptail --title "Confirmation" --yesno "$prompt" $HEIGHT $WIDTH; then
      echo "yes"
    else
      echo "no"
    fi
  else
    while true; do
      read -p "$prompt (y/n): " yn
      case $yn in
      [Yy]*)
        echo "yes"
        break
        ;;
      [Nn]*)
        echo "no"
        break
        ;;
      *) echo "Please answer yes or no." ;;
      esac
    done
  fi
}

select_options() {
  local title="$1"
  local prompt="$2"
  shift 2
  local options=("$@")

  if [[ -z "$NO_GUI" ]] && command -v whiptail &>/dev/null; then
    local menu_items=()
    for i in "${!options[@]}"; do
      menu_items+=("$((i + 1))" "${options[$i]}")
    done

    whiptail --title "$title" --menu "$prompt" $HEIGHT $WIDTH $CHOICE_HEIGHT "${menu_items[@]}" 3>&1 1>&2 2>&3
  else
    echo "$prompt"
    for i in "${!options[@]}"; do
      echo "$((i + 1)). ${options[$i]}"
    done
    read -p "Enter your choice (1-${#options[@]}): " choice
    echo "$choice"
  fi
}

show_progress() {
  local percent="$1"
  local message="$2"

  if [[ -z "$NO_GUI" ]] && command -v whiptail &>/dev/null; then
    echo "$percent" | whiptail --title "Progress" --gauge "$message" 6 70 0
  else
    echo "[$percent%] $message"
  fi
}

sudo mkdir -p $LOG_DIR
sudo mkdir -p $BACKUP_DIR
log 0 "Extracting logs to $LOG_FILE"

# Welcome screen
show_message "Welcome to Ubuntu Security Hardening Script

This script will help you secure your Ubuntu system by:
- Configuring SSH security
- Setting up firewall rules
- Installing and configuring security tools
- Hardening kernel parameters
- Setting up monitoring and intrusion detection

Please follow the prompts to customize your security setup."

# Configuration menu
show_configuration_menu() {
  if [[ -z "$NO_GUI" ]] && command -v whiptail &>/dev/null; then
    COMPONENTS=$(whiptail --title "Select Components to Install/Configure" \
      --checklist "Choose which security components you want to configure:" \
      20 78 12 \
      "INSTALL_PKGS" "Install Required Packages" ON \
      "SSH" "Configure SSH security settings" ON \
      "FIREWALL" "Configure UFW firewall" ON \
      "FAIL2BAN" "Install and configure Fail2ban" ON \
      "CLAMAV" "Install ClamAV antivirus" ON \
      "LYNIS" "Install Lynis security auditing tool" ON \
      "RKHUNTER" "Install and configure rkhunter" ON \
      "NTP" "Configure time synchronization" ON \
      "AIDE" "Install AIDE file integrity checker" ON \
      "AUDITD" "Configure system auditing" ON \
      "SYSCTL" "Harden kernel parameters" ON \
      "ADMIN_USER" "Create admin user" OFF 3>&1 1>&2 2>&3)
  else
    echo "Select components to configure (enter numbers separated by spaces):"
    echo "1. SSH security"
    echo "2. UFW firewall"
    echo "3. Fail2ban"
    echo "4. ClamAV antivirus"
    echo "5. Lynis auditing"
    echo "6. Rkhunter"
    echo "7. NTP synchronization"
    echo "8. AIDE file integrity"
    echo "9. System auditing (auditd)"
    echo "10. Kernel hardening (sysctl)"
    echo "11. Create admin user"
    read -p "Enter your choices (e.g., 1 2 3 4): " choices

    # Convert to whiptail-like format
    COMPONENTS=""
    for choice in $choices; do
      case $choice in
      1) COMPONENTS="$COMPONENTS INSTALL_PKGS" ;;
      2) COMPONENTS="$COMPONENTS SSH" ;;
      3) COMPONENTS="$COMPONENTS FIREWALL" ;;
      4) COMPONENTS="$COMPONENTS FAIL2BAN" ;;
      6) COMPONENTS="$COMPONENTS CLAMAV" ;;
      6) COMPONENTS="$COMPONENTS LYNIS" ;;
      7) COMPONENTS="$COMPONENTS RKHUNTER" ;;
      8) COMPONENTS="$COMPONENTS NTP" ;;
      9) COMPONENTS="$COMPONENTS AIDE" ;;
      10) COMPONENTS="$COMPONENTS AUDITD" ;;
      11) COMPONENTS="$COMPONENTS SYSCTL" ;;
      12) COMPONENTS="$COMPONENTS ADMIN_USER" ;;
      esac
    done
  fi
}

setup_admin_user() {
  local ADMIN_USER
  ADMIN_USER=$(get_input "Enter username for new admin user:" "john")

  log 0 "Creating new admin user: $ADMIN_USER"
  show_info "Creating admin user: $ADMIN_USER"

  if ! id "$ADMIN_USER" &>/dev/null; then
    sudo useradd -m -G sudo -s "$(which bash)" "$ADMIN_USER"
  fi

  local ssh_dir="/home/$ADMIN_USER/.ssh"
  mkdir -p "$ssh_dir"
  sudo chmod 700 "$ssh_dir"
  touch "$ssh_dir/authorized_keys"
  sudo chmod 600 "$ssh_dir/authorized_keys"
  sudo chown -R "$ADMIN_USER:$ADMIN_USER" "/home/$ADMIN_USER"

  show_info "Admin user created successfully. Remember to add your SSH key to $ssh_dir/authorized_keys"
}

backup_file() {
  local file=$1
  if [[ -f "$file" ]]; then
    local backup_name="${BACKUP_DIR}/$(basename "$file").$(date +%Y%m%d-%H%M%S).bak"
    log 2 "cp -p \"$file\" \"$backup_name\""
    cp -p "$file" "$backup_name"
    stat -c "%a %U:%G" "$file" >"${backup_name}.meta"
    log 1 "Backed up $file to $backup_name"
  fi
}

validate_frequency() {
  local frequency=$1
  case "$frequency" in
  daily | weekly | monthly)
    echo "$frequency"
    ;;
  *)
    log 0 "Invalid frequency. Using 'weekly' as default."
    echo "weekly"
    ;;
  esac
}

add_cisofy_lynis_repos() {
  log 0 "Adding Lynis source repos"
  curl -fsSL https://packages.cisofy.com/keys/cisofy-software-public.key | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/cisofy-software-public.gpg
  echo "deb [arch=amd64,arm64 signed-by=/etc/apt/trusted.gpg.d/cisofy-software-public.gpg] https://packages.cisofy.com/community/lynis/deb/ stable main" | sudo tee /etc/apt/sources.list.d/cisofy-lynis.list
}

install_pkgs() {
  show_info "Installing security packages. This may take a few minutes..."

  log 0 "Updating repositories"
  sudo apt-get update -y

  log 0 "Installing packages"
  add_cisofy_lynis_repos
  pkgs="fail2ban sudo clamav clamav-daemon clamav-freshclam rkhunter ntp aide aide-common aide-dynamic auditd audispd-plugins lynis"
  sudo apt-get install $pkgs -y

  show_info "Package installation completed successfully!"
}

sed_ssh_param() {
  PARAM=$1
  VALUE=$2
  TARGET=$3
  log 0 "Setting $PARAM"
  if grep -q $PARAM $SSHD_CONFIG_FILE; then
    sudo sed -i "s/^#$PARAM.*/$PARAM $VALUE/" "$TARGET"
    sudo sed -i "s/^$PARAM.*/$PARAM $VALUE/" "$TARGET"
  else
    echo "$PARAM $VALUE" | sudo tee -a $SSHD_CONFIG_FILE
  fi
}

restart_ssh() {
  log 0 "Restarting SSH service"
  sudo systemctl restart ssh || sudo systemctl restart sshd
}

configure_ssh() {
  show_info "Configuring SSH security settings..."

  # Get SSH port
  SSH_PORT=$(get_input "Enter SSH port (default: 1911):" "1911")

  # Ask about password authentication
  password_auth=$(get_yes_no "Allow password authentication? (Recommended: No if you have SSH keys)")
  if [[ "$password_auth" == "yes" ]]; then
    password_setting="yes"
  else
    password_setting="no"
  fi

  backup_file $SSHD_CONFIG_FILE

  sed_ssh_param "PubkeyAuthentication" "yes" $SSHD_CONFIG_FILE
  sed_ssh_param "MaxAuthTries" "3" $SSHD_CONFIG_FILE
  sed_ssh_param "PermitRootLogin" "no" $SSHD_CONFIG_FILE
  sed_ssh_param "Port" "$SSH_PORT" $SSHD_CONFIG_FILE
  sed_ssh_param "PasswordAuthentication" "$password_setting" $SSHD_CONFIG_FILE
  sed_ssh_param "MaxSessions" "2" $SSHD_CONFIG_FILE
  sed_ssh_param "TCPKeepAlive" "no" $SSHD_CONFIG_FILE
  sed_ssh_param "X11Forwarding" "no" $SSHD_CONFIG_FILE
  sed_ssh_param "AllowAgentForwarding" "no" $SSHD_CONFIG_FILE

  restart_ssh
  show_info "SSH configuration completed. New SSH port: $SSH_PORT"
}

set_fw_rules() {
  show_info "Configuring UFW firewall..."

  backup_file "/etc/default/ufw"

  # Enable IPv6 support
  sed -i 's/IPV6=.*/IPV6=yes/' /etc/default/ufw

  # Reset firewall to defaults
  ufw --force reset

  # Set default policies
  ufw default deny incoming
  ufw default allow outgoing
  ufw default deny routed

  # Configure logging
  ufw logging on
  ufw logging medium

  # Basic rules with rate limiting
  ufw limit $SSH_PORT/tcp comment 'SSH rate limit'

  # Allow DHCP client (important for cloud instances)
  ufw allow 68/udp comment 'DHCP client'

  # Ask about additional ports
  add_ports=$(get_yes_no "Do you want to open additional ports? (e.g., web server ports)")
  if [[ "$add_ports" == "yes" ]]; then
    additional_ports=$(get_input "Enter additional ports to open (comma-separated, e.g., 80,443):" "")
    if [[ -n "$additional_ports" ]]; then
      IFS=',' read -ra PORTS <<<"$additional_ports"
      for port in "${PORTS[@]}"; do
        port=$(echo "$port" | xargs) # trim whitespace
        ufw allow "$port"
        log 0 "Opened port: $port"
      done
    fi
  fi

  # Enable firewall
  echo "y" | ufw enable

  # Configure iptables-persistent
  if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save
    sudo systemctl enable netfilter-persistent
  fi

  show_info "UFW firewall configured and enabled successfully!"
}

configure_fail2ban() {
  show_info "Configuring Fail2ban intrusion prevention..."

  backup_file "/etc/fail2ban/jail.conf"

  # Create jail.local with Ubuntu 24.04 optimizations
  sudo tee /etc/fail2ban/jail.local <<EOF
[DEFAULT]
# Ubuntu 24.04 Fail2ban Configuration
bantime  = 1h
findtime  = 10m
maxretry = 5
backend = systemd
usedns = warn
logencoding = utf-8
enabled = false
mode = normal
filter = %(__name__)s[mode=%(mode)s]

# Action
action = %(action_mwl)s

# Ignore localhost and private networks
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16

[sshd]
enabled = true
port = $SSH_PORT
logpath = %(sshd_log)s
backend = %(sshd_backend)s
maxretry = 3
bantime = 2h
findtime = 20m

[sshd-ddos]
enabled = true
port = $SSH_PORT
logpath = %(sshd_log)s
backend = %(sshd_backend)s
maxretry = 10
findtime = 5m
bantime = 10m

# Ubuntu 24.04 - systemd journal monitoring
[systemd-ssh]
enabled = true
backend = systemd
journalmatch = _SYSTEMD_UNIT=sshd.service + _COMM=sshd
maxretry = 3
bantime = 2h

# Protect against port scanning
[port-scan]
enabled = true
filter = port-scan
logpath = /var/log/ufw.log
maxretry = 2
bantime = 1d
findtime = 1d
EOF

  # Create custom filters
  sudo mkdir -p /etc/fail2ban/filter.d

  # Port scan filter
  sudo tee /etc/fail2ban/filter.d/port-scan.conf <<'EOF'
[Definition]
failregex = .*UFW BLOCK.* SRC=<HOST>
ignoreregex =
EOF

  # Restart fail2ban
  sudo systemctl restart fail2ban
  sudo systemctl enable fail2ban

  show_info "Fail2ban configured successfully!"
}

configure_and_start_clamav() {
  show_info "Configuring ClamAV antivirus..."

  # Get scan frequency
  if [[ -z "$NO_GUI" ]] && command -v whiptail &>/dev/null; then
    scan_frequency=$(whiptail --title "ClamAV Configuration" --menu "How often should ClamAV scan your system?" $HEIGHT $WIDTH $CHOICE_HEIGHT \
      "daily" "Scan every day (high security)" \
      "weekly" "Scan weekly (recommended)" \
      "monthly" "Scan monthly (basic)" 3>&1 1>&2 2>&3)
  else
    echo "Select scan frequency:"
    echo "1. Daily (high security)"
    echo "2. Weekly (recommended)"
    echo "3. Monthly (basic)"
    read -p "Enter choice (1-3): " freq_choice
    case $freq_choice in
    1) scan_frequency="daily" ;;
    2) scan_frequency="weekly" ;;
    3) scan_frequency="monthly" ;;
    *) scan_frequency="weekly" ;;
    esac
  fi

  backup_file "/etc/clamav/clamd.conf"
  backup_file "/etc/clamav/freshclam.conf"

  # Optimize ClamAV configuration
  sudo tee -a /etc/clamav/clamd.conf <<'EOF'

# Ubuntu 24.04 Optimizations
MaxThreads 4
MaxDirectoryRecursion 20
FollowDirectorySymlinks false
FollowFileSymlinks false
CrossFilesystems false
ScanPE true
ScanELF true
DetectBrokenExecutables true
ScanOLE2 true
ScanPDF true
ScanSWF true
ScanHTML true
ScanXMLDOCS true
ScanHWP3 true
ScanArchive true
MaxScanTime 300000
MaxScanSize 400M
MaxFileSize 100M
MaxRecursion 16
MaxFiles 10000
EOF

  # Configure freshclam for automatic updates
  sed -i 's/^Checks.*/Checks 24/' /etc/clamav/freshclam.conf 2>/dev/null || true

  # Stop services for configuration
  sudo systemctl stop clamav-freshclam
  sudo systemctl stop clamav-daemon

  # Update virus database
  sudo freshclam || log 0 "WARNING: Failed to update ClamAV database"

  # Start and enable services
  sudo systemctl start clamav-freshclam
  sudo systemctl start clamav-daemon
  sudo systemctl enable clamav-freshclam
  sudo systemctl enable clamav-daemon

  scan_frequency=$(validate_frequency "$scan_frequency")

  # Create systemd timer for scans
  sudo tee /etc/systemd/system/clamav-scan.service <<'EOF'
[Unit]
Description=ClamAV Virus Scan
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/clamav-scan.sh
User=root
Nice=19
IOSchedulingClass=best-effort
IOSchedulingPriority=7
EOF

  # Create scan script
  sudo tee /usr/local/bin/clamav-scan.sh <<'EOF'
#!/bin/bash
LOG_FILE="/var/log/clamav/scan-$(date +%Y%m%d-%H%M%S).log"
INFECTED_DIR="/var/quarantine"

mkdir -p "$INFECTED_DIR"
chmod 700 "$INFECTED_DIR"

# Exclude virtual filesystems and large directories
EXCLUDE_DIRS="--exclude-dir=^/sys --exclude-dir=^/proc --exclude-dir=^/dev --exclude-dir=^/run --exclude-dir=^/snap --exclude-dir=^/var/lib/docker --exclude-dir=^/var/lib/containerd"

# Scan with optimized settings
nice -n 19 ionice -c 3 clamscan -r -i \
    --move="$INFECTED_DIR" \
    $EXCLUDE_DIRS \
    --max-filesize=100M \
    --max-scansize=400M \
    --max-recursion=16 \
    --max-dir-recursion=20 \
    --log="$LOG_FILE" \
    / 2>/dev/null
EOF
  sudo chmod 755 /usr/local/bin/clamav-scan.sh

  # Create timer based on frequency
  case "$scan_frequency" in
  daily)
    timer_schedule="daily"
    ;;
  weekly)
    timer_schedule="weekly"
    ;;
  monthly)
    timer_schedule="monthly"
    ;;
  esac

  sudo tee /etc/systemd/system/clamav-scan.timer <<EOF
[Unit]
Description=Run ClamAV scan $scan_frequency
Requires=clamav-scan.service

[Timer]
OnCalendar=$timer_schedule
RandomizedDelaySec=4h
Persistent=true

[Install]
WantedBy=timers.target
EOF

  sudo systemctl daemon-reload
  sudo systemctl enable clamav-scan.timer
  sudo systemctl start clamav-scan.timer

  show_info "ClamAV configured with $scan_frequency scans"
}

install_cisofy_lynis() {
  show_info "Installing and configuring Lynis security auditing tool..."

  local LYNIS_BIN='/usr/sbin/lynis'
  LYNIS_LOG_FOLDER='/var/log/lynis'
  sudo mkdir -p /var/log/lynis
  sudo crontab -l -u root | tee $TMP_DIR/crontab
  tee -a $TMP_DIR/crontab <<EOF
0 0 * * 7  $LYNIS_BIN audit system --log-file $LYNIS_LOG_FOLDER/\$(date +%Y-%m-%d_%H-%M-%S -u).log --cronjob
EOF
  sudo crontab -u root $TMP_DIR/crontab
  sudo rm $TMP_DIR/crontab

  show_info "Lynis configured to run weekly security audits"
}

configure_rkhunter() {
  show_info "Configuring RKHunter rootkit scanner..."

  local RKHUNTER_CONFIG_FILE="/etc/rkhunter.conf"
  backup_file $RKHUNTER_CONFIG_FILE

  sudo sed -i "s/UPDATE_MIRRORS\=0/UPDATE_MIRRORS\=1/g" $RKHUNTER_CONFIG_FILE
  echo "CRON_DAILY_RUN=true" | sudo tee -a $RKHUNTER_CONFIG_FILE
  sudo sed -i "s/USE_SYSLOG\=authpriv\.warning/USE_SYSLOG\=authpriv\.notice/g" $RKHUNTER_CONFIG_FILE
  sudo sed -i 's/^WEB_CMD.*/WEB_CMD=curl -L /' $RKHUNTER_CONFIG_FILE

  sudo rkhunter --update
  sudo rkhunter --propupd

  show_info "RKHunter configured successfully"
}

setup_ntp() {
  show_info "Configuring time synchronization..."

  if sudo systemctl list-unit-files | grep -q systemd-timesyncd.service; then
    sudo systemctl enable systemd-timesyncd.service
    sudo systemctl start systemd-timesyncd.service
  else
    sudo systemctl enable ntpsec
    sudo systemctl start ntpsec
  fi

  show_info "Time synchronization configured"
}

configure_aide() {
  show_info "Configuring AIDE file integrity checker... This may take several minutes."

  backup_file "/etc/aide/aide.conf"

  # Configure AIDE for Ubuntu 24.04
  sudo tee -a /etc/aide/aide.conf <<'EOF'

# Ubuntu 24.04 specific exclusions
!/snap/
!/var/snap/
!/var/lib/snapd/
!/run/snapd/
!/sys/
!/proc/
!/dev/
!/run/
!/var/lib/docker/
!/var/lib/containerd/
!/var/lib/lxc/
!/var/lib/lxd/
EOF

  # Initialize AIDE database
  show_info "Initializing AIDE database (this may take several minutes)..."
  sudo aideinit

  # Move database to production location
  if [[ -f /var/lib/aide/aide.db.new ]]; then
    sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    sudo chmod 600 /var/lib/aide/aide.db
  fi

  # Create systemd timer for AIDE checks
  sudo tee /etc/systemd/system/aide-check.service <<'EOF'
[Unit]
Description=AIDE File Integrity Check
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/bin/aide --check
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aide
User=root
Nice=19
IOSchedulingClass=best-effort
IOSchedulingPriority=7
EOF

  sudo tee /etc/systemd/system/aide-check.timer <<'EOF'
[Unit]
Description=Run AIDE check daily
Requires=aide-check.service

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF

  sudo systemctl daemon-reload
  sudo systemctl enable aide-check.timer
  sudo systemctl start aide-check.timer

  show_info "AIDE file integrity monitoring configured"
}

configure_auditd() {
  show_info "Configuring system auditing (auditd)..."

  backup_file "/etc/audit/auditd.conf"
  backup_file "/etc/audit/rules.d/audit.rules"

  # Configure auditd for Ubuntu 24.04
  sudo tee /etc/audit/auditd.conf <<'EOF'
# Ubuntu 24.04 Optimized Audit Configuration
local_events = yes
write_logs = yes
log_file = /var/log/audit/audit.log
log_group = adm
log_format = ENRICHED
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 8
num_logs = 5
priority_boost = 4
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = HOSTNAME
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
verify_email = yes
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
use_libwrap = yes
tcp_listen_port = 60
tcp_listen_queue = 5
tcp_max_per_addr = 1
tcp_client_max_idle = 0
transport = TCP
krb5_principal = auditd
distribute_network = no
q_depth = 1200
overflow_action = SYSLOG
max_restarts = 10
plugin_dir = /etc/audit/plugins.d
end_of_event_timeout = 2
EOF

  # Create comprehensive audit rules
  sudo tee /etc/audit/rules.d/hardening.rules <<'EOF'
# Ubuntu 24.04 Security Audit Rules
# Delete all existing rules
-D

# Buffer Size
-b 8192

# Failure Mode
-f 1

# Monitor authentication files
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Monitor sudo configuration
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config

# Monitor systemd
-w /etc/systemd/ -p wa -k systemd
-w /lib/systemd/ -p wa -k systemd

# Monitor snap changes (Ubuntu specific)
-w /snap/bin/ -p wa -k snap_changes
-w /var/lib/snapd/ -p wa -k snap_changes

# Monitor AppArmor
-w /etc/apparmor.d/ -p wa -k apparmor
-w /etc/apparmor/ -p wa -k apparmor

# Monitor kernel modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,finit_module -k module_insertion
-a always,exit -F arch=b64 -S delete_module -k module_deletion

# Monitor privileged commands
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Monitor system calls
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change

# Monitor network configuration
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/hostname -p wa -k system-locale
-w /etc/netplan/ -p wa -k network_config

# Monitor login/logout events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

# Monitor cron
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# Make configuration immutable
-e 2
EOF

  # Load rules and restart auditd
  augenrules --load
  sudo systemctl restart auditd
  sudo systemctl enable auditd

  # Configure audit log rotation
  sudo tee /etc/logrotate.d/audit <<'EOF'
/var/log/audit/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
    sharedscripts
    postrotate
        /usr/bin/sudo systemctl kill -s USR1 auditd.service >/dev/null 2>&1 || true
    endscript
}
EOF

  show_info "System auditing (auditd) configured successfully"
}

configure_sysctl() {
  show_info "Hardening kernel parameters..."

  local SYSCTL_SECURITY_HARDENING_CONF_FILE='/etc/sysctl.d/99-security-hardening.conf'

  backup_file "/etc/sysctl.conf"

  # Create comprehensive sysctl security configuration
  sudo tee $SYSCTL_SECURITY_HARDENING_CONF_FILE <<'EOF'
# Ubuntu 24.04 Kernel Security Hardening

### Network Security ###

# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore Directed pings
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable TCP/IP SYN cookies
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Disable TCP timestamps
net.ipv4.tcp_timestamps = 0

# Enable TCP RFC 1337
net.ipv4.tcp_rfc1337 = 1

# Secure ICMP
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# ARP security
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2

### Kernel Security ###

# Enable ExecShield (if available)
kernel.exec-shield = 1
kernel.randomize_va_space = 2

# Restrict dmesg
kernel.dmesg_restrict = 1

# Restrict kernel pointer exposure
kernel.kptr_restrict = 2

# Restrict ptrace
kernel.yama.ptrace_scope = 2

# Disable kexec
kernel.kexec_load_disabled = 1

# Harden BPF JIT
net.core.bpf_jit_harden = 2

# Restrict performance events
kernel.perf_event_paranoid = 3

# Disable SysRq
kernel.sysrq = 0

# Restrict core dumps
fs.suid_dumpable = 0

# Protect hardlinks and symlinks
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_regular = 2
fs.protected_fifos = 2

# ASLR
kernel.randomize_va_space = 2

# Restrict unprivileged userns
kernel.unprivileged_userns_clone = 0

# Ubuntu 24.04 specific
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_enable = 0
kernel.modules_disabled = 0
kernel.io_uring_disabled = 2

### Performance and Resource Protection ###
vm.swappiness = 10
vm.vfs_cache_pressure = 50
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_fastopen = 3

# Increase system file limits
fs.file-max = 65536

# Restrict access to kernel logs
kernel.printk = 3 3 3 3
EOF

  # Apply sysctl settings
  sudo sysctl -p /etc/sysctl.d/99-security-hardening.conf

  show_info "Kernel security parameters configured"
}

give_info() {
  local info_text="
UBUNTU HARDENING COMPLETED SUCCESSFULLY!

Configuration Summary:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SSH Configuration:
• Port: $SSH_PORT
• Root login: Disabled
• Password auth: As configured
• Max auth tries: 3

Security Tools Installed:
• Fail2ban: Active (protects SSH and other services)
• ClamAV: Active (scheduled scans)
• Lynis: Weekly security audits
• RKHunter: Rootkit detection
• AIDE: File integrity monitoring
• Auditd: System activity auditing

Firewall:
• UFW enabled with strict rules
• Only SSH and specified ports allowed
• IPv6 support enabled

Log Files:
• Main log: $LOG_FILE
• Backup directory: $BACKUP_DIR
• ClamAV logs: /var/log/clamav/
• Lynis logs: /var/log/lynis/
• Audit logs: /var/log/audit/

Important Notes:
• Remember your new SSH port: $SSH_PORT
• Reboot recommended to ensure all changes take effect
• Run 'sudo lynis audit system' for security assessment
• Check fail2ban status: 'sudo fail2ban-client status'

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"

  if [[ -z "$NO_GUI" ]] && command -v whiptail &>/dev/null; then
    whiptail --title "Hardening Complete" --msgbox "$info_text" 25 80
  else
    echo "$info_text"
  fi
}

# Main execution
main() {
  # Check if running as root
  if [[ $EUID -eq 0 ]]; then
    show_message "Warning: Running as root. Some features may not work correctly. It's recommended to run as a sudo user."
  fi

  # Show configuration menu
  show_configuration_menu

  # Convert space-separated to array for processing
  IFS=' ' read -ra SELECTED_COMPONENTS <<<"$COMPONENTS"

  total_steps=${#SELECTED_COMPONENTS[@]}
  current_step=0

  # Process selected components
  for component in "${SELECTED_COMPONENTS[@]}"; do
    # Remove quotes if present
    component=$(echo "$component" | tr -d '"')
    current_step=$((current_step + 1))
    progress=$((current_step * 100 / total_steps))

    case "$component" in
    "INSTALL_PKGS")
      show_progress $progress "Installing packages..."
      install_pkgs
      ;;
    "ADMIN_USER")
      show_progress $progress "Creating admin user..."
      setup_admin_user
      ;;
    "SSH")
      show_progress $progress "Configuring SSH..."
      configure_ssh
      ;;
    "FIREWALL")
      show_progress $progress "Configuring firewall..."
      set_fw_rules
      ;;
    "FAIL2BAN")
      show_progress $progress "Configuring Fail2ban..."
      configure_fail2ban
      ;;
    "CLAMAV")
      show_progress $progress "Configuring ClamAV..."
      configure_and_start_clamav
      ;;
    "LYNIS")
      show_progress $progress "Installing Lynis..."
      install_cisofy_lynis
      ;;
    "RKHUNTER")
      show_progress $progress "Configuring RKHunter..."
      configure_rkhunter
      ;;
    "NTP")
      show_progress $progress "Setting up time sync..."
      setup_ntp
      ;;
    "AIDE")
      show_progress $progress "Configuring AIDE..."
      configure_aide
      ;;
    "AUDITD")
      show_progress $progress "Configuring auditd..."
      configure_auditd
      ;;
    "SYSCTL")
      show_progress $progress "Hardening kernel..."
      configure_sysctl
      ;;
    esac
  done

  # Show completion information
  give_info

  # Ask about reboot
  reboot_now=$(get_yes_no "Reboot now to ensure all changes take effect?")
  if [[ "$reboot_now" == "yes" ]]; then
    show_info "System will reboot in 10 seconds..."
    sleep 10
    sudo reboot
  else
    show_info "Please remember to reboot your system later to ensure all changes take effect."
  fi
}

# Run main function
main "$@"
