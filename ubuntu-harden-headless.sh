#!/bin/bash

sudo apt-get update -y >/dev/null 2>&1

export DEBIAN_FRONTEND=noninteractive
TMP_DIR=/tmp
LOG_DIR=/var/log/ubuntu-hardener
LOG_FILE=${LOG_FILE:-"$LOG_DIR/harden-$(date +%s).log"}
SSHD_CONFIG_FILE="/etc/ssh/sshd_config"
SSH_PORT=1911
BACKUP_DIR=$TMP_DIR/backup
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
  *)
    VERBOSITY_LEVEL=3
    ;;
  esac
done

log() {
  local level=$1
  local message=$2
  if [[ $VERBOSITY_LEVEL -ge $level ]]; then
    echo "[$(date)] $message" | sudo tee -a "$LOG_FILE"
  fi
}

sudo mkdir -p $LOG_DIR
sudo mkdir -p $BACKUP_DIR
log 0 "Extracting logs to $LOG_FILE"

setup_admin_user() {
  local ADMIN_USER="john"
  log 0 "Yeni yönetici kullanıcı oluşturuluyor: $ADMIN_USER"
  if ! id "$ADMIN_USER" &>/dev/null; then
    sudo useradd -m -G sudo -s "$(which bash)" "$ADMIN_USER"
  fi

  local ssh_dir="/home/$ADMIN_USER/.ssh"
  mkdir -p "$ssh_dir"
  sudo chmod 700 "$ssh_dir"
  touch "$ssh_dir/authorized_keys"
  sudo chmod 600 "$ssh_dir/authorized_keys"
  sudo chown -R "$ADMIN_USER:$ADMIN_USER" -R "/home/$ADMIN_USER"

  log 0 "SSH anahtarınızı $ssh_dir/authorized_keys dosyasına ekleyin."
}

backup_file() {
  local file=$1
  if [[ -f "$file" ]]; then
    local backup_name="${BACKUP_DIR}/$(basename "$file").$(date +%Y%m%d-%H%M%S).bak"
    log 2 "cp -p \"$file\" \"$backup_name\""
    cp -p "$file" "$backup_name"
    # Save file permissions and ownership
    log 2 "stat -c \"%a %U:%G\" \"$file\" >\"${backup_name}.meta\""
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
  log 2 "curl -fsSL https://packages.cisofy.com/keys/cisofy-software-public.key | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/cisofy-software-public.gpg"
  curl -fsSL https://packages.cisofy.com/keys/cisofy-software-public.key | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/cisofy-software-public.gpg
  log 2 'echo "deb [arch=amd64,arm64 signed-by=/etc/apt/trusted.gpg.d/cisofy-software-public.gpg] https://packages.cisofy.com/community/lynis/deb/ stable main" | sudo tee /etc/apt/sources.list.d/cisofy-lynis.list'
  echo "deb [arch=amd64,arm64 signed-by=/etc/apt/trusted.gpg.d/cisofy-software-public.gpg] https://packages.cisofy.com/community/lynis/deb/ stable main" | sudo tee /etc/apt/sources.list.d/cisofy-lynis.list
}

install_pkgs() {
  log 0 "Updating repositories"
  log 2 "sudo apt-get update -y"
  sudo apt-get update -y
  log 0 "Installing packages"
  add_cisofy_lynis_repos
  pkgs="fail2ban sudo clamav clamav-daemon clamav-freshclam rkhunter ntp aide aide-common aide-dynamic auditd audispd-plugins lynis"
  log 2 "sudo apt-get install $pkgs -y"
  sudo apt-get install $pkgs -y
}

sed_ssh_param() {
  PARAM=$1
  VALUE=$2
  TARGET=$3
  log 0 "Setting $PARAM"
  if grep -q $PARAM $SSHD_CONFIG_FILE; then
    log 2 "sed -i \"s/^#$PARAM.*/$PARAM $VALUE/\" \"$TARGET\""
    sudo sed -i "s/^#$PARAM.*/$PARAM $VALUE/" "$TARGET"
    log 2 "sed -i \"s/^$PARAM.*/$PARAM $VALUE/\" \"$TARGET\""
    sudo sed -i "s/^$PARAM.*/$PARAM $VALUE/" "$TARGET"
  else
    echo "$PARAM $VALUE" | tee -a $SSHD_CONFIG_FILE
  fi
}

restart_ssh() {
  log 0 "Restarting SSH service"
  log 2 "sudo systemctl restart ssh"
  sudo systemctl restart ssh || sudo systemctl restart sshd
}

configure_ssh() {
  sed_ssh_param "PubkeyAuthentication" "yes" $SSHD_CONFIG_FILE
  sed_ssh_param "MaxAuthTries" "3" $SSHD_CONFIG_FILE
  sed_ssh_param "PermitRootLogin" "no" $SSHD_CONFIG_FILE
  sed_ssh_param "Port" "$SSH_PORT" $SSHD_CONFIG_FILE
  sed_ssh_param "PasswordAuthentication" "yes" $SSHD_CONFIG_FILE
  sed_ssh_param "MaxSessions" "2" $SSHD_CONFIG_FILE
  sed_ssh_param "TCPKeepAlive" "no" $SSHD_CONFIG_FILE
  sed_ssh_param "X11Forwarding" "no" $SSHD_CONFIG_FILE
  sed_ssh_param "AllowAgentForwarding" "no" $SSHD_CONFIG_FILE
  restart_ssh
}

set_fw_rules() {
  log 0 "Configuring UFW firewall with IPv6 support..."

  backup_file "/etc/default/ufw"

  # Enable IPv6 support
  log 0 "Enable IPv6 support"
  sed -i 's/IPV6=.*/IPV6=yes/' /etc/default/ufw

  # Reset firewall to defaults
  log 0 "Reset UFW"
  log 2 "ufw --force reset"
  ufw --force reset

  # Set default policies
  log 2 "ufw default deny incoming"
  log 0 "Default Deny Incoming Requests"
  ufw default deny incoming
  log 2 "ufw default allow outgoing"
  log 0 "Default Allow Outing Requests"
  ufw default allow outgoing
  log 2 "ufw default deny routed"
  log 0 "Deny Routed"
  ufw default deny routed

  # Configure logging
  log 2 "ufw logging on"
  log 0 "Enable UFW"
  ufw logging on
  log 2 "ufw logging medium"
  log 0 "Enable UFW logging"
  ufw logging medium

  # Basic rules with rate limiting
  log 2 "ufw limit 22/tcp comment 'SSH rate limit'"
  log 0 "Allow SSH"
  ufw limit $SSH_PORT/tcp comment 'SSH rate limit'

  # Allow DHCP client (important for cloud instances)
  log 2 "ufw allow 68/udp comment 'DHCP client'"
  log 0 "Allow 67/UDP DHPCP Client for cloud"
  ufw allow 68/udp comment 'DHCP client'

  # Enable firewall
  log 2 "echo \"y\" | ufw enable"
  log 0 "Enable UFW service"
  echo "y" | ufw enable

  # Configure iptables-persistent
  if command -v netfilter-persistent &>/dev/null; then
    log 2 "netfilter-persistent save"
    netfilter-persistent save
    log 2 "sudo systemctl enable netfilter-persistent"
    sudo systemctl enable netfilter-persistent
  fi

  log 0 "UFW firewall configured and enabled"
  log 0 "NOTE: Only SSH (rate-limited) and DHCP are allowed"

}

configure_fail2ban() {
  log 0 "Configuring Fail2ban with systemd integration..."

  backup_file "/etc/fail2ban/jail.conf"

  # Create jail.local with Ubuntu 24.04 optimizations
  log 0 "Configuring jail.local"
  sudo tee /etc/fail2ban/jail.local <<'EOF'
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

# Destination email
# destemail = root@localhost
# sender = root@localhost
# mta = sendmail

# Action
action = %(action_mwl)s

# Ignore localhost and private networks
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
maxretry = 3
bantime = 2h
findtime = 20m

[sshd-ddos]
enabled = true
port = ssh
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

# Additional jails for common services
[apache-auth]
enabled = false
port = http,https
logpath = %(apache_error_log)s

[nginx-http-auth]
enabled = false
port = http,https
logpath = %(nginx_error_log)s
EOF

  # Create custom filters
  log 2 "mkdir -p /etc/fail2ban/filter.d"
  sudo mkdir -p /etc/fail2ban/filter.d

  # Port scan filter
  log 0 "Configuring port scan filter"
  sudo tee /etc/fail2ban/filter.d/port-scan.conf <<'EOF'
[Definition]
failregex = .*UFW BLOCK.* SRC=<HOST>
ignoreregex =
EOF

  # Restart fail2ban
  log 0 "Restarting fail2ban"
  log 2 "sudo systemctl restart fail2ban"
  sudo systemctl restart fail2ban
  log 2 "sudo systemctl enable fail2ban"
  log 0 "Enable fail2ban service"
  sudo systemctl enable fail2ban

  log 0 "Fail2ban configured with systemd integration"
}

configure_and_start_clamav() {
  log 0 "Configuring ClamAV with performance optimizations..."

  # Configure ClamAV for Ubuntu 24.04
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
  log 0 "Stoping clamav-freshclam service"
  sudo systemctl stop clamav-freshclam
  log 0 "Stoping clamav-daemon"
  sudo systemctl stop clamav-daemon

  # Update virus database
  log 0 "Updating ClamAV virus database..."
  # TO-DO | fix permission denied
  sudo freshclam || log 0 "WARNING: Failed to update ClamAV database"

  # Start and enable services
  log 0 "Starting clamav-freshclam service"
  sudo systemctl start clamav-freshclam
  log 0 "Starting clamav-daemon service"
  sudo systemctl start clamav-daemon
  log 0 "Enabling clamav-freshclam service"
  sudo systemctl enable clamav-freshclam
  log 0 "Enabling clamav-daemon service"
  sudo systemctl enable clamav-daemon

  # Get scan frequency
  log 0 "Please enter how often you want ClamAV scans to run (daily/weekly/monthly):"
  read -r scan_frequency
  scan_frequency=$(validate_frequency "$scan_frequency")

  # Create systemd timer for scans (Ubuntu 24.04 preferred)
  log 0 "Creating clamav-scan service"
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
fi
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
  log 0 "Enabling clamav-scan service"
  sudo systemctl enable clamav-scan.timer
  log 0 "Starting clamav-scan service"
  sudo systemctl start clamav-scan.timer

  log 0 "ClamAV configured with $scan_frequency scans"
}

install_cisofy_lynis() {
  local LYNIS_BIN='/usr/sbin/lynis'
  LYNIS_LOG_FOLDER='/var/log/lynis'
  log 2 "mkdir -p /var/log/lynis"
  sudo mkdir -p /var/log/lynis
  log 2 "sudo crontab -l -u root | tee $TMP_DIR/crontab"
  sudo crontab -l -u root | tee $TMP_DIR/crontab
  tee -a $TMP_DIR/crontab <<EOF
0 0 * * 7  $LYNIS_BIN audit system --log-file $LYNIS_LOG_FOLDER/\$(date +%Y-%m-%d_%H-%M-%S -u).log --cronjob
EOF
  log 2 "sudo crontab -u root $TMP_DIR/crontab"
  sudo crontab -u root $TMP_DIR/crontab
  log 2 "sudo rm $TMP_DIR/crontab"
  sudo rm $TMP_DIR/crontab
}

configure_rkhunter() {
  log 0 "Configuring $RKHUNTER_CONFIG_FILE"
  local RKHUNTER_CONFIG_FILE="/etc/rkhunter.conf"
  log 2 "sudo sed -i \"s/UPDATE_MIRRORS\=0/UPDATE_MIRRORS\=1/g\" $RKHUNTER_CONFIG_FILE"
  sudo sed -i "s/UPDATE_MIRRORS\=0/UPDATE_MIRRORS\=1/g" $RKHUNTER_CONFIG_FILE
  log 2 "sudo tee -a \"CRON_DAILY_RUN=true\" $RKHUNTER_CONFIG_FILE"
  echo "CRON_DAILY_RUN=true" | sudo tee -a $RKHUNTER_CONFIG_FILE
  log 2 "sudo sed -i \"s/USE_SYSLOG\=authpriv\.warning/USE_SYSLOG\=authpriv\.notice/g\" $RKHUNTER_CONFIG_FILE"
  sudo sed -i "s/USE_SYSLOG\=authpriv\.warning/USE_SYSLOG\=authpriv\.notice/g" $RKHUNTER_CONFIG_FILE
  log 2 "sudo sed -i 's/^WEB_CMD.*/WEB_CMD=curl -L /' $RKHUNTER_CONFIG_FILE"
  sudo sed -i 's/^WEB_CMD.*/WEB_CMD=curl -L /' $RKHUNTER_CONFIG_FILE
  log 2 "sudo rkhunter --update"
  sudo rkhunter --update
  log 2 "sudo rkhunter --propupd"
  sudo rkhunter --propupd
}

setup_ntp() {
  if sudo systemctl list-unit-files | grep -q systemd-timesyncd.service; then
    log 0 "Using systemd-timesyncd for time synchronization"
    log 2 "sudo systemctl enable systemd-timesyncd.service"
    sudo systemctl enable systemd-timesyncd.service
    log 2 "sudo systemctl start systemd-timesyncd.service"
    sudo systemctl start systemd-timesyncd.service
    log 0 "systemd-timesyncd setup complete"
  else
    log 0 "Using traditional NTP for time synchronization"
    log 2 "sudo systemctl enable ntpsec"
    sudo systemctl enable ntpsec
    log 2 "sudo systemctl start ntpsec"
    sudo systemctl start ntpsec
    log 0 "NTP setup complete"
  fi
}

configure_aide() {
  log 0 "Configuring AIDE file integrity checker..."

  backup_file "/etc/aide/aide.conf"

  # Configure AIDE for Ubuntu 24.04
  log 0 "Configuring /etc/aide/aide.conf"
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
  log 0 "Initializing AIDE database (this may take several minutes)..."
  log 2 "aideinit || error_exit \"Failed to initialize AIDE\""
  sudo aideinit || error_exit "Failed to initialize AIDE"

  # Move database to production location
  if [[ -f /var/lib/aide/aide.db.new ]]; then
    log 2 "mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db"
    sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    log 2 "chmod 600 /var/lib/aide/aide.db"
    sudo chmod 600 /var/lib/aide/aide.db
    log 0 "AIDE database initialized successfully"
  fi

  # Create systemd timer for AIDE checks (Ubuntu 24.04 preferred method)
  log 0 "Creating aide-check service"
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
  log 2 "sudo systemctl daemon-reload"
  sudo systemctl daemon-reload
  log 2 "sudo systemctl enable aide-check.timer"
  log 0 "Enabling aide-check service"
  sudo systemctl enable aide-check.timer
  log 2 "sudo systemctl start aide-check.timer"
  sudo systemctl start aide-check.timer
}

configure_auditd() {
  log 1 "Configuring auditd with Ubuntu 24.04 optimizations..."

  backup_file "/etc/audit/auditd.conf"
  backup_file "/etc/audit/rules.d/audit.rules"

  # Configure auditd for Ubuntu 24.04
  log 0 "Creating auditd.conf"
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

  # Create comprehensive audit rules for Ubuntu 24.04
  log 0 "Creating hardening.rules"
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
  log 2 "augenrules --load"
  augenrules --load
  log 2 "sudo systemctl restart auditd"
  log 0 "Restarting auditd service"
  sudo systemctl restart auditd
  log 2 "sudo systemctl enable auditd"
  log 0 "Enabling auditd"
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
}

configure_sysctl() {
  local SYSCTL_SECURITY_HARDENING_CONF_FILE='/etc/sysctl.d/99-security-hardening.conf'
  log 0 "Configuring kernel security parameters for Ubuntu 24.04..."

  backup_file "/etc/sysctl.conf"

  # Create comprehensive sysctl security configuration
  log 0 "Creating $SYSCTL_SECURITY_HARDENING_CONF_FILE"
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

### IPv6 Security (disable if not needed) ###
# Uncomment to disable IPv6
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1
# net.ipv6.conf.lo.disable_ipv6 = 1

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
  log 0 "Applying sysctl.conf"
  sudo sysctl -p /etc/sysctl.d/99-security-hardening.conf

  log 0 "Kernel parameters configured"
}

give_info() {
  cat <<EOF
SSH Group Users -> $(getent group ssh_users | cut -d : -f 4 | sed "s/\,/ /g")
Clamav Log Files -> $FRESH_CLAM_LOG_FILE, $CLAMD_LOG_FILE, $CLAMSCAN_LOG_FILE
Lynis Log Folder -> $LYNIS_LOG_FOLDER
Rkhunter Log File -> /var/log/rkunter.log
Active Cronjobs for $USER:
$(crontab -l)
Active Cronjobs for root:
$(sudo crontab -l -u root)
EOF
}

# setup_admin_user
install_pkgs
configure_ssh
restart_ssh
configure_fail2ban
configure_and_start_clamav
install_cisofy_lynis
configure_rkhunter
setup_ntp
configure_aide
configure_auditd
configure_sysctl
