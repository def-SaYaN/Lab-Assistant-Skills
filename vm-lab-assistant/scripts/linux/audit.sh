#!/usr/bin/env sh
# audit.sh - Read-only security posture audit for a Linux guest.
#
# CIS-aligned checks across: identity, SSH, kernel/sysctl, filesystem,
# services, firewall, auditing, patching, and mandatory access control.
#
# Writes NOTHING. Safe non-root, though several checks degrade to UNKNOWN
# without privileges.
#
# POSIX sh - runs on Debian/Ubuntu, RHEL/Rocky/Alma, SUSE, Alpine, Arch.
#
# Usage: ./audit.sh [--json FILE] [--category NAME] [--quiet]
# Exit:  0 all pass | 1 warnings only | 2 failures present

set -u

JSON_OUT=""
ONLY_CAT=""
QUIET=0

while [ $# -gt 0 ]; do
  case "$1" in
    --json)     JSON_OUT="${2:-}"; shift 2 ;;
    --category) ONLY_CAT="${2:-}"; shift 2 ;;
    --quiet)    QUIET=1; shift ;;
    -h|--help)
      sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

# ---------------------------------------------------------------- state ----

PASS=0; FAIL=0; WARN=0; UNKNOWN=0
TMPRES="${TMPDIR:-/tmp}/labaudit.$$"
: > "$TMPRES"
trap 'rm -f "$TMPRES"' EXIT INT TERM

IS_ROOT=0
[ "$(id -u)" = "0" ] && IS_ROOT=1

# ------------------------------------------------------------ distro id ----

OS_ID=""; OS_VER=""; OS_NAME=""; PKG=""
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-}"; OS_VER="${VERSION_ID:-}"; OS_NAME="${PRETTY_NAME:-}"
fi
if   command -v apt-get >/dev/null 2>&1; then PKG=apt
elif command -v dnf     >/dev/null 2>&1; then PKG=dnf
elif command -v yum     >/dev/null 2>&1; then PKG=yum
elif command -v zypper  >/dev/null 2>&1; then PKG=zypper
elif command -v apk     >/dev/null 2>&1; then PKG=apk
elif command -v pacman  >/dev/null 2>&1; then PKG=pacman
fi

HAS_SYSTEMD=0
[ -d /run/systemd/system ] && HAS_SYSTEMD=1

# ------------------------------------------------------------- helpers -----

# add ID|CATEGORY|TITLE|STATUS|OBSERVED|EXPECTED|SEVERITY|FIXHINT
add() {
  _id="$1"; _cat="$2"; _title="$3"; _status="$4"
  _obs="$5"; _exp="$6"; _sev="$7"; _fix="${8:-}"

  if [ -n "$ONLY_CAT" ] && [ "$ONLY_CAT" != "$_cat" ]; then return 0; fi

  case "$_status" in
    PASS)    PASS=$((PASS+1)) ;;
    FAIL)    FAIL=$((FAIL+1)) ;;
    WARN)    WARN=$((WARN+1)) ;;
    *)       UNKNOWN=$((UNKNOWN+1)); _status="UNKNOWN" ;;
  esac

  # Strip our delimiter from free text.
  _obs=$(printf '%s' "$_obs"   | tr '|' '/' | tr -d '\n')
  _fix=$(printf '%s' "$_fix"   | tr '|' '/' | tr -d '\n')
  printf '%s|%s|%s|%s|%s|%s|%s|%s\n' \
    "$_id" "$_cat" "$_title" "$_status" "$_obs" "$_exp" "$_sev" "$_fix" >> "$TMPRES"
}

# Read an effective sshd setting. Prefers `sshd -T` (authoritative, includes
# Include'd files and defaults); falls back to grepping config.
SSHD_T=""
sshd_effective() {
  if [ -z "$SSHD_T" ]; then
    if command -v sshd >/dev/null 2>&1 && [ "$IS_ROOT" = "1" ]; then
      SSHD_T=$(sshd -T 2>/dev/null || echo "__NONE__")
    else
      SSHD_T="__NONE__"
    fi
  fi
  [ "$SSHD_T" = "__NONE__" ] && return 1
  printf '%s\n' "$SSHD_T" | awk -v k="$(printf '%s' "$1" | tr 'A-Z' 'a-z')" \
    'tolower($1)==k {print $2; found=1} END{exit !found}'
}

sshd_config_grep() {
  [ -r /etc/ssh/sshd_config ] || return 1
  # sshd keeps the FIRST value it reads. The usual layout is an Include of
  # sshd_config.d/*.conf at the top, so drop-ins are read before the rest.
  # (Approximation: ignores Match blocks; sshd -T is authoritative.)
  _files="/etc/ssh/sshd_config"
  if grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config 2>/dev/null; then
    _files="$(ls /etc/ssh/sshd_config.d/*.conf 2>/dev/null | sort | tr '\n' ' ') /etc/ssh/sshd_config"
  fi
  # shellcheck disable=SC2086
  awk -v k="$(printf '%s' "$1" | tr 'A-Z' 'a-z')" '
    FNR==1 { inmatch=0 }
    tolower($1)=="match" { inmatch=1 }
    !inmatch && tolower($1)==k { print $2; exit }' $_files 2>/dev/null
}

sshd_get() {
  v=$(sshd_effective "$1" 2>/dev/null) && [ -n "$v" ] && { printf '%s' "$v"; return 0; }
  v=$(sshd_config_grep "$1" 2>/dev/null) && [ -n "$v" ] && { printf '%s' "$v"; return 0; }
  return 1
}

sysctl_get() {
  if command -v sysctl >/dev/null 2>&1; then
    sysctl -n "$1" 2>/dev/null && return 0
  fi
  p="/proc/sys/$(printf '%s' "$1" | tr '.' '/')"
  [ -r "$p" ] && cat "$p" 2>/dev/null && return 0
  return 1
}

svc_active() {
  [ "$HAS_SYSTEMD" = "1" ] || return 2
  systemctl is-active --quiet "$1" 2>/dev/null
}

svc_enabled() {
  [ "$HAS_SYSTEMD" = "1" ] || return 2
  systemctl is-enabled --quiet "$1" 2>/dev/null
}

# Coerce to a single integer. `grep -c` exits non-zero on zero matches, so
# `$(... || echo 0)` can yield "0\n0" and break arithmetic tests.
num() {
  printf '%s' "${1:-0}" | tr -dc '0-9\n' | head -1 | sed 's/^$/0/'
}

has_pkg() {
  case "$PKG" in
    apt)    dpkg -s "$1" >/dev/null 2>&1 ;;
    dnf|yum)rpm -q "$1" >/dev/null 2>&1 ;;
    zypper) rpm -q "$1" >/dev/null 2>&1 ;;
    apk)    apk info -e "$1" >/dev/null 2>&1 ;;
    pacman) pacman -Q "$1" >/dev/null 2>&1 ;;
    *) return 2 ;;
  esac
}

# =========================================================== 1. SYSTEM ======

add "SY-001" "System" "Operating system identified" "PASS" \
    "${OS_NAME:-unknown} (id=${OS_ID:-?} ver=${OS_VER:-?})" "supported distro" "Info" ""

add "SY-002" "System" "Kernel version" "PASS" \
    "$(uname -r) $(uname -m)" "current kernel" "Info" ""

add "SY-003" "System" "Audit running with root privileges" \
    "$([ "$IS_ROOT" = "1" ] && echo PASS || echo WARN)" \
    "uid=$(id -u)" "uid=0 for full coverage" "Info" \
    "Re-run with sudo for SSH, audit, and firewall visibility."

# =========================================================== 2. IDENTITY ====

# Accounts with empty passwords (second field in shadow is blank)
if [ -r /etc/shadow ]; then
  empty=$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null | tr '\n' ' ')
  if [ -n "$empty" ]; then
    add "ID-001" "Identity" "No accounts with empty passwords" "FAIL" \
        "$empty" "none" "Critical" "passwd -l <user>  (or set a password)"
  else
    add "ID-001" "Identity" "No accounts with empty passwords" "PASS" "none" "none" "Critical" ""
  fi
else
  add "ID-001" "Identity" "No accounts with empty passwords" "UNKNOWN" \
      "/etc/shadow unreadable" "none" "Critical" "Run as root."
fi

# Non-root UID 0 accounts
uid0=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd 2>/dev/null | tr '\n' ' ')
if [ -n "$uid0" ]; then
  add "ID-002" "Identity" "Only root has UID 0" "FAIL" "$uid0" "root only" "Critical" \
      "A second UID 0 account is a persistent backdoor. Remove or change its UID."
else
  add "ID-002" "Identity" "Only root has UID 0" "PASS" "root only" "root only" "Critical" ""
fi

# Password aging defaults
if [ -r /etc/login.defs ]; then
  maxd=$(awk '/^[[:space:]]*PASS_MAX_DAYS/{print $2}' /etc/login.defs | tail -1)
  mind=$(awk '/^[[:space:]]*PASS_MIN_DAYS/{print $2}' /etc/login.defs | tail -1)
  warnd=$(awk '/^[[:space:]]*PASS_WARN_AGE/{print $2}' /etc/login.defs | tail -1)

  add "ID-003" "Identity" "PASS_MAX_DAYS <= 365" \
      "$([ -n "${maxd:-}" ] && [ "$maxd" -le 365 ] 2>/dev/null && echo PASS || echo WARN)" \
      "${maxd:-unset}" "<= 365" "Low" "Set PASS_MAX_DAYS 90 in /etc/login.defs"

  add "ID-004" "Identity" "PASS_MIN_DAYS >= 1" \
      "$([ -n "${mind:-}" ] && [ "$mind" -ge 1 ] 2>/dev/null && echo PASS || echo WARN)" \
      "${mind:-unset}" ">= 1" "Low" "Set PASS_MIN_DAYS 1 in /etc/login.defs"

  add "ID-005" "Identity" "PASS_WARN_AGE >= 7" \
      "$([ -n "${warnd:-}" ] && [ "$warnd" -ge 7 ] 2>/dev/null && echo PASS || echo WARN)" \
      "${warnd:-unset}" ">= 7" "Low" "Set PASS_WARN_AGE 7 in /etc/login.defs"

  umaskdef=$(awk '/^[[:space:]]*UMASK/{print $2}' /etc/login.defs | tail -1)
  add "ID-006" "Identity" "Default UMASK is 027 or stricter" \
      "$(case "${umaskdef:-}" in 027|077|0027|0077) echo PASS ;; "") echo UNKNOWN ;; *) echo WARN ;; esac)" \
      "${umaskdef:-unset}" "027 or 077" "Medium" "Set UMASK 027 in /etc/login.defs"
else
  add "ID-003" "Identity" "Password aging policy" "UNKNOWN" "/etc/login.defs missing" "" "Low" ""
fi

# Password quality enforcement
pwq=""
for f in /etc/security/pwquality.conf /etc/pam.d/common-password /etc/pam.d/system-auth; do
  [ -r "$f" ] || continue
  if grep -qE 'pam_pwquality|pam_cracklib|minlen' "$f" 2>/dev/null; then pwq="$f"; break; fi
done
if [ -n "$pwq" ]; then
  minlen=$(grep -hoE 'minlen[[:space:]]*=?[[:space:]]*[0-9]+' "$pwq" 2>/dev/null | grep -oE '[0-9]+' | tail -1)
  add "ID-007" "Identity" "Password quality module configured (minlen >= 14)" \
      "$([ -n "${minlen:-}" ] && [ "$minlen" -ge 14 ] 2>/dev/null && echo PASS || echo WARN)" \
      "$pwq minlen=${minlen:-unset}" "minlen >= 14" "Medium" \
      "Set minlen=14 in /etc/security/pwquality.conf"
else
  add "ID-007" "Identity" "Password quality module configured" "WARN" \
      "pam_pwquality/pam_cracklib not found" "configured" "Medium" \
      "Install libpam-pwquality (apt) or libpwquality (dnf)."
fi

# Account lockout on failed auth
lock=""
for f in /etc/pam.d/common-auth /etc/pam.d/system-auth /etc/security/faillock.conf; do
  [ -r "$f" ] || continue
  if grep -qE 'pam_faillock|pam_tally2' "$f" 2>/dev/null; then lock="$f"; break; fi
done
add "ID-008" "Identity" "Account lockout configured (pam_faillock)" \
    "$([ -n "$lock" ] && echo PASS || echo WARN)" \
    "${lock:-not configured}" "pam_faillock active" "Medium" \
    "Configure deny=5 unlock_time=900 in /etc/security/faillock.conf"

# root login on tty
if [ -r /etc/securetty ]; then
  n=$(num "$(grep -cvE '^[[:space:]]*(#|$)' /etc/securetty 2>/dev/null)")
  add "ID-009" "Identity" "Root console logins restricted" \
      "$([ "$n" -le 2 ] && echo PASS || echo WARN)" \
      "$n tty entries" "minimal" "Low" "Trim /etc/securetty"
fi

# sudo config: NOPASSWD is a common lab shortcut that becomes a prod risk
if [ -d /etc/sudoers.d ] || [ -r /etc/sudoers ]; then
  nopw=$(grep -rhE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | head -3 | tr '\n' ';')
  add "ID-010" "Identity" "No passwordless sudo rules" \
      "$([ -z "$nopw" ] && echo PASS || echo WARN)" \
      "${nopw:-none}" "none" "High" \
      "NOPASSWD lets any compromised shell escalate silently. Remove unless required."

  ald=$(grep -rhE '^[^#]*Defaults.*\blog_year\b|^[^#]*Defaults.*\blogfile\b' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | head -1)
  add "ID-011" "Identity" "sudo logging configured" \
      "$([ -n "$ald" ] && echo PASS || echo WARN)" \
      "${ald:-default syslog}" "explicit logfile" "Low" \
      'Add: Defaults logfile="/var/log/sudo.log"'
fi

# =========================================================== 3. SSH =========

if [ -r /etc/ssh/sshd_config ] || command -v sshd >/dev/null 2>&1; then

  v=$(sshd_get permitrootlogin || echo "")
  add "SSH-001" "SSH" "PermitRootLogin disabled" \
      "$(case "$v" in no|prohibit-password|forced-commands-only) echo PASS ;; "") echo UNKNOWN ;; *) echo FAIL ;; esac)" \
      "${v:-unknown}" "no" "High" \
      "Set 'PermitRootLogin no' in /etc/ssh/sshd_config"

  v=$(sshd_get passwordauthentication || echo "")
  add "SSH-002" "SSH" "Password authentication disabled (keys only)" \
      "$(case "$v" in no) echo PASS ;; "") echo UNKNOWN ;; *) echo WARN ;; esac)" \
      "${v:-unknown}" "no" "High" \
      "Keys only defeats brute force. Ensure a working key first."

  v=$(sshd_get permitemptypasswords || echo "")
  add "SSH-003" "SSH" "Empty passwords rejected" \
      "$(case "$v" in no) echo PASS ;; "") echo UNKNOWN ;; *) echo FAIL ;; esac)" \
      "${v:-unknown}" "no" "Critical" "Set 'PermitEmptyPasswords no'"

  v=$(sshd_get x11forwarding || echo "")
  add "SSH-004" "SSH" "X11 forwarding disabled" \
      "$(case "$v" in no) echo PASS ;; "") echo UNKNOWN ;; *) echo WARN ;; esac)" \
      "${v:-unknown}" "no" "Low" "Set 'X11Forwarding no'"

  v=$(sshd_get maxauthtries || echo "")
  add "SSH-005" "SSH" "MaxAuthTries <= 4" \
      "$([ -n "$v" ] && [ "$v" -le 4 ] 2>/dev/null && echo PASS || echo WARN)" \
      "${v:-unknown}" "<= 4" "Medium" "Set 'MaxAuthTries 4'"

  v=$(sshd_get clientaliveinterval || echo "")
  add "SSH-006" "SSH" "Idle session timeout configured" \
      "$([ -n "$v" ] && [ "$v" -gt 0 ] && [ "$v" -le 900 ] 2>/dev/null && echo PASS || echo WARN)" \
      "${v:-unset}" "1-900 seconds" "Low" \
      "Set 'ClientAliveInterval 300' and 'ClientAliveCountMax 3'"

  v=$(sshd_get logingracetime || echo "")
  add "SSH-007" "SSH" "LoginGraceTime <= 60" \
      "$([ -n "$v" ] && [ "$v" -le 60 ] 2>/dev/null && echo PASS || echo WARN)" \
      "${v:-unknown}" "<= 60" "Low" "Set 'LoginGraceTime 60'"

  v=$(sshd_get hostbasedauthentication || echo "")
  add "SSH-008" "SSH" "HostbasedAuthentication disabled" \
      "$(case "$v" in no) echo PASS ;; "") echo UNKNOWN ;; *) echo FAIL ;; esac)" \
      "${v:-unknown}" "no" "Medium" "Set 'HostbasedAuthentication no'"

  v=$(sshd_get ignorerhosts || echo "")
  add "SSH-009" "SSH" "IgnoreRhosts enabled" \
      "$(case "$v" in yes) echo PASS ;; "") echo UNKNOWN ;; *) echo FAIL ;; esac)" \
      "${v:-unknown}" "yes" "Medium" "Set 'IgnoreRhosts yes'"

  v=$(sshd_get permituserenvironment || echo "")
  add "SSH-010" "SSH" "PermitUserEnvironment disabled" \
      "$(case "$v" in no) echo PASS ;; "") echo UNKNOWN ;; *) echo WARN ;; esac)" \
      "${v:-unknown}" "no" "Medium" "Set 'PermitUserEnvironment no'"

  # Host key file permissions
  badkeys=""
  for k in /etc/ssh/ssh_host_*_key; do
    [ -e "$k" ] || continue
    m=$(stat -c '%a' "$k" 2>/dev/null || stat -f '%Lp' "$k" 2>/dev/null)
    case "$m" in 600|400) ;; *) badkeys="$badkeys $k($m)" ;; esac
  done
  add "SSH-011" "SSH" "Host private keys are 0600 or stricter" \
      "$([ -z "$badkeys" ] && echo PASS || echo FAIL)" \
      "${badkeys:-all ok}" "0600" "High" "chmod 600 /etc/ssh/ssh_host_*_key"
else
  add "SSH-001" "SSH" "OpenSSH server present" "PASS" "not installed" "n/a" "Info" \
      "No sshd means no SSH attack surface."
fi

# ======================================================== 4. KERNEL/SYSCTL ==

# key = expected
sysctl_check() {
  _id="$1"; _key="$2"; _want="$3"; _sev="$4"; _why="$5"
  _got=$(sysctl_get "$_key" 2>/dev/null | tr -d ' \t')
  if [ -z "$_got" ]; then
    add "$_id" "Kernel" "$_key = $_want" "UNKNOWN" "unreadable" "$_want" "$_sev" "$_why"
  elif [ "$_got" = "$_want" ]; then
    add "$_id" "Kernel" "$_key = $_want" "PASS" "$_got" "$_want" "$_sev" ""
  else
    add "$_id" "Kernel" "$_key = $_want" "FAIL" "$_got" "$_want" "$_sev" \
        "sysctl -w $_key=$_want ; persist in /etc/sysctl.d/99-hardening.conf"
  fi
}

sysctl_check "KN-001" "net.ipv4.ip_forward" "0" "Medium" \
  "Routing between interfaces turns the host into a pivot."
sysctl_check "KN-002" "net.ipv4.conf.all.accept_redirects" "0" "Medium" \
  "ICMP redirects allow route hijacking."
sysctl_check "KN-003" "net.ipv4.conf.all.send_redirects" "0" "Medium" \
  "Only routers should send redirects."
sysctl_check "KN-004" "net.ipv4.conf.all.accept_source_route" "0" "Medium" \
  "Source routing enables spoofing."
sysctl_check "KN-005" "net.ipv4.conf.all.rp_filter" "1" "Medium" \
  "Reverse-path filtering drops spoofed source addresses."
sysctl_check "KN-006" "net.ipv4.conf.all.log_martians" "1" "Low" \
  "Logs impossible source addresses."
sysctl_check "KN-007" "net.ipv4.icmp_echo_ignore_broadcasts" "1" "Low" \
  "Prevents smurf amplification."
sysctl_check "KN-008" "net.ipv4.tcp_syncookies" "1" "Medium" \
  "Mitigates SYN flood."
sysctl_check "KN-009" "kernel.randomize_va_space" "2" "High" \
  "Full ASLR. Anything less weakens memory-corruption exploitation defence."
sysctl_check "KN-010" "fs.suid_dumpable" "0" "Medium" \
  "Core dumps from setuid binaries can leak secrets."
sysctl_check "KN-011" "kernel.dmesg_restrict" "1" "Medium" \
  "Kernel log can leak addresses useful for exploitation."
sysctl_check "KN-012" "kernel.kptr_restrict" "2" "Medium" \
  "Hides kernel pointers from unprivileged users."
sysctl_check "KN-013" "net.ipv6.conf.all.accept_redirects" "0" "Medium" \
  "IPv6 equivalent of KN-002."
sysctl_check "KN-014" "kernel.yama.ptrace_scope" "1" "Medium" \
  "Restricts ptrace to descendants; blocks cross-process credential theft."
sysctl_check "KN-015" "net.ipv4.conf.default.accept_redirects" "0" "Medium" \
  "'all' only covers existing interfaces; 'default' covers ones created later."
sysctl_check "KN-016" "net.ipv4.conf.default.accept_source_route" "0" "Medium" \
  "Source routing on interfaces created after boot."
sysctl_check "KN-017" "net.ipv6.conf.default.accept_redirects" "0" "Medium" \
  "IPv6 redirects on interfaces created after boot."

# ======================================================= 5. FILESYSTEM ======

perm_check() {
  _id="$1"; _path="$2"; _want="$3"; _sev="$4"
  if [ ! -e "$_path" ]; then
    add "$_id" "Filesystem" "$_path permissions $_want" "UNKNOWN" "missing" "$_want" "$_sev" ""
    return
  fi
  _got=$(stat -c '%a' "$_path" 2>/dev/null || stat -f '%Lp' "$_path" 2>/dev/null)
  if [ "$_got" = "$_want" ]; then
    add "$_id" "Filesystem" "$_path permissions $_want" "PASS" "$_got" "$_want" "$_sev" ""
  else
    add "$_id" "Filesystem" "$_path permissions $_want" "WARN" "$_got" "$_want" "$_sev" \
        "chmod $_want $_path"
  fi
}

perm_check "FS-001" "/etc/passwd"  "644" "Medium"
perm_check "FS-002" "/etc/group"   "644" "Medium"
perm_check "FS-004" "/etc/ssh/sshd_config" "600" "Medium"

# shadow is 640 on Debian (root:shadow), 000/400 on RHEL
if [ -e /etc/shadow ]; then
  m=$(stat -c '%a' /etc/shadow 2>/dev/null || stat -f '%Lp' /etc/shadow 2>/dev/null)
  case "$m" in
    0|400|600|640) st=PASS ;;
    *)             st=FAIL ;;
  esac
  add "FS-003" "Filesystem" "/etc/shadow not world-readable" "$st" "$m" "<= 640" "Critical" \
      "chmod 640 /etc/shadow (Debian) or chmod 000 (RHEL)"
fi

# World-writable files outside the usual temp dirs
if [ "$IS_ROOT" = "1" ]; then
  ww=$(find / -xdev -type f -perm -0002 \
        -not -path '/proc/*' -not -path '/sys/*' -not -path '/tmp/*' \
        -not -path '/var/tmp/*' -not -path '/dev/*' 2>/dev/null | head -5 | tr '\n' ' ')
  add "FS-005" "Filesystem" "No world-writable files outside temp dirs" \
      "$([ -z "$ww" ] && echo PASS || echo WARN)" \
      "${ww:-none}" "none" "High" "chmod o-w on each file listed."

  nouser=$(find / -xdev \( -nouser -o -nogroup \) \
            -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -5 | tr '\n' ' ')
  add "FS-006" "Filesystem" "No unowned files" \
      "$([ -z "$nouser" ] && echo PASS || echo WARN)" \
      "${nouser:-none}" "none" "Medium" \
      "Unowned files get silently inherited by any new UID with that number."

  suid=$(num "$(find / -xdev -type f -perm -4000 2>/dev/null | wc -l)")
  add "FS-007" "Filesystem" "SUID binary count is reasonable" \
      "$([ "${suid:-0}" -le 40 ] && echo PASS || echo WARN)" \
      "$suid SUID binaries" "<= 40" "Medium" \
      "Review: find / -xdev -type f -perm -4000. Each is a potential escalation path."
else
  add "FS-005" "Filesystem" "World-writable file scan" "UNKNOWN" "needs root" "none" "High" ""
fi

# /tmp mount hardening
if mount | grep -qE ' on /tmp '; then
  topts=$(mount | grep -E ' on /tmp ' | head -1 | sed 's/.*(\(.*\)).*/\1/')
  miss=""
  for o in noexec nosuid nodev; do
    printf '%s' "$topts" | grep -q "$o" || miss="$miss $o"
  done
  add "FS-008" "Filesystem" "/tmp mounted noexec,nosuid,nodev" \
      "$([ -z "$miss" ] && echo PASS || echo WARN)" \
      "${topts}" "noexec,nosuid,nodev" "Medium" \
      "Blocks payload execution from a world-writable directory. Missing:${miss:- none}"
else
  add "FS-008" "Filesystem" "/tmp is a separate mount" "WARN" "not a separate mount" \
      "separate with noexec,nosuid,nodev" "Low" \
      "Without a separate /tmp you cannot apply noexec there."
fi

# Core dumps
cl=$(grep -rhE '^[[:space:]]*\*[[:space:]]+hard[[:space:]]+core' /etc/security/limits.conf /etc/security/limits.d/ 2>/dev/null | head -1)
add "FS-009" "Filesystem" "Core dumps disabled" \
    "$([ -n "$cl" ] && echo PASS || echo WARN)" \
    "${cl:-not configured}" "* hard core 0" "Low" \
    "Core dumps can contain credentials and keys."

# ========================================================= 6. SERVICES =====

if [ "$HAS_SYSTEMD" = "1" ]; then
  i=0
  for pair in \
    "telnet.socket:Telnet (cleartext)" \
    "rsh.socket:rsh (cleartext)" \
    "rlogin.socket:rlogin (cleartext)" \
    "vsftpd:FTP (often cleartext)" \
    "avahi-daemon:mDNS/Bonjour discovery" \
    "cups:Print service" \
    "rpcbind:RPC portmapper" \
    "nfs-server:NFS server" \
    "smbd:Samba file sharing" \
    "snmpd:SNMP (often default community)" \
    "xinetd:Legacy super-server" \
    "dovecot:IMAP/POP3" \
    "slapd:LDAP" \
    "named:DNS server"
  do
    i=$((i+1))
    svc="${pair%%:*}"; desc="${pair#*:}"
    if svc_active "$svc" 2>/dev/null; then
      add "$(printf 'SV-%03d' "$i")" "Services" "$svc disabled - $desc" "WARN" \
          "active" "inactive/masked" "Medium" \
          "systemctl disable --now $svc"
    else
      add "$(printf 'SV-%03d' "$i")" "Services" "$svc disabled - $desc" "PASS" \
          "not active" "inactive" "Info" ""
    fi
  done
else
  add "SV-001" "Services" "Service enumeration" "UNKNOWN" "no systemd" "" "Medium" ""
fi

# Listening sockets bound to all interfaces
if command -v ss >/dev/null 2>&1; then
  lst=$(num "$(ss -lntuH 2>/dev/null | awk '{print $5}' | grep -cE '^(0\.0\.0\.0|\*|\[::\]):')")
  ports=$(ss -lntuH 2>/dev/null | awk '{print $5}' | grep -E '^(0\.0\.0\.0|\*|\[::\]):' \
          | sed 's/.*://' | sort -un | tr '\n' ',' | sed 's/,$//')
  add "NW-001" "Network" "Externally-bound listening sockets minimal" \
      "$([ "${lst:-0}" -le 6 ] && echo PASS || echo WARN)" \
      "${lst:-0} sockets; ports: ${ports:-none}" "minimal" "Medium" \
      "Each 0.0.0.0 listener is network-reachable. Bind to 127.0.0.1 or firewall it."
elif command -v netstat >/dev/null 2>&1; then
  lst=$(num "$(netstat -lntu 2>/dev/null | grep -cE '0\.0\.0\.0:|:::')")
  add "NW-001" "Network" "Externally-bound listening sockets minimal" \
      "$([ "${lst:-0}" -le 6 ] && echo PASS || echo WARN)" \
      "${lst:-0} sockets" "minimal" "Medium" ""
fi

# ========================================================= 7. FIREWALL =====

fw_found=0
if command -v ufw >/dev/null 2>&1; then
  fw_found=1
  st=$(ufw status 2>/dev/null | head -1)
  add "FW-001" "Firewall" "ufw enabled with default deny incoming" \
      "$(printf '%s' "$st" | grep -qiE '^status:[[:space:]]*active' && echo PASS || echo FAIL)" \
      "${st:-unknown}" "Status: active" "High" \
      "ufw default deny incoming; ufw allow 22/tcp; ufw --force enable"
fi
if command -v firewall-cmd >/dev/null 2>&1; then
  fw_found=1
  st=$(firewall-cmd --state 2>/dev/null)
  add "FW-002" "Firewall" "firewalld running" \
      "$([ "$st" = "running" ] && echo PASS || echo FAIL)" \
      "${st:-not running}" "running" "High" "systemctl enable --now firewalld"
fi
if command -v nft >/dev/null 2>&1 && [ "$IS_ROOT" = "1" ]; then
  n=$(num "$(nft list ruleset 2>/dev/null | grep -c 'chain')")
  [ "$n" -gt 0 ] && fw_found=1
  add "FW-003" "Firewall" "nftables ruleset present" \
      "$([ "${n:-0}" -gt 0 ] && echo PASS || echo WARN)" \
      "$n chains" ">0 chains" "Medium" ""
fi
if command -v iptables >/dev/null 2>&1 && [ "$IS_ROOT" = "1" ]; then
  pol=$(iptables -S 2>/dev/null | grep '^-P INPUT' | awk '{print $3}')
  [ -n "$pol" ] && add "FW-004" "Firewall" "iptables INPUT policy is DROP" \
      "$([ "$pol" = "DROP" ] && echo PASS || echo WARN)" \
      "${pol:-unknown}" "DROP" "High" "iptables -P INPUT DROP (ensure SSH is allowed first)"
fi
[ "$fw_found" = "0" ] && add "FW-001" "Firewall" "A host firewall is present" "FAIL" \
    "none detected" "ufw/firewalld/nftables" "High" \
    "Install and enable ufw (Debian) or firewalld (RHEL)."

# ========================================================= 8. AUDIT/LOG ====

if [ "$HAS_SYSTEMD" = "1" ]; then
  if svc_active auditd 2>/dev/null; then
    add "LG-001" "Logging" "auditd running" "PASS" "active" "active" "Medium" ""
    if [ "$IS_ROOT" = "1" ] && command -v auditctl >/dev/null 2>&1; then
      nr=$(num "$(auditctl -l 2>/dev/null | grep -vc '^No rules')")
      add "LG-002" "Logging" "Audit rules loaded" \
          "$([ "${nr:-0}" -gt 3 ] && echo PASS || echo WARN)" \
          "$nr rules" ">3 rules" "Medium" \
          "Load a CIS ruleset into /etc/audit/rules.d/"
    fi
  else
    add "LG-001" "Logging" "auditd running" "WARN" "not active" "active" "Medium" \
        "systemctl enable --now auditd  (package: auditd / audit)"
  fi

  if svc_active rsyslog 2>/dev/null || svc_active systemd-journald 2>/dev/null; then
    add "LG-003" "Logging" "System logging active" "PASS" "rsyslog or journald active" "active" "Medium" ""
  else
    add "LG-003" "Logging" "System logging active" "WARN" "none active" "active" "Medium" ""
  fi
fi

# Persistent journal
if [ -d /var/log/journal ]; then
  add "LG-004" "Logging" "systemd journal persisted to disk" "PASS" "/var/log/journal exists" "persistent" "Low" ""
else
  add "LG-004" "Logging" "systemd journal persisted to disk" "WARN" \
      "volatile (lost on reboot)" "persistent" "Low" \
      "mkdir -p /var/log/journal && systemd-tmpfiles --create --prefix /var/log/journal"
fi

# Remote log shipping
rem=$(grep -rhE '^[[:space:]]*\*\.\*[[:space:]]+@|^[[:space:]]*action\(type="omfwd"' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | head -1)
add "LG-005" "Logging" "Logs forwarded to a remote collector" \
    "$([ -n "$rem" ] && echo PASS || echo WARN)" \
    "${rem:-not configured}" "remote target" "Medium" \
    "Local-only logs are deleted by any attacker who gets root."

# ========================================================= 9. MAC ==========

mac_found=0
if command -v getenforce >/dev/null 2>&1; then
  mac_found=1
  se=$(getenforce 2>/dev/null)
  add "MAC-001" "MAC" "SELinux enforcing" \
      "$([ "$se" = "Enforcing" ] && echo PASS || echo WARN)" \
      "${se:-unknown}" "Enforcing" "High" \
      "setenforce 1; set SELINUX=enforcing in /etc/selinux/config"
fi
if command -v aa-status >/dev/null 2>&1; then
  mac_found=1
  if [ "$IS_ROOT" = "1" ]; then
    np=$(num "$(aa-status --enforced 2>/dev/null)")
    add "MAC-002" "MAC" "AppArmor profiles enforced" \
        "$([ "${np:-0}" -gt 0 ] && echo PASS || echo WARN)" \
        "${np:-0} enforced profiles" ">0" "High" "aa-enforce /etc/apparmor.d/*"
  else
    add "MAC-002" "MAC" "AppArmor profiles enforced" "UNKNOWN" "needs root" ">0" "High" ""
  fi
fi
[ "$mac_found" = "0" ] && add "MAC-001" "MAC" "Mandatory access control present" "WARN" \
    "neither SELinux nor AppArmor" "one enforcing" "High" \
    "MAC contains a compromised service to its own domain."

# ========================================================= 10. PATCHING ====

case "$PKG" in
  apt)
    if [ "$IS_ROOT" = "1" ]; then
      n=$(num "$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst ')")
      sec=$(num "$(apt-get -s upgrade 2>/dev/null | grep '^Inst ' | grep -ci security)")
      add "PA-001" "Patching" "No pending package updates" \
          "$([ "${n:-0}" -eq 0 ] && echo PASS || echo FAIL)" \
          "$n pending ($sec security)" "0" \
          "$([ "${sec:-0}" -gt 0 ] && echo Critical || echo Medium)" \
          "apt-get update && apt-get upgrade"
    else
      add "PA-001" "Patching" "Pending update scan" "UNKNOWN" "needs root" "0 pending" "Medium" ""
    fi
    add "PA-002" "Patching" "Unattended security upgrades enabled" \
        "$(has_pkg unattended-upgrades && echo PASS || echo WARN)" \
        "$(has_pkg unattended-upgrades && echo installed || echo 'not installed')" \
        "installed+enabled" "Medium" "apt-get install unattended-upgrades"
    ;;
  dnf|yum)
    if [ "$IS_ROOT" = "1" ]; then
      n=$(num "$($PKG -q check-update 2>/dev/null | awk 'NF>=3 && $1 ~ /\./' | grep -c .)")
      add "PA-001" "Patching" "No pending package updates" \
          "$([ "${n:-0}" -eq 0 ] && echo PASS || echo FAIL)" \
          "$n pending" "0" "Medium" "$PKG update"
    else
      add "PA-001" "Patching" "Pending update scan" "UNKNOWN" "needs root" "0" "Medium" ""
    fi
    add "PA-002" "Patching" "Automatic updates configured" \
        "$(has_pkg dnf-automatic && echo PASS || echo WARN)" \
        "$(has_pkg dnf-automatic && echo installed || echo 'not installed')" \
        "installed" "Medium" "dnf install dnf-automatic"
    ;;
  *)
    add "PA-001" "Patching" "Package update status" "UNKNOWN" \
        "unsupported package manager: ${PKG:-none}" "" "Medium" ""
    ;;
esac

# Reboot required?
if [ -f /var/run/reboot-required ] || [ -f /run/reboot-required ]; then
  add "PA-003" "Patching" "No reboot pending" "WARN" "reboot-required flag present" "none" "Medium" \
      "Reboot to activate the new kernel."
elif command -v needs-restarting >/dev/null 2>&1 && [ "$IS_ROOT" = "1" ]; then
  if needs-restarting -r >/dev/null 2>&1; then
    add "PA-003" "Patching" "No reboot pending" "PASS" "none" "none" "Medium" ""
  else
    add "PA-003" "Patching" "No reboot pending" "WARN" "reboot required" "none" "Medium" "Reboot."
  fi
else
  add "PA-003" "Patching" "No reboot pending" "PASS" "no flag present" "none" "Low" ""
fi

# ========================================================= 11. BOOT ========

if [ -r /boot/grub/grub.cfg ] || [ -r /boot/grub2/grub.cfg ]; then
  gc=$([ -r /boot/grub/grub.cfg ] && echo /boot/grub/grub.cfg || echo /boot/grub2/grub.cfg)
  m=$(stat -c '%a' "$gc" 2>/dev/null || stat -f '%Lp' "$gc" 2>/dev/null)
  add "BT-001" "Boot" "GRUB config not world-readable" \
      "$(case "$m" in 600|400) echo PASS ;; *) echo WARN ;; esac)" \
      "$m" "600" "Medium" "chmod 600 $gc"

  if grep -qE '^[[:space:]]*(set superusers|password_pbkdf2)' "$gc" 2>/dev/null; then
    add "BT-002" "Boot" "GRUB password set" "PASS" "configured" "configured" "Medium" ""
  else
    add "BT-002" "Boot" "GRUB password set" "WARN" "not set" "configured" "Medium" \
        "Without it, anyone at the console can boot to a root shell via init=/bin/bash."
  fi
fi

if [ -d /sys/firmware/efi ]; then
  if command -v mokutil >/dev/null 2>&1; then
    sb=$(mokutil --sb-state 2>/dev/null | head -1)
    add "BT-003" "Boot" "Secure Boot enabled" \
        "$(printf '%s' "$sb" | grep -qi 'enabled' && echo PASS || echo WARN)" \
        "${sb:-unknown}" "SecureBoot enabled" "Medium" "Enable Secure Boot in VM firmware."
  fi
else
  add "BT-003" "Boot" "System booted via UEFI" "WARN" "legacy BIOS" "UEFI" "Low" \
      "UEFI + Secure Boot blocks bootkits."
fi

# ============================================================== REPORT ======

TOTAL=$((PASS+FAIL+WARN+UNKNOWN))
DENOM=$((PASS+FAIL+WARN))
SCORE=0
[ "$DENOM" -gt 0 ] && SCORE=$(( 100 * PASS / DENOM ))

if [ "$QUIET" = "0" ]; then
  echo ""
  echo "===== LINUX HARDENING AUDIT ====="
  echo "Host     : $(hostname 2>/dev/null || echo unknown)"
  echo "OS       : ${OS_NAME:-unknown}"
  echo "Kernel   : $(uname -r)"
  echo "User     : $(id -un) (uid=$(id -u))"
  echo "Time     : $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "Score    : ${SCORE}% ($PASS pass / $FAIL fail / $WARN warn / $UNKNOWN unknown)"
  [ "$IS_ROOT" = "0" ] && echo "NOTE     : running non-root; some checks report UNKNOWN."
  echo ""

  # Group by category, failures first within each.
  cats=$(cut -d'|' -f2 "$TMPRES" | sort -u)
  for c in $cats; do
    echo "--- $c ---"
    for st in FAIL WARN UNKNOWN PASS; do
      awk -F'|' -v c="$c" -v s="$st" '$2==c && $4==s' "$TMPRES" | \
      while IFS='|' read -r id cat title status obs exp sev fix; do
        printf '  [%-4s] %-8s %s\n' "$status" "$id" "$title"
        if [ "$status" != "PASS" ] && [ -n "$obs" ]; then
          printf '           observed: %s\n' "$obs"
        fi
        if { [ "$status" = "FAIL" ] || [ "$status" = "WARN" ]; } && [ -n "$fix" ]; then
          printf '           fix     : %s\n' "$fix"
        fi
      done
    done
    echo ""
  done

  crit=$(awk -F'|' '$4=="FAIL" && ($7=="Critical" || $7=="High")' "$TMPRES")
  if [ -n "$crit" ]; then
    echo "===== PRIORITY FAILURES ====="
    printf '%s\n' "$crit" | while IFS='|' read -r id cat title status obs exp sev fix; do
      printf '  [%s] %s - %s\n' "$sev" "$id" "$title"
    done
    echo ""
  fi
fi

if [ -n "$JSON_OUT" ]; then
  {
    printf '{\n'
    printf '  "summary": {\n'
    printf '    "host": "%s",\n'     "$(hostname 2>/dev/null)"
    printf '    "os": "%s",\n'       "${OS_NAME:-unknown}"
    printf '    "kernel": "%s",\n'   "$(uname -r)"
    printf '    "root": %s,\n'       "$([ "$IS_ROOT" = "1" ] && echo true || echo false)"
    printf '    "timestampUtc": "%s",\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '    "total": %d, "pass": %d, "fail": %d, "warn": %d, "unknown": %d,\n' \
           "$TOTAL" "$PASS" "$FAIL" "$WARN" "$UNKNOWN"
    printf '    "scorePercent": %d\n' "$SCORE"
    printf '  },\n'
    printf '  "results": [\n'
    first=1
    while IFS='|' read -r id cat title status obs exp sev fix; do
      [ -z "$id" ] && continue
      [ "$first" = "0" ] && printf ',\n'
      first=0
      esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr '\t\r' '  '; }
      printf '    {"id":"%s","category":"%s","title":"%s","status":"%s","observed":"%s","expected":"%s","severity":"%s","fixHint":"%s"}' \
        "$(esc "$id")" "$(esc "$cat")" "$(esc "$title")" "$(esc "$status")" \
        "$(esc "$obs")" "$(esc "$exp")" "$(esc "$sev")" "$(esc "$fix")"
    done < "$TMPRES"
    printf '\n  ]\n}\n'
  } > "$JSON_OUT"
  [ "$QUIET" = "0" ] && echo "JSON report: $JSON_OUT"
fi

if [ "$FAIL" -gt 0 ]; then exit 2
elif [ "$WARN" -gt 0 ]; then exit 1
else exit 0
fi
