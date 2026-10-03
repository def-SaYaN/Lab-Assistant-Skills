#!/usr/bin/env sh
# harden.sh - Apply Linux hardening controls with dry-run and rollback.
#
# Remediates findings from audit.sh. Every change backs up the prior state
# into a rollback journal directory before touching anything.
#
# REQUIRES ROOT.
#
# Usage:
#   ./harden.sh --dry-run                  show what would change
#   ./harden.sh --profile baseline         apply
#   ./harden.sh --profile strict
#   ./harden.sh --rollback /var/backups/lab-harden/<stamp>
#   ./harden.sh --profile strict --only HD-SSH-011,HD-FW-001
#   ./harden.sh --profile strict --yes     allow keys-only SSH even when no
#                                          authorized_keys file is found
#
# Profiles:
#   baseline  safe, reversible, low breakage risk
#   strict    + service lockdown, SSH keys-only, firewall default deny
#   paranoid  + noexec /tmp, disable extra kernel modules, strict umask
#
# Exit: 0 ok | 2 failures | 3 not root

set -u

PROFILE="baseline"
DRY=0
ROLLBACK=""
ONLY=""
SKIP=""
JOURNAL_BASE="/var/backups/lab-harden"
ASSUME_YES=0

while [ $# -gt 0 ]; do
  case "$1" in
    --profile)  PROFILE="${2:-baseline}"; shift 2 ;;
    --dry-run|-n) DRY=1; shift ;;
    --rollback) ROLLBACK="${2:-}"; shift 2 ;;
    --only)     ONLY="${2:-}"; shift 2 ;;
    --skip)     SKIP="${2:-}"; shift 2 ;;
    --yes|-y)   ASSUME_YES=1; shift ;;
    -h|--help)  sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

case "$PROFILE" in
  baseline|strict|paranoid) ;;
  *) echo "invalid profile: $PROFILE (baseline|strict|paranoid)" >&2; exit 2 ;;
esac

[ "$(id -u)" = "0" ] || { echo "harden.sh must run as root." >&2; exit 3; }

APPLIED=0; FAILED=0; SKIPPED=0; NOOP=0; WOULD=0

# ------------------------------------------------------------- rollback ----

if [ -n "$ROLLBACK" ]; then
  [ -d "$ROLLBACK" ] || { echo "rollback dir not found: $ROLLBACK" >&2; exit 2; }
  echo "Reverting from: $ROLLBACK"
  if [ -f "$ROLLBACK/manifest.txt" ]; then
    # manifest lines: backup_relpath<TAB>original_path
    while IFS="$(printf '\t')" read -r rel orig; do
      [ -z "${rel:-}" ] && continue
      if [ -f "$ROLLBACK/$rel" ]; then
        cp -p "$ROLLBACK/$rel" "$orig" 2>/dev/null && echo "  [rev] $orig"
      fi
    done < "$ROLLBACK/manifest.txt"
  fi
  if [ -f "$ROLLBACK/removed-files.txt" ]; then
    while read -r f; do
      [ -z "${f:-}" ] && continue
      rm -f "$f" 2>/dev/null && echo "  [rev] removed $f"
    done < "$ROLLBACK/removed-files.txt"
  fi
  if [ -f "$ROLLBACK/perms.txt" ]; then
    # perms lines: mode<TAB>path
    while IFS="$(printf '\t')" read -r mode path; do
      [ -z "${path:-}" ] && continue
      chmod "$mode" "$path" 2>/dev/null && echo "  [rev] chmod $mode $path"
    done < "$ROLLBACK/perms.txt"
  fi
  if [ -f "$ROLLBACK/services.txt" ] && [ -s "$ROLLBACK/services.txt" ]; then
    echo ""
    echo "Service changes must be reverted manually:"
    cat "$ROLLBACK/services.txt"
  fi
  echo ""
  echo "Rollback complete. Reload affected daemons and settings:"
  echo "  sshd -t && systemctl restart sshd   (ssh on Debian/Ubuntu)"
  echo "  sysctl --system"
  exit 0
fi

# -------------------------------------------------------------- journal ----

STAMP=$(date -u '+%Y%m%d-%H%M%S')
JDIR="$JOURNAL_BASE/$STAMP"
if [ "$DRY" = "0" ]; then
  mkdir -p "$JDIR" || { echo "cannot create journal dir $JDIR" >&2; exit 2; }
  chmod 700 "$JDIR"
  : > "$JDIR/manifest.txt"
  : > "$JDIR/removed-files.txt"
  : > "$JDIR/services.txt"
  : > "$JDIR/perms.txt"
fi

# Back up a file ONCE per run. Controls call this repeatedly for the same
# file (sshd_config has 13 controls); without the guard the second call would
# overwrite the pristine backup with an already-modified copy, making the
# rollback journal useless.
backup_file() {
  _f="$1"
  [ "$DRY" = "1" ] && return 0
  _rel=$(printf '%s' "$_f" | sed 's|^/||; s|/|_|g')

  # Already captured in this run?
  if [ -f "$JDIR/.seen" ] && grep -Fxq "$_f" "$JDIR/.seen" 2>/dev/null; then
    return 0
  fi
  printf '%s\n' "$_f" >> "$JDIR/.seen"

  if [ -f "$_f" ]; then
    cp -p "$_f" "$JDIR/$_rel" 2>/dev/null || return 1
    printf '%s\t%s\n' "$_rel" "$_f" >> "$JDIR/manifest.txt"
  else
    # File did not exist: record so rollback deletes what we create.
    printf '%s\n' "$_f" >> "$JDIR/removed-files.txt"
  fi
  return 0
}

selected() {
  _id="$1"; shift
  _ok=0
  for p in "$@"; do [ "$p" = "$PROFILE" ] && _ok=1; done
  [ "$_ok" = "1" ] || { SKIPPED=$((SKIPPED+1)); return 1; }
  if [ -n "$ONLY" ]; then
    printf '%s' ",$ONLY," | grep -q ",$_id," || { SKIPPED=$((SKIPPED+1)); return 1; }
  fi
  if [ -n "$SKIP" ]; then
    printf '%s' ",$SKIP," | grep -q ",$_id," && { SKIPPED=$((SKIPPED+1)); return 1; }
  fi
  return 0
}

say_would() { printf '  [would] %-12s %s\n' "$1" "$2"; WOULD=$((WOULD+1)); }
say_set()   { printf '  [set]   %-12s %s\n' "$1" "$2"; APPLIED=$((APPLIED+1)); }
say_ok()    { printf '  [ok]    %-12s %s\n' "$1" "$2"; NOOP=$((NOOP+1)); }
say_fail()  { printf '  [FAIL]  %-12s %s\n' "$1" "$2"; FAILED=$((FAILED+1)); }

# Set a key=value in a config file (append or replace), idempotently.
set_kv() {
  _id="$1"; _file="$2"; _key="$3"; _val="$4"; _sep="${5:- }"; _desc="$6"

  # Remember what sshd should end up with, for the sshd -T check later.
  if [ "$_file" = "${SSHD:-}" ]; then
    SSHD_EXPECT="$SSHD_EXPECT $(printf '%s:%s' "$_key" "$_val" | tr 'A-Z' 'a-z')"
  fi

  _cur=""
  if [ -f "$_file" ]; then
    _cur=$(grep -iE "^[[:space:]]*${_key}([[:space:]]|=)" "$_file" 2>/dev/null | tail -1 \
           | sed -E "s/^[[:space:]]*${_key}[[:space:]]*=?[[:space:]]*//I")
  fi
  if [ "$_cur" = "$_val" ]; then say_ok "$_id" "$_desc"; return 0; fi

  if [ "$DRY" = "1" ]; then
    say_would "$_id" "$_desc (${_cur:-unset} -> $_val)"
    return 0
  fi

  backup_file "$_file" || { say_fail "$_id" "backup failed for $_file"; return 1; }
  mkdir -p "$(dirname "$_file")" 2>/dev/null
  touch "$_file" 2>/dev/null

  if grep -qiE "^[[:space:]]*#?[[:space:]]*${_key}([[:space:]]|=)" "$_file" 2>/dev/null; then
    # Replace existing (including commented) occurrences.
    # NOTE: the delimiter must NOT be '|' - the regex contains an alternation
    # '([[:space:]]|=)' and sed would read that '|' as the delimiter.
    _tmp="${_file}.labtmp.$$"
    sed -E "s,^[[:space:]]*#?[[:space:]]*(${_key})([[:space:]]|=).*,${_key}${_sep}${_val}," \
        "$_file" > "$_tmp" 2>/dev/null && cat "$_tmp" > "$_file" && rm -f "$_tmp"
  elif grep -qiE '^[[:space:]]*Match[[:space:]]' "$_file" 2>/dev/null; then
    # sshd_config: anything after the first Match line belongs to that Match
    # block, so a global setting must be inserted ABOVE it, not appended.
    _tmp="${_file}.labtmp.$$"
    awk -v line="${_key}${_sep}${_val}" '
      !done && tolower($0) ~ /^[[:space:]]*match[[:space:]]/ { print line; done=1 }
      { print }' "$_file" > "$_tmp" 2>/dev/null && cat "$_tmp" > "$_file" && rm -f "$_tmp"
  else
    printf '%s%s%s\n' "$_key" "$_sep" "$_val" >> "$_file"
  fi

  _new=$(grep -iE "^[[:space:]]*${_key}([[:space:]]|=)" "$_file" 2>/dev/null | tail -1 \
         | sed -E "s/^[[:space:]]*${_key}[[:space:]]*=?[[:space:]]*//I")
  if [ "$_new" = "$_val" ]; then say_set "$_id" "$_desc"; else say_fail "$_id" "$_desc"; fi
}

HAS_SYSTEMD=0
[ -d /run/systemd/system ] && HAS_SYSTEMD=1

OS_ID=""
[ -r /etc/os-release ] && . /etc/os-release && OS_ID="${ID:-}"

echo ""
echo "===== LINUX HARDENING : profile=$PROFILE ====="
[ "$DRY" = "1" ] && echo "DRY RUN - nothing will be changed."
[ "$DRY" = "0" ] && echo "Journal: $JDIR"
echo ""

# ======================================================= 1. KERNEL/SYSCTL ==

echo "--- Kernel parameters (sysctl) ---"
SYSCTL_FILE="/etc/sysctl.d/99-lab-hardening.conf"

sysctl_set() {
  _id="$1"; _key="$2"; _val="$3"; _desc="$4"; shift 4
  selected "$_id" "$@" || return 0

  _cur=$(sysctl -n "$_key" 2>/dev/null | tr -d ' \t')
  if [ "$_cur" = "$_val" ]; then say_ok "$_id" "$_key=$_val"; return 0; fi

  if [ "$DRY" = "1" ]; then say_would "$_id" "$_key: ${_cur:-?} -> $_val ($_desc)"; return 0; fi

  backup_file "$SYSCTL_FILE"
  # Remove any previous line for this key in our file, then append.
  if [ -f "$SYSCTL_FILE" ] && grep -q "^${_key}[[:space:]]*=" "$SYSCTL_FILE" 2>/dev/null; then
    _t="${SYSCTL_FILE}.tmp.$$"
    grep -v "^${_key}[[:space:]]*=" "$SYSCTL_FILE" > "$_t" && cat "$_t" > "$SYSCTL_FILE" && rm -f "$_t"
  fi
  printf '%s = %s\n' "$_key" "$_val" >> "$SYSCTL_FILE"

  if sysctl -w "$_key=$_val" >/dev/null 2>&1; then
    say_set "$_id" "$_key=$_val"
  else
    # Persisted but not live (common in containers).
    say_set "$_id" "$_key=$_val (persisted; live set failed - normal in containers)"
  fi
}

sysctl_set "HD-KN-001" "net.ipv4.ip_forward"                    "0" "no routing" baseline strict paranoid
sysctl_set "HD-KN-002" "net.ipv4.conf.all.accept_redirects"     "0" "no ICMP redirect" baseline strict paranoid
sysctl_set "HD-KN-003" "net.ipv4.conf.all.send_redirects"       "0" "no send redirect" baseline strict paranoid
sysctl_set "HD-KN-004" "net.ipv4.conf.all.accept_source_route"  "0" "no source route" baseline strict paranoid
sysctl_set "HD-KN-005" "net.ipv4.conf.all.rp_filter"            "1" "reverse path filter" baseline strict paranoid
sysctl_set "HD-KN-006" "net.ipv4.conf.all.log_martians"         "1" "log spoofed" baseline strict paranoid
sysctl_set "HD-KN-007" "net.ipv4.icmp_echo_ignore_broadcasts"   "1" "no smurf" baseline strict paranoid
sysctl_set "HD-KN-008" "net.ipv4.tcp_syncookies"                "1" "syn flood" baseline strict paranoid
sysctl_set "HD-KN-009" "kernel.randomize_va_space"              "2" "full ASLR" baseline strict paranoid
sysctl_set "HD-KN-010" "fs.suid_dumpable"                       "0" "no suid cores" baseline strict paranoid
sysctl_set "HD-KN-011" "kernel.dmesg_restrict"                  "1" "restrict dmesg" baseline strict paranoid
sysctl_set "HD-KN-012" "kernel.kptr_restrict"                   "2" "hide kptrs" strict paranoid
sysctl_set "HD-KN-013" "net.ipv6.conf.all.accept_redirects"     "0" "no v6 redirect" baseline strict paranoid
sysctl_set "HD-KN-014" "kernel.yama.ptrace_scope"               "1" "restrict ptrace" strict paranoid
# "all" only covers existing interfaces; "default" covers ones created later.
sysctl_set "HD-KN-015" "net.ipv4.conf.default.accept_redirects" "0" "no ICMP redirect (new ifaces)" baseline strict paranoid
sysctl_set "HD-KN-016" "net.ipv4.conf.default.accept_source_route" "0" "no source route (new ifaces)" baseline strict paranoid
sysctl_set "HD-KN-017" "net.ipv6.conf.default.accept_redirects" "0" "no v6 redirect (new ifaces)" baseline strict paranoid

# =============================================================== 2. SSH ====

echo ""
echo "--- SSH daemon ---"
SSHD_MAIN=/etc/ssh/sshd_config
SSHD="$SSHD_MAIN"
SSHD_EXPECT=""

# sshd uses the FIRST value it sees for a keyword. Modern distros put
# "Include /etc/ssh/sshd_config.d/*.conf" at the top of sshd_config, so a
# drop-in such as 50-cloud-init.conf (PasswordAuthentication yes) beats
# anything we write further down. When that Include exists, write our
# settings to a drop-in that sorts first instead; rollback then just
# deletes it.
if [ -f "$SSHD_MAIN" ] && \
   grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' "$SSHD_MAIN" 2>/dev/null; then
  SSHD=/etc/ssh/sshd_config.d/00-lab-hardening.conf
  echo "  (sshd_config includes sshd_config.d; writing settings to $SSHD)"
fi

# Users who could still log in with a key once passwords are turned off.
ssh_key_users() {
  for _h in /root /home/*; do
    [ -s "$_h/.ssh/authorized_keys" ] && printf '%s ' "$(basename "$_h")"
  done
}

if [ -f "$SSHD_MAIN" ]; then
  selected "HD-SSH-001" baseline strict paranoid && \
    set_kv "HD-SSH-001" "$SSHD" "PermitRootLogin" "no" " " "Disable direct root SSH login"
  selected "HD-SSH-002" baseline strict paranoid && \
    set_kv "HD-SSH-002" "$SSHD" "PermitEmptyPasswords" "no" " " "Reject empty passwords"
  selected "HD-SSH-003" baseline strict paranoid && \
    set_kv "HD-SSH-003" "$SSHD" "MaxAuthTries" "4" " " "Limit auth attempts per connection"
  selected "HD-SSH-004" baseline strict paranoid && \
    set_kv "HD-SSH-004" "$SSHD" "X11Forwarding" "no" " " "Disable X11 forwarding"
  selected "HD-SSH-005" baseline strict paranoid && \
    set_kv "HD-SSH-005" "$SSHD" "IgnoreRhosts" "yes" " " "Ignore .rhosts files"
  selected "HD-SSH-006" baseline strict paranoid && \
    set_kv "HD-SSH-006" "$SSHD" "HostbasedAuthentication" "no" " " "Disable host-based auth"
  selected "HD-SSH-007" baseline strict paranoid && \
    set_kv "HD-SSH-007" "$SSHD" "ClientAliveInterval" "300" " " "Idle timeout 300s"
  # NOTE: 0 does NOT mean "disconnect immediately" on OpenSSH >= 8.2 - it
  # disables keepalive-based termination entirely. 3 drops dead clients
  # after 3 unanswered keepalives (CIS current guidance).
  selected "HD-SSH-008" baseline strict paranoid && \
    set_kv "HD-SSH-008" "$SSHD" "ClientAliveCountMax" "3" " " "Drop unresponsive clients after 3 missed keepalives"
  selected "HD-SSH-009" baseline strict paranoid && \
    set_kv "HD-SSH-009" "$SSHD" "LoginGraceTime" "60" " " "Auth must complete in 60s"
  selected "HD-SSH-010" baseline strict paranoid && \
    set_kv "HD-SSH-010" "$SSHD" "PermitUserEnvironment" "no" " " "Block user env injection"
  if selected "HD-SSH-011" strict paranoid; then
    _ku=$(ssh_key_users)
    if [ -z "$_ku" ] && [ "$ASSUME_YES" = "0" ]; then
      # Turning off passwords with no authorized_keys anywhere locks
      # everyone out at the next sshd restart.
      say_fail "HD-SSH-011" "refusing PasswordAuthentication no: no authorized_keys found (override with --yes)"
    else
      set_kv "HD-SSH-011" "$SSHD" "PasswordAuthentication" "no" " " \
        "Keys only (key users: ${_ku:-none - forced by --yes})"
    fi
  fi
  selected "HD-SSH-012" strict paranoid && \
    set_kv "HD-SSH-012" "$SSHD" "AllowTcpForwarding" "no" " " "Block SSH tunnelling"
  selected "HD-SSH-013" baseline strict paranoid && \
    set_kv "HD-SSH-013" "$SSHD" "LogLevel" "VERBOSE" " " "Log key fingerprints on login"

  # Validate before anyone restarts sshd with a broken config.
  if [ "$DRY" = "0" ] && command -v sshd >/dev/null 2>&1; then
    # Debian's sshd -t refuses to run without its privilege-separation dir.
    [ -d /run/sshd ] || mkdir -p /run/sshd 2>/dev/null
    if sshd -t 2>/dev/null; then
      echo "  [ok]    sshd-check   configuration syntax valid"
      # Confirm the EFFECTIVE values (sshd -T) - catches settings shadowed
      # by an earlier Include or by a Match block.
      _eff=$(sshd -T 2>/dev/null)
      if [ -n "$_eff" ]; then
        _shadow=""
        for _kv in $SSHD_EXPECT; do
          _k=${_kv%%:*}; _v=${_kv#*:}
          _got=$(printf '%s\n' "$_eff" | awk -v k="$_k" '$1==k {print tolower($2); exit}')
          [ -n "$_got" ] && [ "$_got" != "$_v" ] && _shadow="$_shadow $_k=$_got"
        done
        if [ -n "$_shadow" ]; then
          echo "  [FAIL]  sshd-check   effective config still has:$_shadow (overridden elsewhere?)"
          FAILED=$((FAILED+1))
        fi
      fi
    else
      echo "  [FAIL]  sshd-check   sshd -t FAILED - DO NOT restart sshd; restore from $JDIR"
      FAILED=$((FAILED+1))
    fi
  fi
else
  echo "  (no /etc/ssh/sshd_config - skipping SSH section)"
fi

# ======================================================= 3. ACCOUNTS =======

echo ""
echo "--- Accounts and password policy ---"
LD=/etc/login.defs
if [ -f "$LD" ]; then
  selected "HD-ID-001" baseline strict paranoid && \
    set_kv "HD-ID-001" "$LD" "PASS_MAX_DAYS" "90"  "	" "Password max age 90 days"
  selected "HD-ID-002" baseline strict paranoid && \
    set_kv "HD-ID-002" "$LD" "PASS_MIN_DAYS" "1"   "	" "Password min age 1 day"
  selected "HD-ID-003" baseline strict paranoid && \
    set_kv "HD-ID-003" "$LD" "PASS_WARN_AGE" "7"   "	" "Warn 7 days before expiry"
  selected "HD-ID-004" baseline strict && \
    set_kv "HD-ID-004" "$LD" "UMASK"         "027" "	" "Default umask 027"
  selected "HD-ID-005" paranoid && \
    set_kv "HD-ID-005" "$LD" "UMASK"         "077" "	" "Default umask 077 (paranoid)"
fi

# Password quality
PWQ=/etc/security/pwquality.conf
if [ -f "$PWQ" ]; then
  selected "HD-ID-006" baseline strict paranoid && \
    set_kv "HD-ID-006" "$PWQ" "minlen"  "14" " = " "Minimum password length 14"
  selected "HD-ID-007" strict paranoid && \
    set_kv "HD-ID-007" "$PWQ" "dcredit" "-1" " = " "Require a digit"
  selected "HD-ID-008" strict paranoid && \
    set_kv "HD-ID-008" "$PWQ" "ucredit" "-1" " = " "Require an uppercase char"
  selected "HD-ID-009" strict paranoid && \
    set_kv "HD-ID-009" "$PWQ" "lcredit" "-1" " = " "Require a lowercase char"
  selected "HD-ID-010" strict paranoid && \
    set_kv "HD-ID-010" "$PWQ" "ocredit" "-1" " = " "Require a special char"
fi

# Lockout
FL=/etc/security/faillock.conf
if [ -f "$FL" ]; then
  selected "HD-ID-011" baseline strict paranoid && \
    set_kv "HD-ID-011" "$FL" "deny"        "5"   " = " "Lock after 5 failures"
  selected "HD-ID-012" baseline strict paranoid && \
    set_kv "HD-ID-012" "$FL" "unlock_time" "900" " = " "Unlock after 15 minutes"
fi

# Core dumps
if selected "HD-ID-013" baseline strict paranoid; then
  LIM=/etc/security/limits.d/99-lab-hardening.conf
  if [ -f "$LIM" ] && grep -q 'hard core' "$LIM" 2>/dev/null; then
    say_ok "HD-ID-013" "core dumps disabled"
  elif [ "$DRY" = "1" ]; then
    say_would "HD-ID-013" "disable core dumps via $LIM"
  else
    backup_file "$LIM"
    printf '* hard core 0\n' >> "$LIM" && say_set "HD-ID-013" "core dumps disabled" \
      || say_fail "HD-ID-013" "core dumps"
  fi
fi

# ======================================================= 4. SERVICES =======

echo ""
echo "--- Services ---"
disable_svc() {
  _id="$1"; _svc="$2"; _desc="$3"; shift 3
  selected "$_id" "$@" || return 0
  [ "$HAS_SYSTEMD" = "1" ] || { say_ok "$_id" "$_svc (no systemd)"; return 0; }

  # Exact unit match: a bare prefix would treat cups-browsed as cups.
  if ! systemctl list-unit-files 2>/dev/null | grep -qE "^${_svc}(\.service)?[[:space:]]"; then
    say_ok "$_id" "$_svc not installed"; return 0
  fi
  if ! systemctl is-active --quiet "$_svc" 2>/dev/null && \
     ! systemctl is-enabled --quiet "$_svc" 2>/dev/null; then
    say_ok "$_id" "$_svc already disabled"; return 0
  fi
  if [ "$DRY" = "1" ]; then say_would "$_id" "disable $_svc ($_desc)"; return 0; fi

  printf 'was-enabled: %s\n' "$_svc" >> "$JDIR/services.txt"
  if systemctl disable --now "$_svc" >/dev/null 2>&1; then
    say_set "$_id" "disabled $_svc ($_desc)"
  else
    say_fail "$_id" "could not disable $_svc"
  fi
}

disable_svc "HD-SV-001" "avahi-daemon" "mDNS discovery"       baseline strict paranoid
disable_svc "HD-SV-002" "cups"         "printing"             baseline strict paranoid
disable_svc "HD-SV-003" "rpcbind"      "RPC portmapper"       baseline strict paranoid
disable_svc "HD-SV-004" "telnet.socket" "cleartext telnet"    baseline strict paranoid
disable_svc "HD-SV-005" "vsftpd"       "FTP"                  strict paranoid
disable_svc "HD-SV-006" "snmpd"        "SNMP"                 strict paranoid
disable_svc "HD-SV-007" "nfs-server"   "NFS export"           strict paranoid
disable_svc "HD-SV-008" "smbd"         "Samba"                strict paranoid
disable_svc "HD-SV-009" "xinetd"       "legacy super-server"  strict paranoid

# ======================================================= 5. FIREWALL =======

echo ""
echo "--- Firewall ---"
# Allow the port sshd ACTUALLY listens on, or enabling the firewall cuts off
# the session running this script.
SSH_PORTS=$(sshd -T 2>/dev/null | awk '$1=="port" {print $2}' | sort -un | tr '\n' ' ')
SSH_PORTS=${SSH_PORTS:-22}
if selected "HD-FW-001" baseline strict paranoid; then
  if command -v ufw >/dev/null 2>&1; then
    # NOTE: match "Status: active" exactly - "inactive" also contains "active".
    if ufw status 2>/dev/null | head -1 | grep -qiE '^status:[[:space:]]*active'; then
      say_ok "HD-FW-001" "ufw already active"
    elif [ "$DRY" = "1" ]; then
      say_would "HD-FW-001" "ufw: default deny incoming, allow ssh (${SSH_PORTS% }/tcp), enable"
    else
      printf 'ufw: was inactive (revert: ufw disable)\n' >> "$JDIR/services.txt"
      ufw --force default deny incoming  >/dev/null 2>&1
      ufw --force default allow outgoing >/dev/null 2>&1
      for _p in $SSH_PORTS; do ufw allow "$_p/tcp" >/dev/null 2>&1; done
      if ufw --force enable >/dev/null 2>&1; then
        say_set "HD-FW-001" "ufw enabled (deny incoming, SSH ${SSH_PORTS% } allowed)"
      else
        say_fail "HD-FW-001" "ufw enable failed"
      fi
    fi
  elif command -v firewall-cmd >/dev/null 2>&1; then
    if [ "$(firewall-cmd --state 2>/dev/null)" = "running" ]; then
      say_ok "HD-FW-001" "firewalld already running"
    elif [ "$DRY" = "1" ]; then
      say_would "HD-FW-001" "enable firewalld, allow ssh"
    else
      printf 'firewalld: was stopped (revert: systemctl disable --now firewalld)\n' >> "$JDIR/services.txt"
      if systemctl enable --now firewalld >/dev/null 2>&1; then
        firewall-cmd --permanent --add-service=ssh >/dev/null 2>&1
        for _p in $SSH_PORTS; do
          [ "$_p" = "22" ] || firewall-cmd --permanent --add-port="$_p/tcp" >/dev/null 2>&1
        done
        firewall-cmd --reload >/dev/null 2>&1
        say_set "HD-FW-001" "firewalld enabled (SSH ${SSH_PORTS% } allowed)"
      else
        say_fail "HD-FW-001" "firewalld enable failed"
      fi
    fi
  else
    echo "  [skip]  HD-FW-001    no ufw/firewalld present; configure nftables manually"
  fi
fi

# ===================================================== 6. AUDIT/LOGGING ====

echo ""
echo "--- Logging and audit ---"
if selected "HD-LG-001" baseline strict paranoid; then
  if [ "$HAS_SYSTEMD" = "1" ] && systemctl list-unit-files 2>/dev/null | grep -q '^auditd'; then
    if systemctl is-active --quiet auditd 2>/dev/null; then
      say_ok "HD-LG-001" "auditd running"
    elif [ "$DRY" = "1" ]; then
      say_would "HD-LG-001" "enable auditd"
    else
      systemctl enable --now auditd >/dev/null 2>&1 && say_set "HD-LG-001" "auditd enabled" \
        || say_fail "HD-LG-001" "auditd enable failed"
    fi
  else
    echo "  [skip]  HD-LG-001    auditd not installed"
  fi
fi

if selected "HD-LG-002" baseline strict paranoid; then
  if [ "$HAS_SYSTEMD" = "0" ]; then
    say_ok "HD-LG-002" "no systemd journal on this host"
  elif [ -d /var/log/journal ]; then
    say_ok "HD-LG-002" "journal already persistent"
  elif [ "$DRY" = "1" ]; then
    say_would "HD-LG-002" "make systemd journal persistent"
  else
    mkdir -p /var/log/journal 2>/dev/null && chmod 2755 /var/log/journal 2>/dev/null
    command -v systemd-tmpfiles >/dev/null 2>&1 && \
      systemd-tmpfiles --create --prefix /var/log/journal >/dev/null 2>&1
    say_set "HD-LG-002" "journal persisted to /var/log/journal"
  fi
fi

# Audit rules: minimal high-value CIS subset
if selected "HD-LG-003" strict paranoid; then
  ARULES=/etc/audit/rules.d/99-lab-hardening.rules
  if [ -f "$ARULES" ]; then
    say_ok "HD-LG-003" "audit rules present"
  elif [ ! -d /etc/audit/rules.d ]; then
    echo "  [skip]  HD-LG-003    auditd not installed"
  elif [ "$DRY" = "1" ]; then
    say_would "HD-LG-003" "install baseline audit rules"
  else
    backup_file "$ARULES"
    # File watches on a path that does not exist make auditctl reject the
    # rule (and augenrules may stop loading the rest), so emit only the
    # watches that apply to this distro.
    {
      echo "# Generated by harden.sh (HD-LG-003)"
      for _w in "/etc/passwd:wa:identity" "/etc/shadow:wa:identity" \
                "/etc/group:wa:identity" "/etc/gshadow:wa:identity" \
                "/etc/sudoers:wa:scope" "/etc/sudoers.d/:wa:scope" \
                "/var/log/lastlog:wa:logins" "/var/run/faillock/:wa:logins" \
                "/sbin/insmod:x:modules" "/sbin/rmmod:x:modules" "/sbin/modprobe:x:modules" \
                "/etc/localtime:wa:time-change" \
                "/etc/hosts:wa:system-locale" "/etc/sysconfig/network:wa:system-locale"; do
        _wp=${_w%%:*}; _rest=${_w#*:}
        [ -e "$_wp" ] && printf -- '-w %s -p %s -k %s\n' "$_wp" "${_rest%%:*}" "${_rest#*:}"
      done
      echo "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid_exec"
      echo "-a always,exit -F arch=b64 -S init_module,delete_module -k modules"
      echo "-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change"
    } > "$ARULES"
    if command -v augenrules >/dev/null 2>&1 && ! augenrules --load >/dev/null 2>&1; then
      say_fail "HD-LG-003" "audit rules written but augenrules --load failed (check $ARULES)"
    else
      say_set "HD-LG-003" "baseline audit rules installed"
    fi
  fi
fi

# ====================================================== 7. FILESYSTEM =====

echo ""
echo "--- Filesystem ---"
fix_perm() {
  _id="$1"; _path="$2"; _mode="$3"; _desc="$4"; shift 4
  selected "$_id" "$@" || return 0
  [ -e "$_path" ] || { say_ok "$_id" "$_path absent"; return 0; }
  _cur=$(stat -c '%a' "$_path" 2>/dev/null)
  [ "$_cur" = "$_mode" ] && { say_ok "$_id" "$_path already $_mode"; return 0; }
  if [ "$DRY" = "1" ]; then say_would "$_id" "chmod $_mode $_path ($_cur now)"; return 0; fi
  printf '%s\t%s\n' "$_cur" "$_path" >> "$JDIR/perms.txt"
  if chmod "$_mode" "$_path" 2>/dev/null; then say_set "$_id" "$_path -> $_mode ($_desc)"
  else say_fail "$_id" "chmod $_mode $_path"; fi
}

fix_perm "HD-FS-001" /etc/passwd 644 "world-readable, not writable" baseline strict paranoid
fix_perm "HD-FS-002" /etc/group  644 "world-readable, not writable" baseline strict paranoid
fix_perm "HD-FS-004" /etc/ssh/sshd_config 600 "root only" baseline strict paranoid

# shadow: 640 on Debian, 000 on RHEL - pick per distro
if selected "HD-FS-003" baseline strict paranoid; then
  case "$OS_ID" in
    debian|ubuntu|linuxmint) want=640 ;;
    *) want=000 ;;
  esac
  cur=$(stat -c '%a' /etc/shadow 2>/dev/null)
  if [ "$cur" = "$want" ] || [ "$cur" = "0" ] || [ "$cur" = "400" ]; then
    say_ok "HD-FS-003" "/etc/shadow mode $cur acceptable"
  elif [ "$DRY" = "1" ]; then
    say_would "HD-FS-003" "chmod $want /etc/shadow (now $cur)"
  else
    printf '%s\t%s\n' "$cur" /etc/shadow >> "$JDIR/perms.txt"
    chmod "$want" /etc/shadow 2>/dev/null && say_set "HD-FS-003" "/etc/shadow -> $want" \
      || say_fail "HD-FS-003" "chmod /etc/shadow"
  fi
fi

# Blacklist rarely-needed filesystem/network modules
if selected "HD-FS-005" strict paranoid; then
  MODF=/etc/modprobe.d/99-lab-hardening.conf
  if [ -f "$MODF" ]; then
    say_ok "HD-FS-005" "module blacklist present"
  elif [ "$DRY" = "1" ]; then
    say_would "HD-FS-005" "blacklist cramfs/freevxfs/jffs2/hfs/udf/dccp/sctp/rds/tipc"
  else
    backup_file "$MODF"
    mkdir -p /etc/modprobe.d 2>/dev/null
    for m in cramfs freevxfs jffs2 hfs hfsplus udf dccp sctp rds tipc; do
      printf 'install %s /bin/true\n' "$m" >> "$MODF"
    done
    say_set "HD-FS-005" "unused kernel modules blacklisted"
  fi
fi

# /tmp noexec via systemd mount unit
if selected "HD-FS-006" paranoid; then
  if mount | grep -E ' on /tmp ' | grep -q noexec; then
    say_ok "HD-FS-006" "/tmp already noexec"
  elif [ "$DRY" = "1" ]; then
    say_would "HD-FS-006" "mount /tmp with noexec,nosuid,nodev (tmp.mount)"
  else
    echo "  [skip]  HD-FS-006    /tmp noexec needs an fstab/tmp.mount change; do this manually"
    echo "                       (a wrong entry here can prevent boot)"
    SKIPPED=$((SKIPPED+1))
  fi
fi

# ======================================================== 8. BANNERS ======

echo ""
echo "--- Login banners ---"
if selected "HD-BN-001" baseline strict paranoid; then
  BANNER='Authorized access only. All activity is monitored and logged.'
  changed=0
  for f in /etc/issue /etc/issue.net /etc/motd; do
    cur=$(head -1 "$f" 2>/dev/null)
    [ "$cur" = "$BANNER" ] && continue
    if [ "$DRY" = "1" ]; then changed=1; continue; fi
    backup_file "$f"
    printf '%s\n' "$BANNER" > "$f" 2>/dev/null && changed=1
  done
  if [ "$DRY" = "1" ] && [ "$changed" = "1" ]; then
    say_would "HD-BN-001" "set legal login banners in /etc/issue, issue.net, motd"
  elif [ "$changed" = "1" ]; then
    say_set "HD-BN-001" "legal login banners set"
  else
    say_ok "HD-BN-001" "banners already set"
  fi
fi

# ========================================================= SUMMARY ========

echo ""
echo "===== SUMMARY ====="
if [ "$DRY" = "1" ]; then
  echo "Would change : $WOULD"
  echo "Already ok   : $NOOP"
  [ "$FAILED" -gt 0 ] && echo "Blocked      : $FAILED (see [FAIL] lines)"
  echo "Dry run complete. Nothing changed."
  echo "Re-run without --dry-run to apply."
  exit 0
fi

echo "Applied : $APPLIED"
echo "Already : $NOOP"
echo "Failed  : $FAILED"
echo "Skipped : $SKIPPED (not in profile '$PROFILE', or filtered)"
echo ""
echo "Rollback journal: $JDIR"
echo "Revert with: $0 --rollback $JDIR"
echo ""
echo "NEXT STEPS:"
echo "  1. Validate SSH in a SECOND session before closing this one:"
echo "       sshd -t && systemctl restart sshd"
echo "  2. Reboot to apply sysctl and module changes fully."
echo "  3. Re-run audit.sh to confirm."

[ "$FAILED" -gt 0 ] && exit 2
exit 0
