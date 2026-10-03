#!/usr/bin/env sh
# patch.sh - Scan for and install OS package updates across distro families.
#
# Supports apt (Debian/Ubuntu), dnf/yum (RHEL/Rocky/Alma/Fedora),
# zypper (SUSE), apk (Alpine), pacman (Arch).
#
# --scan is read-only. --install requires root.
#
# Usage:
#   ./patch.sh --scan
#   ./patch.sh --install                 all available updates
#   ./patch.sh --install --security-only security updates only (apt/dnf)
#   ./patch.sh --reboot-if-needed
#
# Exit: 0 up to date / installed | 1 updates pending (scan) | 2 failure | 3 not root

set -u

MODE="scan"
SECURITY_ONLY=0
REBOOT_IF_NEEDED=0
JSON_OUT=""

while [ $# -gt 0 ]; do
  case "$1" in
    --scan)             MODE="scan"; shift ;;
    --install)          MODE="install"; shift ;;
    --security-only)    SECURITY_ONLY=1; shift ;;
    --reboot-if-needed) REBOOT_IF_NEEDED=1; shift ;;
    --json)             JSON_OUT="${2:-}"; shift 2 ;;
    -h|--help)          sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

IS_ROOT=0; [ "$(id -u)" = "0" ] && IS_ROOT=1
if [ "$MODE" = "install" ] && [ "$IS_ROOT" = "0" ]; then
  echo "patch.sh --install requires root." >&2; exit 3
fi

OS_NAME=""
[ -r /etc/os-release ] && . /etc/os-release && OS_NAME="${PRETTY_NAME:-$ID}"

PKG=""
if   command -v apt-get >/dev/null 2>&1; then PKG=apt
elif command -v dnf     >/dev/null 2>&1; then PKG=dnf
elif command -v yum     >/dev/null 2>&1; then PKG=yum
elif command -v zypper  >/dev/null 2>&1; then PKG=zypper
elif command -v apk     >/dev/null 2>&1; then PKG=apk
elif command -v pacman  >/dev/null 2>&1; then PKG=pacman
else echo "No supported package manager found." >&2; exit 2
fi

echo ""
echo "===== PACKAGE UPDATES ====="
echo "OS      : ${OS_NAME:-unknown}"
echo "Manager : $PKG"
echo "Mode    : $MODE$([ "$SECURITY_ONLY" = "1" ] && echo ' (security only)')"
echo ""

PENDING=0
INSTALLED=0
RC=0

# Run a command, keep its real exit status, show only the tail of output.
# (POSIX sh has no pipefail: `cmd | tail` would report tail's status and
# hide every failed install.)
LOG=$(mktemp "${TMPDIR:-/tmp}/labpatch.XXXXXX") || { echo "mktemp failed" >&2; exit 2; }
trap 'rm -f "$LOG" "${SECLIST:-}"' EXIT INT TERM
run_logged() {
  "$@" > "$LOG" 2>&1
  _rc=$?
  tail -20 "$LOG"
  return $_rc
}

case "$PKG" in

  apt)
    export DEBIAN_FRONTEND=noninteractive
    # Keep local config files on conffile prompts; without this an upgrade
    # that touches a modified config can hang waiting for a TTY answer.
    APT_OPTS="-y -qq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
    echo "Refreshing package index..."
    apt-get update -qq >/dev/null 2>&1 || echo "  (index refresh had warnings)"

    # --with-new-pkgs: plain `upgrade` keeps back anything that needs a new
    # dependency - notably new kernel packages - and would never report them.
    LIST=$(apt-get -s --with-new-pkgs upgrade 2>/dev/null | grep '^Inst ')
    PENDING=$(printf '%s' "$LIST" | grep -c '^Inst ' 2>/dev/null | head -1)
    PENDING=${PENDING:-0}
    SEC=$(printf '%s' "$LIST" | grep -ci security 2>/dev/null | head -1)
    SEC=${SEC:-0}

    echo "Pending : $PENDING ($SEC security)"
    if [ "$PENDING" -gt 0 ]; then
      echo ""
      printf '%s\n' "$LIST" | awk '{print "  " $2 " -> " $4}' | tr -d '()' | head -40
    fi

    if [ "$MODE" = "install" ] && [ "$PENDING" -gt 0 ]; then
      echo ""
      echo "Installing..."
      if [ "$SECURITY_ONLY" = "1" ] && command -v unattended-upgrade >/dev/null 2>&1; then
        # unattended-upgrades already knows the distro's security origins,
        # including deb822 (.sources) layouts used by Ubuntu 24.04+.
        run_logged unattended-upgrade -v; RC=$?
      elif [ "$SECURITY_ONLY" = "1" ]; then
        # Build a security-only one-line source list, then upgrade against it.
        # mktemp, never a fixed /tmp name: this runs as root.
        SECLIST=$(mktemp "${TMPDIR:-/tmp}/labsec.XXXXXX")
        grep -rhE '^deb .*security' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null > "$SECLIST"
        if [ -s "$SECLIST" ]; then
          # shellcheck disable=SC2086
          run_logged apt-get -o Dir::Etc::SourceList="$SECLIST" -o Dir::Etc::SourceParts=/dev/null \
                  $APT_OPTS --with-new-pkgs upgrade; RC=$?
        else
          echo "  no one-line security sources found (deb822 .sources layout?);"
          echo "  install unattended-upgrades for security-only. Falling back to full upgrade."
          # shellcheck disable=SC2086
          run_logged apt-get $APT_OPTS --with-new-pkgs upgrade; RC=$?
        fi
      else
        # shellcheck disable=SC2086
        run_logged apt-get $APT_OPTS --with-new-pkgs upgrade; RC=$?
      fi
      INSTALLED=$((PENDING))
      apt-get -y -qq autoremove >/dev/null 2>&1
    fi
    ;;

  dnf|yum)
    echo "Checking for updates..."
    if [ "$SECURITY_ONLY" = "1" ]; then
      LIST=$($PKG -q --security check-update 2>/dev/null | awk 'NF>=3 && $1 ~ /\./')
    else
      # Package lines only (name.arch version repo); skips headers such as
      # "Obsoleting Packages".
      LIST=$($PKG -q check-update 2>/dev/null | awk 'NF>=3 && $1 ~ /\./')
    fi
    PENDING=$(printf '%s' "$LIST" | grep -c . 2>/dev/null | head -1)
    PENDING=${PENDING:-0}

    echo "Pending : $PENDING"
    [ "$PENDING" -gt 0 ] && printf '%s\n' "$LIST" | awk '{print "  " $1 " -> " $2}' | head -40

    if [ "$MODE" = "install" ] && [ "$PENDING" -gt 0 ]; then
      echo ""
      echo "Installing..."
      if [ "$SECURITY_ONLY" = "1" ]; then
        run_logged "$PKG" -y --security upgrade; RC=$?
      else
        run_logged "$PKG" -y upgrade; RC=$?
      fi
      INSTALLED=$PENDING
    fi
    ;;

  zypper)
    zypper --non-interactive refresh >/dev/null 2>&1
    LIST=$(zypper --quiet list-updates 2>/dev/null | grep '^v ')
    PENDING=$(printf '%s' "$LIST" | grep -c '^v ' 2>/dev/null | head -1)
    PENDING=${PENDING:-0}
    echo "Pending : $PENDING"
    if [ "$MODE" = "install" ] && [ "$PENDING" -gt 0 ]; then
      if [ "$SECURITY_ONLY" = "1" ]; then
        run_logged zypper --non-interactive patch --category security; RC=$?
      else
        run_logged zypper --non-interactive update; RC=$?
      fi
      # zypper: 100-103 are informational (reboot/restart needed), not failure
      case "$RC" in 100|101|102|103) RC=0 ;; esac
      INSTALLED=$PENDING
    fi
    ;;

  apk)
    apk update >/dev/null 2>&1
    LIST=$(apk version -l '<' 2>/dev/null | tail -n +2)
    PENDING=$(printf '%s' "$LIST" | grep -c . 2>/dev/null | head -1)
    PENDING=${PENDING:-0}
    echo "Pending : $PENDING"
    [ "$PENDING" -gt 0 ] && printf '%s\n' "$LIST" | head -40
    if [ "$MODE" = "install" ] && [ "$PENDING" -gt 0 ]; then
      run_logged apk upgrade; RC=$?; INSTALLED=$PENDING
    fi
    ;;

  pacman)
    pacman -Sy >/dev/null 2>&1
    LIST=$(pacman -Qu 2>/dev/null)
    PENDING=$(printf '%s' "$LIST" | grep -c . 2>/dev/null | head -1)
    PENDING=${PENDING:-0}
    echo "Pending : $PENDING"
    [ "$PENDING" -gt 0 ] && printf '%s\n' "$LIST" | head -40
    if [ "$MODE" = "install" ] && [ "$PENDING" -gt 0 ]; then
      run_logged pacman -Su --noconfirm; RC=$?; INSTALLED=$PENDING
    fi
    ;;
esac

# ------------------------------------------------------- reboot status ----

REBOOT=0
REBOOT_WHY=""
if [ -f /var/run/reboot-required ] || [ -f /run/reboot-required ]; then
  REBOOT=1; REBOOT_WHY="reboot-required flag"
elif command -v needs-restarting >/dev/null 2>&1 && [ "$IS_ROOT" = "1" ]; then
  needs-restarting -r >/dev/null 2>&1 || { REBOOT=1; REBOOT_WHY="needs-restarting"; }
else
  # Compare running kernel against the newest installed kernel.
  RUNNING=$(uname -r)
  NEWEST=""
  for _k in /boot/vmlinuz-*; do
    [ -e "$_k" ] || continue
    _v=${_k#/boot/vmlinuz-}
    # Only versioned images: Arch names its image vmlinuz-linux, and RHEL
    # ships a vmlinuz-0-rescue-* that is never "newer".
    case "$_v" in [1-9]*) NEWEST=$(printf '%s\n%s\n' "$NEWEST" "$_v" | sort -V | tail -1) ;; esac
  done
  if [ ! -d "/lib/modules/$RUNNING" ]; then
    # Running kernel's modules were removed by an upgrade (Arch, Alpine).
    REBOOT=1; REBOOT_WHY="modules for running kernel $RUNNING are gone"
  elif [ -n "$NEWEST" ] && [ "$NEWEST" != "$RUNNING" ]; then
    REBOOT=1; REBOOT_WHY="running $RUNNING, installed $NEWEST"
  fi
fi

echo ""
echo "===== SUMMARY ====="
echo "Pending before : $PENDING"
[ "$MODE" = "install" ] && echo "Installed      : $INSTALLED"
echo "Reboot needed  : $([ "$REBOOT" = "1" ] && echo "YES ($REBOOT_WHY)" || echo no)"

if [ -n "$JSON_OUT" ]; then
  cat > "$JSON_OUT" <<EOF
{
  "host": "$(hostname 2>/dev/null)",
  "os": "${OS_NAME:-unknown}",
  "manager": "$PKG",
  "mode": "$MODE",
  "securityOnly": $([ "$SECURITY_ONLY" = "1" ] && echo true || echo false),
  "pending": $PENDING,
  "installed": $INSTALLED,
  "rebootNeeded": $([ "$REBOOT" = "1" ] && echo true || echo false),
  "timestampUtc": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
}
EOF
  echo "JSON report    : $JSON_OUT"
fi

if [ "$REBOOT" = "1" ] && [ "$REBOOT_IF_NEEDED" = "1" ] && [ "$IS_ROOT" = "1" ]; then
  echo ""
  echo "Rebooting in 60 seconds (shutdown -r +1)..."
  shutdown -r +1 "lab-assistant: post-patch reboot" 2>/dev/null || reboot
fi

if [ "$MODE" = "scan" ] && [ "$PENDING" -gt 0 ]; then exit 1; fi
[ "$RC" -ne 0 ] && exit 2
exit 0
