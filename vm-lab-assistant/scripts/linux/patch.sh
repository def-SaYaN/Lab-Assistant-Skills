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
ASSUME_YES=1
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

case "$PKG" in

  apt)
    export DEBIAN_FRONTEND=noninteractive
    echo "Refreshing package index..."
    apt-get update -qq >/dev/null 2>&1 || echo "  (index refresh had warnings)"

    LIST=$(apt-get -s upgrade 2>/dev/null | grep '^Inst ')
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
      if [ "$SECURITY_ONLY" = "1" ]; then
        # Build a security-only source list, then upgrade against it.
        grep -rhE '^deb .*security' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null \
          > /tmp/sec.list 2>/dev/null
        if [ -s /tmp/sec.list ]; then
          apt-get -o Dir::Etc::SourceList=/tmp/sec.list -o Dir::Etc::SourceParts=/dev/null \
                  -y -qq upgrade 2>&1 | tail -20
        else
          echo "  no security sources found; falling back to full upgrade"
          apt-get -y -qq upgrade 2>&1 | tail -20
        fi
        rm -f /tmp/sec.list
      else
        apt-get -y -qq upgrade 2>&1 | tail -20
      fi
      RC=$?
      INSTALLED=$((PENDING))
      apt-get -y -qq autoremove >/dev/null 2>&1
    fi
    ;;

  dnf|yum)
    echo "Checking for updates..."
    if [ "$SECURITY_ONLY" = "1" ]; then
      LIST=$($PKG -q --security check-update 2>/dev/null | grep -E '^[a-zA-Z0-9]')
    else
      LIST=$($PKG -q check-update 2>/dev/null | grep -E '^[a-zA-Z0-9]')
    fi
    PENDING=$(printf '%s' "$LIST" | grep -c . 2>/dev/null | head -1)
    PENDING=${PENDING:-0}

    echo "Pending : $PENDING"
    [ "$PENDING" -gt 0 ] && printf '%s\n' "$LIST" | awk '{print "  " $1 " -> " $2}' | head -40

    if [ "$MODE" = "install" ] && [ "$PENDING" -gt 0 ]; then
      echo ""
      echo "Installing..."
      if [ "$SECURITY_ONLY" = "1" ]; then
        $PKG -y --security upgrade 2>&1 | tail -20
      else
        $PKG -y upgrade 2>&1 | tail -20
      fi
      RC=$?
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
        zypper --non-interactive patch --category security 2>&1 | tail -20
      else
        zypper --non-interactive update 2>&1 | tail -20
      fi
      RC=$?; INSTALLED=$PENDING
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
      apk upgrade 2>&1 | tail -20; RC=$?; INSTALLED=$PENDING
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
      pacman -Su --noconfirm 2>&1 | tail -20; RC=$?; INSTALLED=$PENDING
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
  if [ -d /boot ]; then
    NEWEST=$(ls -1 /boot 2>/dev/null | grep -E '^vmlinuz-' | sed 's/^vmlinuz-//' | sort -V | tail -1)
  fi
  if [ -n "$NEWEST" ] && [ "$NEWEST" != "$RUNNING" ]; then
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
