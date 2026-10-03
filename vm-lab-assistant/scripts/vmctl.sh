#!/usr/bin/env bash
# vmctl.sh - Host-side control wrapper for a VMware Fusion / Workstation guest.
#
# Wraps `vmrun` with the ergonomics an agent needs: no interactive prompts,
# explicit exit codes, bounded waits, and UTF-16 -> UTF-8 normalisation of
# PowerShell output.
#
# Config is read from env vars (see `vmctl.sh env`) or a .vmctl.env file in
# the current directory / script directory.
#
# Usage:  ./vmctl.sh <command> [args...]
# Help:   ./vmctl.sh help

set -o pipefail

# ---------------------------------------------------------------- config ----

_load_env_file() {
  local f
  for f in "./.vmctl.env" "$(dirname "${BASH_SOURCE[0]}")/../.vmctl.env"; do
    if [[ -f "$f" ]]; then
      # shellcheck disable=SC1090
      source "$f"
      return 0
    fi
  done
  return 0
}
_load_env_file

VMRUN="${VMRUN:-}"
if [[ -z "$VMRUN" ]]; then
  for c in \
    "/Applications/VMware Fusion.app/Contents/Public/vmrun" \
    "/usr/local/bin/vmrun" \
    "/usr/bin/vmrun" \
    "C:/Program Files (x86)/VMware/VMware Workstation/vmrun.exe"; do
    [[ -x "$c" ]] && { VMRUN="$c"; break; }
  done
fi

VMX="${VMX:-}"
GUEST_USER="${GUEST_USER:-}"
GUEST_PASS="${GUEST_PASS:-}"
VM_TYPE="${VM_TYPE:-fusion}"
# Guest paths. GUEST_TMP must be writable by GUEST_USER.
GUEST_TMP="${GUEST_TMP:-C:\\Windows\\Temp\\vmctl}"
GUEST_PS="${GUEST_PS:-C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe}"
GUEST_CMD="${GUEST_CMD:-C:\\Windows\\System32\\cmd.exe}"
# Scheduled task name used by the elevation bootstrap.
ELEV_TASK="${ELEV_TASK:-VMCTL-Elevated}"

# Transport: "auto" (detect), "vmrun" (VMware guest ops), "ssh" (Linux/remote).
TRANSPORT="${TRANSPORT:-auto}"
# SSH settings, used when TRANSPORT=ssh. SSH_HOST may be an IP or alias.
SSH_HOST="${SSH_HOST:-}"
SSH_USER="${SSH_USER:-${GUEST_USER:-}}"
SSH_PORT="${SSH_PORT:-22}"
SSH_KEY="${SSH_KEY:-}"
SSH_OPTS="${SSH_OPTS:--o StrictHostKeyChecking=accept-new -o ConnectTimeout=10}"
# Privilege escalation command inside a Linux guest.
SUDO="${SUDO:-sudo -n}"
# Guest scratch directory for Linux targets.
LINUX_TMP="${LINUX_TMP:-/tmp/vmctl}"

# Exit codes
E_OK=0; E_USAGE=2; E_CONFIG=3; E_VMRUN=4; E_GUEST=5; E_TIMEOUT=6

# ---------------------------------------------------------------- helpers ---

_err()  { printf '%s\n' "ERROR: $*" >&2; }
_info() { [[ -n "${VMCTL_QUIET:-}" ]] || printf '%s\n' "$*" >&2; }

_need_vmrun() {
  [[ -n "$VMRUN" && -x "$VMRUN" ]] || { _err "vmrun not found. Set VMRUN=/path/to/vmrun"; exit $E_CONFIG; }
}

_need_vmx() {
  [[ -n "$VMX" ]] || { _err "VMX not set. Export VMX=/path/to/vm.vmx or create .vmctl.env"; exit $E_CONFIG; }
  [[ -f "$VMX" ]] || { _err "VMX not found: $VMX"; exit $E_CONFIG; }
}

_need_creds() {
  [[ -n "$GUEST_USER" ]] || { _err "GUEST_USER not set"; exit $E_CONFIG; }
  [[ -n "$GUEST_PASS" ]] || { _err "GUEST_PASS not set"; exit $E_CONFIG; }
}

# vmrun with credentials
_vmg() {
  _need_vmrun; _need_vmx; _need_creds
  "$VMRUN" -T "$VM_TYPE" -gu "$GUEST_USER" -gp "$GUEST_PASS" "$@"
}

# vmrun without credentials (power/snapshot ops)
_vm() {
  _need_vmrun; _need_vmx
  "$VMRUN" -T "$VM_TYPE" "$@"
}

# Portable mktemp
_tmpf() { mktemp "${TMPDIR:-/tmp}/vmctl.XXXXXX"; }

# Uppercase without bash 4 parameter expansion (macOS /bin/bash is 3.2).
_upper() { printf '%s' "$1" | tr '[:lower:]' '[:upper:]'; }

# Decode guest text: strip UTF-16 BOM/nulls and CR. PowerShell redirection
# and Out-File default to UTF-16LE on Windows PowerShell 5.1.
_decode() {
  local f="$1" bom
  [[ -s "$f" ]] || return 0
  bom=$(head -c3 "$f" | od -An -tx1 | tr -s ' ' | sed 's/^ //; s/ $//')
  case "$bom" in
    'ff fe'*)        # UTF-16LE BOM
      iconv -f UTF-16LE -t UTF-8 "$f" 2>/dev/null | sed '1s/^\xef\xbb\xbf//' | tr -d '\r' ;;
    'fe ff'*)        # UTF-16BE BOM
      iconv -f UTF-16BE -t UTF-8 "$f" 2>/dev/null | tr -d '\r' ;;
    'ef bb bf')      # UTF-8 BOM
      tail -c +4 "$f" | tr -d '\r' ;;
    *)
      # Heuristic: UTF-16LE without BOM has NUL in the second byte.
      if [[ "$(head -c2 "$f" | od -An -tx1 | awk '{print $2}')" == "00" ]]; then
        iconv -f UTF-16LE -t UTF-8 "$f" 2>/dev/null | tr -d '\r'
      else
        tr -d '\r' < "$f"
      fi ;;
  esac
}

# ------------------------------------------------------------- lifecycle ----

cmd_env() {
  cat <<EOF
VMRUN=$VMRUN
VMX=$VMX
VM_TYPE=$VM_TYPE
GUEST_USER=$GUEST_USER
GUEST_PASS=$([[ -n "$GUEST_PASS" ]] && echo '<set>' || echo '<unset>')
GUEST_TMP=$GUEST_TMP
GUEST_PS=$GUEST_PS
ELEV_TASK=$ELEV_TASK
ELEV_TIMEOUT=${ELEV_TIMEOUT:-900}
SSH_HOST=${SSH_HOST:-<autodetect>}
SSH_USER=$SSH_USER
SSH_PORT=$SSH_PORT
SSH_KEY=${SSH_KEY:-<none>}
SUDO=$SUDO
LINUX_TMP=$LINUX_TMP
EOF
}

cmd_status() {
  _need_vmrun; _need_vmx
  local running tools ip
  running=$("$VMRUN" list 2>/dev/null | grep -Fxq "$VMX" && echo yes || echo no)
  tools=$(_vm checkToolsState "$VMX" 2>&1)
  ip=$(_vm getGuestIPAddress "$VMX" 2>&1 | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' || echo "-")
  printf 'running=%s\ntools=%s\nip=%s\n' "$running" "$tools" "$ip"
  [[ "$running" == yes ]] || return 1
  return 0
}

cmd_start() {
  _vm start "$VMX" "${1:-gui}" 2>&1 | grep -v '^$' || true
  cmd_wait-tools "${WAIT_SECS:-180}"
}

# Graceful stop with hard fallback. `vmrun stop soft` hangs indefinitely when
# Tools is not responding, so we background it and enforce our own deadline.
cmd_stop() {
  _need_vmrun; _need_vmx
  local deadline="${1:-90}" mode="${2:-soft}" waited=0
  ( "$VMRUN" -T "$VM_TYPE" stop "$VMX" "$mode" >/dev/null 2>&1 & ) || true
  while (( waited < deadline )); do
    sleep 3; waited=$((waited+3))
    if ! "$VMRUN" list 2>/dev/null | grep -Fxq "$VMX"; then
      _info "stopped after ${waited}s (${mode})"; return $E_OK
    fi
  done
  _info "soft stop exceeded ${deadline}s; forcing"
  "$VMRUN" -T "$VM_TYPE" stop "$VMX" hard >/dev/null 2>&1 || true
  sleep 3
  if "$VMRUN" list 2>/dev/null | grep -Fxq "$VMX"; then
    local p; p=$(pgrep -f "vmware-vmx.*$(basename "$VMX")" | head -1)
    [[ -n "$p" ]] && { kill -9 "$p" 2>/dev/null; sleep 3; }
  fi
  "$VMRUN" list 2>/dev/null | grep -Fxq "$VMX" && { _err "could not stop VM"; return $E_VMRUN; }
  return $E_OK
}

cmd_restart() { cmd_stop "${1:-90}" soft; cmd_start gui; }

cmd_wait-tools() {
  _need_vmrun; _need_vmx
  local deadline="${1:-180}" waited=0 st
  while (( waited < deadline )); do
    st=$(_vm checkToolsState "$VMX" 2>&1)
    [[ "$st" == "running" ]] && { _info "tools running after ${waited}s"; return $E_OK; }
    sleep 5; waited=$((waited+5))
  done
  _err "tools not running after ${deadline}s (last: ${st:-unknown})"
  return $E_TIMEOUT
}

cmd_snapshot()      { _vm snapshot "$VMX" "${1:?snapshot name required}"; }
cmd_snapshots()     { _vm listSnapshots "$VMX"; }
cmd_revert()        { _vm revertToSnapshot "$VMX" "${1:?snapshot name required}"; }
cmd_delete-snapshot(){ _vm deleteSnapshot "$VMX" "${1:?snapshot name required}"; }

# ------------------------------------------------------------ file + exec ---

cmd_push() {
  local src="${1:?local source required}" dst="${2:?guest dest required}"
  [[ -f "$src" ]] || { _err "no such file: $src"; return $E_USAGE; }
  _vmg CopyFileFromHostToGuest "$VMX" "$src" "$dst"
}

cmd_pull() {
  local src="${1:?guest source required}" dst="${2:?local dest required}"
  _vmg CopyFileFromGuestToHost "$VMX" "$src" "$dst"
}

cmd_mkdir-guest() {
  _vmg createDirectoryInGuest "$VMX" "${1:?guest dir required}" 2>/dev/null || true
}

cmd_exists() { _vmg fileExistsInGuest "$VMX" "${1:?guest path required}"; }
cmd_ps-list(){ _vmg listProcessesInGuest "$VMX"; }

# Run a PowerShell snippet in the guest, return stdout on host stdout.
# Non-elevated (UAC-limited token).
#
# NOTE: vmrun must launch cmd.exe, NOT powershell.exe directly. Invoking
# powershell.exe as the vmrun program fails with exit code 1 and produces no
# output on Windows 11 ARM64 / Tools 13349. Routing through `cmd /c` works
# reliably. See reference/troubleshooting.md.
cmd_ps() {
  local code="${1:?powershell code required}"
  _need_creds
  local lf rf b64
  lf=$(_tmpf); rf="${GUEST_TMP}\\out.txt"
  cmd_mkdir-guest "$GUEST_TMP" >/dev/null 2>&1
  # Remove the previous transfer file so a snippet that dies early cannot
  # hand back a stale result from an earlier call.
  _vmg deleteFileInGuest "$VMX" "$rf" >/dev/null 2>&1 || true
  # Base64 (UTF-16LE) avoids every quoting/escaping pitfall across the
  # host shell -> vmrun -> cmd -> powershell boundary.
  b64=$(printf '%s' "$code" | iconv -f UTF-8 -t UTF-16LE | base64 | tr -d '\n')
  _vmg runProgramInGuest "$VMX" -interactive "$GUEST_CMD" \
    "/c ${GUEST_PS} -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $b64 >nul 2>&1" \
    >/dev/null 2>&1
  local rc=$?
  # Caller-visible output is whatever the snippet wrote to $out.
  if _vmg CopyFileFromGuestToHost "$VMX" "$rf" "$lf" >/dev/null 2>&1; then
    _decode "$lf"
  fi
  rm -f "$lf"
  return $rc
}

# Run PowerShell and capture stdout automatically (wraps snippet so all
# pipeline output lands in the transfer file).
cmd_psout() {
  local code="${1:?powershell code required}"
  local wrapped="\$ProgressPreference='SilentlyContinue'
\$ErrorActionPreference='Continue'
New-Item -ItemType Directory -Force -Path '${GUEST_TMP}' | Out-Null
\$__o = & { $code } 2>&1 | Out-String -Width 400
\$__o | Set-Content -LiteralPath '${GUEST_TMP}\\out.txt' -Encoding UTF8"
  cmd_ps "$wrapped"
}

# Run a local .ps1 in the guest (non-elevated). Extra args are passed through.
cmd_run-script() {
  local lp="${1:?local .ps1 required}"; shift || true
  [[ -f "$lp" ]] || { _err "no such script: $lp"; return $E_USAGE; }
  local base gp lf rf
  base=$(basename "$lp"); gp="${GUEST_TMP}\\${base}"
  cmd_mkdir-guest "$GUEST_TMP" >/dev/null 2>&1
  cmd_push "$lp" "$gp" >/dev/null || { _err "push failed"; return $E_GUEST; }
  rf="${GUEST_TMP}\\run.log"; lf=$(_tmpf)
  # Use -Command "& 'script' args" rather than -File. With -File, cmd.exe
  # hands PowerShell a stray empty argument and every call fails with
  # "A positional parameter cannot be found that accepts argument ' '".
  local argstr=""
  (( $# > 0 )) && argstr=" $*"
  _vmg runProgramInGuest "$VMX" -interactive "$GUEST_CMD" \
    "/c ${GUEST_PS} -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"& '${gp}'${argstr}\" > \"$rf\" 2>&1" \
    >/dev/null 2>&1
  local rc=$?
  if _vmg CopyFileFromGuestToHost "$VMX" "$rf" "$lf" >/dev/null 2>&1; then
    _decode "$lf"
  fi
  rm -f "$lf"
  return $rc
}

# Run a local .ps1 ELEVATED via the scheduled task created by
# Enable-AgentElevation.ps1. Falls back with a clear error if absent.
cmd_run-elevated() {
  local lp="${1:?local .ps1 required}"; shift || true
  [[ -f "$lp" ]] || { _err "no such script: $lp"; return $E_USAGE; }
  local base gp lf rf argfile
  base=$(basename "$lp"); gp="${GUEST_TMP}\\${base}"
  cmd_mkdir-guest "$GUEST_TMP" >/dev/null 2>&1
  cmd_push "$lp" "$gp" >/dev/null || { _err "push failed"; return $E_GUEST; }

  # The task reads target script + args from a control file.
  argfile=$(_tmpf)
  printf '%s\r\n%s\r\n' "$gp" "$*" > "$argfile"
  cmd_push "$argfile" "${GUEST_TMP}\\task.cmdline" >/dev/null
  rm -f "$argfile"

  # Clear previous log so we do not read stale output.
  cmd_ps "Remove-Item -LiteralPath '${GUEST_TMP}\\elevated.log' -Force -EA SilentlyContinue; New-Item -ItemType Directory -Force -Path '${GUEST_TMP}' | Out-Null; '' | Set-Content '${GUEST_TMP}\\out.txt'" >/dev/null 2>&1

  local probe
  probe=$(cmd_psout "if (Get-ScheduledTask -TaskName '${ELEV_TASK}' -EA SilentlyContinue) { 'present' } else { 'absent' }" 2>/dev/null | tr -d '[:space:]')
  if [[ "$probe" != "present" ]]; then
    _err "elevation task '${ELEV_TASK}' not found in guest."
    _err "Run scripts/windows/Enable-AgentElevation.ps1 once from an elevated PowerShell inside the VM."
    return $E_GUEST
  fi

  _vmg runProgramInGuest "$VMX" -interactive 'C:\Windows\System32\schtasks.exe' \
    "/Run /TN ${ELEV_TASK}" >/dev/null 2>&1

  # Poll for the sentinel the task writes on completion.
  rf="${GUEST_TMP}\\elevated.log"; lf=$(_tmpf)
  local waited=0 deadline="${ELEV_TIMEOUT:-900}" done_marker=""
  while (( waited < deadline )); do
    sleep 5; waited=$((waited+5))
    done_marker=$(cmd_psout "if (Test-Path '${GUEST_TMP}\\elevated.done') { Get-Content '${GUEST_TMP}\\elevated.done' -Raw } else { '' }" 2>/dev/null | tr -d '[:space:]')
    [[ -n "$done_marker" ]] && break
  done
  if [[ -z "$done_marker" ]]; then
    _err "elevated run did not finish within ${deadline}s"
    _vmg CopyFileFromGuestToHost "$VMX" "$rf" "$lf" >/dev/null 2>&1 && _decode "$lf"
    rm -f "$lf"; return $E_TIMEOUT
  fi
  if _vmg CopyFileFromGuestToHost "$VMX" "$rf" "$lf" >/dev/null 2>&1; then
    _decode "$lf"
  fi
  rm -f "$lf"
  cmd_ps "Remove-Item -LiteralPath '${GUEST_TMP}\\elevated.done' -Force -EA SilentlyContinue" >/dev/null 2>&1
  # Exit code is the first line of the done marker.
  [[ "$done_marker" == "0" ]] && return $E_OK || return $E_GUEST
}

cmd_whoami() {
  cmd_psout '"{0}`nElevated={1}" -f [Security.Principal.WindowsIdentity]::GetCurrent().Name, ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)'
}

# --------------------------------------------------------- ssh transport ----

_ssh_target() {
  [[ -n "$SSH_HOST" ]] || { _err "SSH_HOST not set"; exit $E_CONFIG; }
  [[ -n "$SSH_USER" ]] || { _err "SSH_USER not set"; exit $E_CONFIG; }
  printf '%s@%s' "$SSH_USER" "$SSH_HOST"
}

# Emit ssh options. Note scp uses -P for port while ssh uses -p, so the
# port flag is supplied by the caller, not here.
_ssh_args() {
  local a=""
  [[ -n "$SSH_KEY" ]] && a="-i $SSH_KEY"
  printf '%s %s' "$a" "$SSH_OPTS"
}

# Resolve SSH_HOST from the hypervisor if not explicitly set.
_ssh_autohost() {
  [[ -n "$SSH_HOST" ]] && return 0
  if [[ -n "$VMX" && -f "$VMX" && -n "$VMRUN" ]]; then
    local ip
    ip=$("$VMRUN" -T "$VM_TYPE" getGuestIPAddress "$VMX" 2>/dev/null \
         | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
    [[ -n "$ip" ]] && { SSH_HOST="$ip"; return 0; }
  fi
  return 1
}

cmd_ssh() {
  _ssh_autohost || true
  # shellcheck disable=SC2046,SC2086
  ssh -p "$SSH_PORT" $(_ssh_args) "$(_ssh_target)" "$@"
}

cmd_lpush() {
  local src="${1:?local source required}" dst="${2:?remote dest required}"
  _ssh_autohost || true
  # shellcheck disable=SC2046,SC2086
  scp -P "$SSH_PORT" $(_ssh_args) "$src" "$(_ssh_target):$dst"
}

cmd_lpull() {
  local src="${1:?remote source required}" dst="${2:?local dest required}"
  _ssh_autohost || true
  # shellcheck disable=SC2046,SC2086
  scp -P "$SSH_PORT" $(_ssh_args) "$(_ssh_target):$src" "$dst"
}

# Run a local shell script on a Linux guest over SSH.
# Use --sudo as the first argument to run it with elevation.
cmd_lrun() {
  local use_sudo=0
  if [[ "${1:-}" == "--sudo" ]]; then use_sudo=1; shift; fi
  local lp="${1:?local script required}"; shift || true
  [[ -f "$lp" ]] || { _err "no such script: $lp"; return $E_USAGE; }
  _ssh_autohost || true

  local base rp
  base=$(basename "$lp"); rp="${LINUX_TMP}/${base}"
  # shellcheck disable=SC2046,SC2086
  ssh -p "$SSH_PORT" $(_ssh_args) "$(_ssh_target)" "mkdir -p '$LINUX_TMP'" >/dev/null 2>&1
  cmd_lpush "$lp" "$rp" >/dev/null || { _err "scp failed"; return $E_GUEST; }

  local pfx=""
  (( use_sudo )) && pfx="$SUDO "
  # shellcheck disable=SC2046,SC2086
  ssh -p "$SSH_PORT" $(_ssh_args) "$(_ssh_target)" "chmod +x '$rp' && ${pfx}sh '$rp'$(_shquote_args "$@")"
}

# Single-quote each argument for the remote shell so values containing
# spaces or metacharacters arrive intact (e.g. --json '/tmp/my report.json').
_shquote_args() {
  local a q=""
  for a in "$@"; do
    q="$q '$(printf '%s' "$a" | sed "s/'/'\\\\''/g")'"
  done
  printf '%s' "$q"
}

# Detect guest OS family. Prefers VMware Tools, falls back to SSH.
cmd_detect() {
  local os=""
  if [[ -n "$VMX" && -f "$VMX" && -n "$VMRUN" ]]; then
    os=$(grep -iE '^[[:space:]]*guestOS[[:space:]]*=' "$VMX" 2>/dev/null \
         | head -1 | sed -E 's/^[^=]*=[[:space:]]*//' | tr -d '"')
  fi
  local family="unknown"
  case "$(_upper "$os")" in
    # DARWIN must precede *WIN*, which would otherwise swallow it.
    *DARWIN*) family="macos" ;;
    *WINDOWS*|*WIN*) family="windows" ;;
    *UBUNTU*|*DEBIAN*|*CENTOS*|*RHEL*|*SUSE*|*SLES*|*LINUX*|*FEDORA*|*ORACLE*|*ROCKY*|*ALMA*) family="linux" ;;
  esac
  printf 'vmx.guestOS=%s\nfamily=%s\n' "${os:-unknown}" "$family"

  if [[ "$family" == "windows" ]]; then
    local role
    role=$(cmd_psout 'try{$cs=Get-CimInstance Win32_ComputerSystem -EA Stop; $os=Get-CimInstance Win32_OperatingSystem -EA Stop; "{0}|{1}|{2}" -f $os.Caption, $cs.DomainRole, $cs.Domain}catch{"unknown"}' 2>/dev/null | tr -d '\r' | head -1)
    [[ -n "$role" ]] && printf 'guest=%s\n' "$role"
    printf 'hint=use scripts/windows/*.ps1 via run-script / run-elevated\n'
    case "$role" in
      *'|4|'*|*'|5|'*) printf 'hint=DOMAIN CONTROLLER - also run Invoke-ADAudit.ps1\n' ;;
      *'|3|'*)         printf 'hint=domain member server - run Invoke-ADAudit.ps1 if RSAT present\n' ;;
    esac
  elif [[ "$family" == "linux" ]]; then
    printf 'hint=use scripts/linux/*.sh via lrun (set SSH_HOST/SSH_USER)\n'
    if _ssh_autohost 2>/dev/null; then
      # shellcheck disable=SC2046,SC2086
      ssh -p "$SSH_PORT" $(_ssh_args) "$(_ssh_target)" \
        '. /etc/os-release 2>/dev/null; echo "guest=${PRETTY_NAME:-unknown}"' 2>/dev/null || true
    fi
  fi
}

# ------------------------------------------------------- host-side audit ----

# Inspect the .vmx for virtualisation-layer posture. These are host-side
# settings the guest cannot see or fix.
cmd_audit-host() {
  _need_vmx
  local v; v=$(tr -d '\r' < "$VMX")
  _get() {
    printf '%s\n' "$v" \
      | grep -iE "^[[:space:]]*$1[[:space:]]*=" \
      | head -1 \
      | sed -E 's/^[^=]*=[[:space:]]*//; s/^"//; s/"[[:space:]]*$//' \
      | tr -d '"'
  }

  local fw sb tpm enc iso1 iso2 shared dnd cp hgfs c3d
  fw=$(_get 'firmware');              sb=$(_get 'uefi.secureBoot.enabled')
  tpm=$(printf '%s\n' "$v" | grep -ciE '^[[:space:]]*vtpm\.present[[:space:]]*=[[:space:]]*"TRUE"')
  enc=$(printf '%s\n' "$v" | grep -ciE '^[[:space:]]*encryption\.')
  iso1=$(_get 'sata0:0.startConnected'); iso2=$(_get 'sata1:0.startConnected')
  shared=$(_get 'sharedFolder0.present'); dnd=$(_get 'isolation.tools.dnd.disable')
  cp=$(_get 'isolation.tools.copy.disable'); hgfs=$(_get 'isolation.tools.hgfsServerSet.disable')
  c3d=$(_get 'mks.enable3d')

  printf '%-34s %s\n' "firmware"                "${fw:-bios (legacy)}"
  printf '%-34s %s\n' "uefi.secureBoot.enabled" "${sb:-FALSE}"
  printf '%-34s %s\n' "vTPM present"            "$([[ "$tpm" -gt 0 ]] && echo TRUE || echo FALSE)"
  printf '%-34s %s\n' "VM encryption"           "$([[ "$enc" -gt 0 ]] && echo TRUE || echo FALSE)"
  printf '%-34s %s\n' "cdrom sata0:0 connected" "${iso1:-n/a}"
  printf '%-34s %s\n' "cdrom sata1:0 connected" "${iso2:-n/a}"
  printf '%-34s %s\n' "shared folders"          "${shared:-FALSE}"
  printf '%-34s %s\n' "drag-and-drop disabled"  "${dnd:-FALSE}"
  printf '%-34s %s\n' "copy/paste disabled"     "${cp:-FALSE}"
  printf '%-34s %s\n' "hgfs disabled"           "${hgfs:-FALSE}"
  printf '%-34s %s\n' "3D acceleration"         "${c3d:-TRUE}"

  echo
  echo "Notes:"
  [[ "$(_upper "$sb")" == "TRUE" ]] || echo "  - Secure Boot is OFF. Enable uefi.secureBoot.enabled for a hardened build."
  [[ "$tpm" -gt 0 ]]                || echo "  - No vTPM. Fusion requires VM encryption before a vTPM can attach; BitLocker/Credential Guard need it."
  if [[ "$(_upper "$iso1")" == "TRUE" || "$(_upper "$iso2")" == "TRUE" ]]; then
    echo "  - An ISO is still connected at boot. Disconnect install media on a finished build."
  fi
  [[ "$(_upper "$dnd")" == "TRUE" ]] || echo "  - Drag-and-drop is enabled (host<->guest data path)."
  [[ "$(_upper "$cp")"  == "TRUE" ]] || echo "  - Copy/paste is enabled (host<->guest data path)."
  return $E_OK
}

# Diff two audit JSON reports (baseline vs. after). Works for Linux, Windows,
# and AD audit output. Exit 1 when any check regressed.
cmd_compare() {
  local before="${1:?baseline json required}" after="${2:?after json required}"; shift 2
  local py
  py=$(command -v python3 || command -v python) || { _err "python3 required for compare"; return $E_CONFIG; }
  "$py" "$(dirname "${BASH_SOURCE[0]}")/compare-audit.py" "$before" "$after" "$@"
}

# ------------------------------------------------------------------ help ----

cmd_help() {
  cat <<'EOF'
vmctl.sh - host-side control for a VMware guest

CONFIG (env or ./.vmctl.env):
  VMX=/path/to/vm.vmx           required
  GUEST_USER=root               required for guest ops
  GUEST_PASS=secret             required for guest ops
  VMRUN=/path/to/vmrun          auto-detected if omitted
  VM_TYPE=fusion|ws             default fusion
  GUEST_TMP=C:\Windows\Temp\vmctl
  ELEV_TASK=VMCTL-Elevated
  ELEV_TIMEOUT=900              seconds to wait for an elevated run

LIFECYCLE
  status                      running / tools / ip
  start [gui|nogui]           power on, wait for Tools
  stop [secs] [soft|hard]     graceful stop w/ hard fallback (default 90 soft)
  restart [secs]
  wait-tools [secs]           block until Tools reports running

SNAPSHOTS
  snapshot <name>
  snapshots
  revert <name>
  delete-snapshot <name>

FILES / EXEC
  push <local> <guest>
  pull <guest> <local>
  exists <guest-path>
  mkdir-guest <guest-dir>
  ps   '<powershell>'         run snippet; snippet writes $GUEST_TMP\out.txt
  psout '<powershell>'        run snippet; stdout captured automatically
  run-script <local.ps1> [args...]      non-elevated
  run-elevated <local.ps1> [args...]    via scheduled task (needs bootstrap)
  ps-list
  whoami                      guest identity + elevation state

LINUX GUESTS (SSH transport; set SSH_HOST/SSH_USER or let it autodetect)
  detect                      identify guest OS family + suggest scripts
  ssh '<cmd>'                 run a command over SSH
  lpush <local> <remote>
  lpull <remote> <local>
  lrun [--sudo] <local.sh> [args...]   copy + execute a shell script

AUDIT
  audit-host                  inspect .vmx virtualisation-layer posture
  compare <before.json> <after.json> [--all]
                              diff two audit reports; exit 1 on regressions

EXIT CODES
  0 ok | 2 usage | 3 config | 4 vmrun | 5 guest | 6 timeout
EOF
}

# ------------------------------------------------------------------ main ----

main() {
  local cmd="${1:-help}"; shift || true
  case "$cmd" in
    env|status|start|stop|restart|wait-tools|snapshot|snapshots|revert|\
    delete-snapshot|push|pull|exists|mkdir-guest|ps|psout|run-script|\
    run-elevated|ps-list|whoami|audit-host|compare|help|\
    ssh|lpush|lpull|lrun|detect)
      "cmd_${cmd}" "$@" ;;
    -h|--help) cmd_help ;;
    *) _err "unknown command: $cmd"; cmd_help; exit $E_USAGE ;;
  esac
}

main "$@"
