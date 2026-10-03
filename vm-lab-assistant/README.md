# VM Lab Assistant

A portable AI skill plus standalone scripts for controlling, auditing,
hardening, and patching lab virtual machines: **Windows 10/11, Windows
Server, Active Directory domain controllers, and Linux**.

This README is written as a **manual you can learn from and follow by hand**.
For every phase it explains:

- **what** is being done and **why** (the attack it stops, the risk it carries),
- the **scripted** way (one command),
- the **manual** way (the exact commands or clicks the script would run for
  you), so you can do it without the scripts or understand what they did,
- how to **verify** it worked, and
- how to **undo** it.

You can read it as a study guide and never run a script. You can also use the
scripts and come back here when you need to know what they did.

---

## Contents

**Part 1 - Understand**
- [1. What this toolkit does](#1-what-this-toolkit-does)
- [2. Key concepts you need first](#2-key-concepts-you-need-first)
- [3. Files in this folder](#3-files-in-this-folder)

**Part 2 - Set up**
- [4. Prerequisites](#4-prerequisites)
- [5. Install](#5-install)
- [6. Configuration (`.vmctl.env`) explained line by line](#6-configuration-vmctlenv-explained-line-by-line)
- [7. Verify you have control of the guest](#7-verify-you-have-control-of-the-guest)

**Part 3 - The workflow with scripts**
- [8. The six phases](#8-the-six-phases)
- [9. Windows client or server, scripted](#9-windows-client-or-server-scripted)
- [10. Active Directory domain controller, scripted](#10-active-directory-domain-controller-scripted)
- [11. Linux, scripted](#11-linux-scripted)
- [12. `vmctl.sh` command reference](#12-vmctlsh-command-reference)

**Part 4 - Doing everything by hand**
- [13. Manual phase 0: snapshot](#13-manual-phase-0-snapshot)
- [14. Manual phase 1: hypervisor (VMX) review](#14-manual-phase-1-hypervisor-vmx-review)
- [15. Manual Windows procedure](#15-manual-windows-procedure)
- [16. Manual Active Directory procedure](#16-manual-active-directory-procedure)
- [17. Manual Linux procedure](#17-manual-linux-procedure)
- [18. Manual verification: comparing before and after](#18-manual-verification-comparing-before-and-after)
- [19. Manual clean-up](#19-manual-clean-up)

**Part 5 - Reference**
- [Windows checks (61)](#windows-checks)
- [Active Directory checks (45+)](#active-directory-checks)
- [Linux checks (70+)](#linux-checks)
- [Hardening profiles](#hardening-profiles)
- [Rollback](#rollback)
- [Safety rules](#safety-rules)
- [Troubleshooting quick reference](#troubleshooting-quick-reference)
- [Glossary](#glossary)
- [Testing status](#testing-status)

---

# Part 1 - Understand

## 1. What this toolkit does

| Target | Audit (read-only) | Harden (changes things) | Patch | How the host reaches it |
|---|---|---|---|---|
| Windows 10/11 client | `windows/Invoke-HardeningAudit.ps1` | `windows/Invoke-Hardening.ps1` | `windows/Invoke-Patching.ps1` | VMware guest operations (`vmrun`) |
| Windows Server | same, plus server-role checks | same | same | `vmrun` |
| AD domain controller | `windows/Invoke-ADAudit.ps1` | `windows/Invoke-ADHardening.ps1` | `windows/Invoke-Patching.ps1` | `vmrun` |
| Linux (Debian/Ubuntu, RHEL/Rocky/Alma/Fedora, SUSE, Alpine, Arch) | `linux/audit.sh` | `linux/harden.sh` | `linux/patch.sh` | SSH |
| Hypervisor layer (the `.vmx` file) | `vmctl.sh audit-host` | manual VMX edits | - | read on the host |

Design rules every script follows:

1. **Audit never changes anything.** It only reads.
2. **Hardening always has a dry run** (`-WhatIf` on Windows, `--dry-run` on
   Linux) and writes a **rollback journal** before it changes anything.
3. **Scripts are standalone.** Each one runs by hand with no framework, no
   modules to install, and no internet access needed (except patching).
4. **Degrade, never crash.** A check that cannot run reports `Unknown`
   instead of aborting the whole run.
5. **Exit codes mean something:** `0` clean, `1` warnings only, `2` failures
   present. Scripts can be chained and scored.

## 2. Key concepts you need first

Read this section once. Most "why did that fail?" questions are answered here.

### 2.1 Guest, host, and the hypervisor

- The **host** is your real computer (macOS, Linux, or Windows with WSL).
- The **guest** is the operating system running inside the VM.
- The **hypervisor** (VMware Fusion or Workstation) runs the guest. Its
  settings live in a text file called the **`.vmx`**.
- **VMware Tools** is an agent installed *inside* the guest. It lets the host
  run programs and copy files in the guest **without any network** via
  `vmrun`. The Windows path in this toolkit depends on it.

### 2.2 How the host runs commands in the guest

| Guest | Mechanism | What you need |
|---|---|---|
| Windows | `vmrun -gu USER -gp PASS runProgramInGuest ...` through VMware Tools | VMware Tools running, a local account and its password |
| Linux | `ssh` / `scp` | sshd running in the guest, a user, ideally a key, and `sudo` |

`vmctl.sh` wraps both so you don't have to remember the flags. Doing it by
hand looks like this:

```bash
# Windows guest: run a command and capture output through a file
vmrun -T fusion -gu labadmin -gp 'Passw0rd!' runProgramInGuest "$VMX" \
  C:\\Windows\\System32\\cmd.exe "/c whoami > C:\\Windows\\Temp\\o.txt"
vmrun -T fusion -gu labadmin -gp 'Passw0rd!' CopyFileFromGuestToHost "$VMX" \
  'C:\Windows\Temp\o.txt' ./o.txt
iconv -f UTF-16LE -t UTF-8 o.txt 2>/dev/null || cat o.txt

# Linux guest
ssh labadmin@192.168.1.50 'id; uname -a'
```

### 2.3 UAC token filtering: why "Administrator" is not "elevated"

When a member of the Administrators group logs on to Windows, Windows creates
**two tokens**: a filtered one (standard user rights, Administrators group
marked *deny-only*) and a full one. Programs get the **filtered** token
unless you approve a UAC prompt ("Run as administrator").

Programs started through VMware Tools always get the **filtered** token, and
nobody is there to approve a prompt. So:

- Reading most settings works.
- Writing to `HKLM`, changing Defender, firewall policy, services, or
  Windows features fails with **`Access is denied`**, even though the account
  is in Administrators.

Check it yourself:

```powershell
whoami /groups | findstr /i "S-1-16-"     # Mandatory Label: Medium = filtered, High = elevated
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')
```

`vmctl.sh whoami` prints `Elevated=False` in this situation.

**The fix used here:** `Enable-AgentElevation.ps1` (run once, by you, in an
elevated window inside the guest) registers a **scheduled task** that runs as
`SYSTEM`. The host drops the script path and arguments into
`C:\Windows\Temp\vmctl\task.cmdline` and starts the task with
`schtasks /Run`. The task runs elevated, writes `elevated.log` and an exit code
to `elevated.done`, and the host reads them back. See
[15.2](#152-elevation) for how to do this by hand and what the security
trade-off is.

The **built-in** `Administrator` account (RID 500) is the exception: by
default it is *not* filtered (`FilterAdministratorToken=0`). Control
`HD-ID-003` turns filtering on for it too, so after Baseline hardening even
that account needs the elevation task.

### 2.4 Linux privilege: sudo without a terminal

Scripts run over SSH have **no terminal** to type a sudo password into.
`lrun --sudo` uses `sudo -n` (non-interactive), which fails instead of
hanging if a password is needed. For a lab, give the admin user a
passwordless rule **for the duration of the work only**:

```bash
echo 'labadmin ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/90-lab-temp
sudo chmod 440 /etc/sudoers.d/90-lab-temp
sudo visudo -c                     # ALWAYS validate sudoers
# remove when done:
sudo rm /etc/sudoers.d/90-lab-temp
```

Audit check `ID-010` flags this rule while it exists. That's intended.

### 2.5 Profiles: how much to change

| Profile | Risk | Meaning |
|---|---|---|
| `Baseline` / `baseline` | Low | Safe defaults most systems tolerate. Broadly reversible. |
| `Strict` / `strict` | Medium | Can break legacy software: LSASS protection, ASR rules, SMBv1/PSv2 removal, keys-only SSH, TLS 1.0/1.1 off. |
| `Paranoid` / `paranoid` | High | Removes remote management (WinRM, RDP), umask 077, deny all NTLM in AD. Don't apply to a machine you can reach only over the network. |

Profiles are cumulative: Strict includes everything in Baseline. **Escalate
one profile at a time and re-audit between them.**

### 2.6 Snapshots vs. rollback journals

- A **snapshot** freezes the whole VM (disk + optionally memory). Reverting
  undoes everything at once, including things you wanted to keep. It is the
  safety net.
- A **rollback journal** records the previous value of every setting the
  hardening script changed, so you can undo *just those changes*. It is the
  precise tool.

Use both: snapshot first, then rely on the journal for fine-grained undo,
and revert the snapshot if something is badly broken.

### 2.7 Control IDs

Every audit check has an ID (`ID-001`, `SSH-004`, `AD-083`...). Every
hardening control has an ID prefixed `HD-` (Windows/Linux) or `ADH-` (AD). Use
them to filter:

```bash
harden.sh --profile strict --only HD-SSH-011,HD-FW-001
Invoke-Hardening.ps1 -Profile Baseline -Skip HD-SU-004
```

## 3. Files in this folder

```
SKILL.md                             skill definition the AI assistant reads
README.md                            this manual
.vmctl.env.example                   configuration template (copy to .vmctl.env)
scripts/vmctl.sh                     host-side control wrapper (vmrun + SSH)
scripts/compare-audit.py             diff two audit JSON reports (before/after)
scripts/windows/
  Enable-AgentElevation.ps1          one-time UAC elevation bootstrap (scheduled task)
  Invoke-HardeningAudit.ps1          61 checks, read-only
  Invoke-Hardening.ps1               remediation, 3 profiles, journal + rollback
  Invoke-Patching.ps1                Windows Update + Defender signatures
  Invoke-ADAudit.ps1                 45+ Active Directory checks, read-only
  Invoke-ADHardening.ps1             AD remediation, journal + rollback
scripts/linux/
  audit.sh                           70+ CIS-aligned checks, read-only, POSIX sh
  harden.sh                          remediation, 3 profiles, journal + rollback
  patch.sh                           apt / dnf / yum / zypper / apk / pacman
reference/checklist.md               phase-by-phase runbook with tick boxes
reference/troubleshooting.md         verbatim error messages and their fixes
```

---

# Part 2 - Set up

## 4. Prerequisites

### On the host

| Need | Why | Check |
|---|---|---|
| bash 3.2+ (macOS default is fine), `iconv`, `base64`, `od` | `vmctl.sh` | `bash --version` |
| VMware Fusion or Workstation with `vmrun` | Windows guest control, snapshots | `"/Applications/VMware Fusion.app/Contents/Public/vmrun" list` |
| OpenSSH client (`ssh`, `scp`) | Linux guest control | `ssh -V` |
| Python 3 (optional) | `vmctl.sh compare` | `python3 --version` |

### In a Windows guest

| Need | Why | Check (in the guest) |
|---|---|---|
| VMware Tools installed and running | all `vmrun` guest operations | `Get-Service VMTools` shows Running |
| A local admin account with a password | `vmrun -gu/-gp` refuses blank passwords | `net user labadmin` |
| Windows PowerShell 5.1 | scripts target 5.1 | `$PSVersionTable.PSVersion` |
| For AD scripts: RSAT AD module | `Import-Module ActiveDirectory` | present by default on a DC |

### In a Linux guest

| Need | Why | Check |
|---|---|---|
| sshd running and reachable | transport | `systemctl status ssh` (Debian/Ubuntu) or `sshd` |
| A user with sudo | hardening and patching need root | `sudo -n true && echo ok` |
| An SSH key (strongly recommended) | `strict` turns password login off | `ls ~/.ssh/authorized_keys` |

## 5. Install

### As an AI skill (Claude Code, opencode)

```bash
mkdir -p ~/.claude/skills
cp -r vm-lab-assistant ~/.claude/skills/vm-lab-assistant
```

opencode also loads `~/.agents/skills/` and `.opencode/skills/`.

### For any other assistant (ChatGPT, Gemini, Cursor)

Give it `SKILL.md` (or paste it into the system prompt) and keep `scripts/`
and `reference/` next to it.

### Standalone (no AI)

Nothing to install. Copy the folder to the host and make the scripts executable:

```bash
chmod +x scripts/vmctl.sh scripts/compare-audit.py scripts/linux/*.sh
```

To use a guest script without the host wrapper, copy it into the guest
(shared folder, `scp`, USB ISO, or paste) and run it there; see Part 4.

## 6. Configuration (`.vmctl.env`) explained line by line

```bash
cp .vmctl.env.example .vmctl.env
chmod 600 .vmctl.env          # it contains a password
```

`vmctl.sh` reads `.vmctl.env` from the current directory, or from the folder
above `scripts/`. Any variable can also be exported in your shell instead.

| Variable | Example | Meaning |
|---|---|---|
| `VMX` | `"$HOME/Virtual Machines.localized/Win11.vmwarevm/Win11.vmx"` | Full path to the VM's `.vmx`. On macOS, right-click the VM bundle > Show Package Contents. **Quote it** if it has spaces. |
| `VM_TYPE` | `fusion` or `ws` | `fusion` on macOS, `ws` for Workstation on Windows/Linux. |
| `GUEST_USER` | `labadmin` | Windows account used for guest operations. |
| `GUEST_PASS` | `Passw0rd!` | Its password. Plaintext, so **throwaway lab credentials only**. |
| `VMRUN` | `/Applications/VMware Fusion.app/Contents/Public/vmrun` | Auto-detected; set it only if detection fails. |
| `GUEST_TMP` | `C:\Windows\Temp\vmctl` | Scratch folder in the guest. Must match `-GuestTmp` of `Enable-AgentElevation.ps1`. |
| `ELEV_TASK` | `VMCTL-Elevated` | Scheduled task name. Must match `-TaskName`. |
| `ELEV_TIMEOUT` | `900` | Seconds the host waits for an elevated run. **Raise to `3600` for Windows patching.** |
| `SSH_HOST` | `192.168.1.50` | Linux guest address. Leave unset to ask VMware Tools for the IP. |
| `SSH_USER` | `labadmin` | Linux user. Defaults to `GUEST_USER`. |
| `SSH_KEY` | `~/.ssh/lab_key` | Private key for SSH. |
| `SSH_PORT` | `22` | sshd port. |
| `SSH_OPTS` | `-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10` | Extra ssh options. |
| `SUDO` | `sudo -n` | How to become root in the guest. |
| `LINUX_TMP` | `/tmp/vmctl` | Where `lrun` copies scripts in the guest. |

Create an SSH key for the lab, if you don't have one:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/lab_key -C lab
ssh-copy-id -i ~/.ssh/lab_key.pub labadmin@192.168.1.50
ssh -i ~/.ssh/lab_key labadmin@192.168.1.50 'echo key login works'
```

## 7. Verify you have control of the guest

```bash
./scripts/vmctl.sh env        # resolved config; password shows as <set>
./scripts/vmctl.sh status     # running=yes, tools=running, ip=...
./scripts/vmctl.sh detect     # OS family; for Windows, whether it is a DC
./scripts/vmctl.sh whoami     # Windows: account name + Elevated=True/False
./scripts/vmctl.sh ssh 'id && sudo -n true && echo SUDO_OK'   # Linux
```

| Output | Meaning | Next step |
|---|---|---|
| `vmrun not found` | wrong or missing VMware path | set `VMRUN=` |
| `tools=` not `running` | VMware Tools missing or still starting | install Tools / `vmctl.sh wait-tools` |
| `Invalid user name or password` from vmrun | wrong creds, or a blank password | set a password on the guest account |
| `Elevated=False` | normal, see [2.3](#23-uac-token-filtering-why-administrator-is-not-elevated) | set up the elevation task (phase 3) |
| `sudo: a password is required` | no passwordless sudo | see [2.4](#24-linux-privilege-sudo-without-a-terminal) |

Full error-to-fix list: `reference/troubleshooting.md`.

---

# Part 3 - The workflow with scripts

## 8. The six phases

Same order for every target. **Don't reorder them.**

```
0. SNAPSHOT   so any mistake is one revert away
1. AUDIT      read-only baseline; save the JSON to compare against later
2. ELEVATE    Windows: elevation task | Linux: sudo
3. PATCH      before hardening, because hardening can disable what updates need
4. HARDEN     dry-run, read it, apply, reboot
5. VERIFY     re-audit, compare with the baseline, clean up
```

Why patch first? Hardening can disable services, protocols, or script hosts
that Windows Update, apt, or dnf depend on. A failed update after hardening
is much harder to diagnose than one before it.

## 9. Windows client or server, scripted

```bash
# 0. snapshot
./scripts/vmctl.sh snapshot pre-hardening

# 1. audit (non-elevated works; some checks report Unknown)
./scripts/vmctl.sh audit-host
./scripts/vmctl.sh run-script scripts/windows/Invoke-HardeningAudit.ps1 -Format Console,Json
./scripts/vmctl.sh pull 'C:\Users\labadmin\AppData\Local\Temp\vmctl\audit\audit-latest.json' ./baseline-win.json
#    (the exact path is printed on the "JSON report:" line)

# 2. elevate: ONCE, inside the guest, from "Run as administrator" PowerShell:
#      Set-ExecutionPolicy -Scope Process Bypass
#      .\Enable-AgentElevation.ps1
#    then from the host:
./scripts/vmctl.sh run-elevated scripts/windows/Invoke-HardeningAudit.ps1   # now Elevated=True

# 3. patch (raise the timeout; updates are slow)
ELEV_TIMEOUT=3600 ./scripts/vmctl.sh run-elevated scripts/windows/Invoke-Patching.ps1 -Install
./scripts/vmctl.sh restart
./scripts/vmctl.sh run-script scripts/windows/Invoke-Patching.ps1 -Scan     # repeat until 0 pending

# 4. harden: dry-run, read, apply, reboot
./scripts/vmctl.sh run-elevated scripts/windows/Invoke-Hardening.ps1 -Profile Baseline -WhatIf
./scripts/vmctl.sh run-elevated scripts/windows/Invoke-Hardening.ps1 -Profile Baseline
./scripts/vmctl.sh restart

# 5. verify
./scripts/vmctl.sh run-elevated scripts/windows/Invoke-HardeningAudit.ps1 -Format Console,Json
./scripts/vmctl.sh pull 'C:\Windows\Temp\vmctl\audit\audit-latest.json' ./after-win.json
./scripts/vmctl.sh compare baseline-win.json after-win.json
```

> When the elevated task runs as SYSTEM, `$env:TEMP` is `C:\Windows\Temp`, so
> elevated reports and journals land under `C:\Windows\Temp\vmctl\...`.
> Non-elevated runs use the user's temp folder. The scripts print the path.

## 10. Active Directory domain controller, scripted

```bash
./scripts/vmctl.sh snapshot pre-ad-hardening        # do this on EVERY DC
./scripts/vmctl.sh run-elevated scripts/windows/Invoke-ADAudit.ps1
./scripts/vmctl.sh run-elevated scripts/windows/Invoke-ADHardening.ps1 -Profile Baseline -WhatIf
./scripts/vmctl.sh run-elevated scripts/windows/Invoke-ADHardening.ps1 -Profile Baseline
./scripts/vmctl.sh restart
./scripts/vmctl.sh run-elevated scripts/windows/Invoke-ADAudit.ps1
```

> AD changes are **forest-wide**. Snapshot all DCs, apply on one, wait for
> replication (`repadmin /replsummary` shows 0 failures), then continue.
> Also run the Windows procedure above on each DC; it covers the host OS.

## 11. Linux, scripted

```bash
./scripts/vmctl.sh snapshot pre-hardening
./scripts/vmctl.sh lrun --sudo scripts/linux/audit.sh --json /tmp/baseline.json
./scripts/vmctl.sh lpull /tmp/baseline.json ./baseline-linux.json

./scripts/vmctl.sh lrun --sudo scripts/linux/patch.sh --install
./scripts/vmctl.sh ssh 'sudo reboot'          # if it reports "Reboot needed : YES"

./scripts/vmctl.sh lrun --sudo scripts/linux/harden.sh --dry-run --profile baseline
./scripts/vmctl.sh lrun --sudo scripts/linux/harden.sh --profile baseline
#   >>> open a SECOND ssh session now and confirm you can still log in <<<
./scripts/vmctl.sh ssh 'sudo sshd -t && sudo systemctl restart ssh || sudo systemctl restart sshd'

./scripts/vmctl.sh lrun --sudo scripts/linux/audit.sh --json /tmp/after.json
./scripts/vmctl.sh lpull /tmp/after.json ./after-linux.json
./scripts/vmctl.sh compare baseline-linux.json after-linux.json
```

Or directly on the box, without the host wrapper:

```bash
sudo sh audit.sh --json /tmp/audit.json
sudo sh patch.sh --scan            # exit 1 = updates pending
sudo sh patch.sh --install
sudo sh harden.sh --dry-run --profile baseline
sudo sh harden.sh --profile baseline
sudo sh harden.sh --rollback /var/backups/lab-harden/<stamp>
```

What `harden.sh` does to protect you:

- **sshd drop-in:** if `sshd_config` has `Include /etc/ssh/sshd_config.d/*.conf`
  (Ubuntu 22.04+, Debian 12+, RHEL 9+), settings go to
  `/etc/ssh/sshd_config.d/00-lab-hardening.conf`. sshd keeps the **first**
  value it reads, so `00-` beats a cloud-init `50-cloud-init.conf` that turns
  passwords back on. Otherwise, settings are inserted *above* the first
  `Match` block, because anything below `Match` only applies to that match.
- **`sshd -t` + `sshd -T`:** syntax is validated, and the *effective* values
  are compared with what was intended. A setting overridden elsewhere is a
  `[FAIL]`.
- **Keys-only lockout guard:** `HD-SSH-011` (`PasswordAuthentication no`) is
  refused when no `authorized_keys` exists for root or any `/home/*` user,
  unless you pass `--yes`.
- **Firewall keeps your session:** ufw/firewalld allow the port sshd actually
  listens on (from `sshd -T`), not just 22.

## 12. `vmctl.sh` command reference

| Command | Purpose |
|---|---|
| `env` | show resolved configuration (password masked) |
| `status` | running / Tools state / IP |
| `detect` | identify guest OS family, DC role; suggest scripts |
| `start [gui\|nogui]` | power on and wait for Tools |
| `stop [secs] [soft\|hard]` | graceful stop with your own deadline, then hard stop |
| `restart [secs]` | stop then start |
| `wait-tools [secs]` | block until Tools responds |
| `snapshot <name>` / `snapshots` / `revert <name>` / `delete-snapshot <name>` | snapshot management |
| `push <local> <guest>` / `pull <guest> <local>` | copy files to/from a Windows guest |
| `exists <path>` / `mkdir-guest <dir>` / `ps-list` | guest filesystem and processes |
| `ps '<code>'` / `psout '<code>'` | run PowerShell in the guest; `psout` returns its output |
| `run-script <ps1> [args]` | run a local `.ps1` in the guest, non-elevated |
| `run-elevated <ps1> [args]` | run a local `.ps1` elevated via the scheduled task |
| `whoami` | guest identity and elevation state |
| `ssh '<cmd>'` | run a command on a Linux guest |
| `lpush` / `lpull` | copy files over SSH |
| `lrun [--sudo] <sh> [args]` | copy a shell script to the guest and run it (args are quoted safely) |
| `audit-host` | inspect the `.vmx` for hypervisor-layer issues |
| `compare <before.json> <after.json> [--all]` | diff two audit reports; exit 1 on any regression |

Exit codes: `0` ok, `2` usage, `3` config, `4` vmrun, `5` guest, `6` timeout.

---

# Part 4 - Doing everything by hand

Everything below can be done without any script from this toolkit. Commands
are what the scripts run, in the same order, with the backup step first and
the undo step after.

**Conventions:** `PS>` means elevated Windows PowerShell inside the guest
("Run as administrator"). `$` means a Linux shell in the guest (use `sudo`
where shown). `host$` means your host terminal.

## 13. Manual phase 0: snapshot

**GUI:** VMware Fusion > Virtual Machine > Snapshots > Take Snapshot. Name it
`pre-hardening`. Workstation: VM > Snapshot > Take Snapshot.

**Command line:**

```bash
host$ vmrun -T fusion snapshot "$VMX" pre-hardening
host$ vmrun -T fusion listSnapshots "$VMX"
host$ vmrun -T fusion revertToSnapshot "$VMX" pre-hardening    # undo everything
host$ vmrun -T fusion deleteSnapshot "$VMX" pre-hardening      # when you're happy
```

A snapshot taken with the VM powered off is smaller and more reliable. For a
domain, snapshot **every** DC at the same time. Reverting one DC on its own
can cause USN rollback on older Windows versions.

## 14. Manual phase 1: hypervisor (VMX) review

Shut the VM down before editing the `.vmx`; Fusion rewrites it on exit.

```bash
host$ grep -iE 'firmware|secureBoot|vtpm|encryption|startConnected|sharedFolder|isolation\.tools|enable3d' "$VMX"
```

| Key | Hardened value | Why |
|---|---|---|
| `firmware` | `"efi"` | Needed for Secure Boot. |
| `uefi.secureBoot.enabled` | `"TRUE"` | Blocks unsigned bootloaders/bootkits. |
| `vtpm.present` | `"TRUE"` | BitLocker, Credential Guard, Windows 11. On Fusion it needs VM encryption first (Settings > Encryption). |
| `sata0:0.startConnected` (CD-ROM) | `"FALSE"` | Detach install media on a finished build. |
| `sharedFolder0.present` | `"FALSE"` | Shared folders are a host-to-guest data path. |
| `isolation.tools.dnd.disable` | `"TRUE"` | Drag-and-drop off. |
| `isolation.tools.copy.disable` / `paste.disable` | `"TRUE"` | Clipboard off. |
| `isolation.tools.hgfsServerSet.disable` | `"TRUE"` | HGFS (shared folder) server off. |

After editing, **re-read the file**: Fusion silently drops keys it doesn't
like (see `reference/troubleshooting.md`). Turning off copy/paste and shared
folders makes your own lab work harder, so decide per VM.

## 15. Manual Windows procedure

### 15.1 Manual audit

Open **PowerShell as administrator** in the guest. Each block shows the
current state of one area. Compare with the "Windows checks" tables in
Part 5.

```powershell
# Identity / UAC
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' |
  Select-Object EnableLUA, ConsentPromptBehaviorAdmin, FilterAdministratorToken, LocalAccountTokenFilterPolicy, InactivityTimeoutSecs
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' |
  Select-Object LimitBlankPasswordUse, RestrictAnonymous, RestrictAnonymousSAM, RunAsPPL, LmCompatibilityLevel
net accounts                                  # password + lockout policy
Get-LocalUser | Select-Object Name, Enabled, PasswordRequired, LastLogon
Get-LocalGroupMember Administrators

# Defender
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, BehaviorMonitorEnabled, AntivirusSignatureAge, IsTamperProtected
Get-MpPreference | Select-Object PUAProtection, MAPSReporting, CloudBlockLevel, EnableNetworkProtection, EnableControlledFolderAccess
(Get-MpPreference).AttackSurfaceReductionRules_Ids.Count

# Firewall
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogBlocked

# Attack surface
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol, MicrosoftWindowsPowerShellV2Root | Select-Object FeatureName, State
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, RequireSecuritySignature
Get-Service RemoteRegistry, SSDPSRV, upnphost, Spooler, WinRM, TermService -ErrorAction SilentlyContinue |
  Select-Object Name, Status, StartType

# Logging
auditpol /get /category:*
Get-WinEvent -ListLog Security, System, Application | Select-Object LogName, MaximumSizeInBytes

# Encryption / boot
Confirm-SecureBootUEFI
Get-BitLockerVolume -MountPoint C: | Select-Object VolumeStatus, ProtectionStatus
Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard |
  Select-Object VirtualizationBasedSecurityStatus, SecurityServicesRunning

# Patching
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5
```

Save the output to a file (`... | Out-File C:\baseline.txt`). That's your
baseline.

### 15.2 Elevation

**Option A: work interactively.** Do everything in this Part from an
elevated PowerShell window inside the VM. No elevation task needed, and
nothing persistent is created. This is the simplest manual route.

**Option B: build the elevation task by hand** (what
`Enable-AgentElevation.ps1` does), so the host can trigger elevated runs:

```powershell
PS> $dir = 'C:\Windows\Temp\vmctl'
PS> New-Item -ItemType Directory -Force $dir | Out-Null
# Lock the folder down: whoever can write task.cmdline gets SYSTEM.
PS> icacls $dir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "$env:USERDOMAIN\labadmin:(OI)(CI)M"
#   ^ labadmin = the GUEST_USER the host uses. It needs its own grant because
#     its filtered token has Administrators as deny-only.
PS> Copy-Item .\elevated-runner.ps1 $dir     # the runner text is inside Enable-AgentElevation.ps1
PS> $a = New-ScheduledTaskAction -Execute powershell.exe -Argument "-NoProfile -ExecutionPolicy Bypass -File $dir\elevated-runner.ps1"
PS> $p = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
PS> Register-ScheduledTask -TaskName VMCTL-Elevated -Action $a -Principal $p
```

Trigger it from the host:

```bash
host$ printf 'C:\\Windows\\Temp\\vmctl\\Invoke-HardeningAudit.ps1\r\n-Format Console\r\n' > task.cmdline
host$ vmrun -T fusion -gu labadmin -gp 'Passw0rd!' CopyFileFromHostToGuest "$VMX" task.cmdline 'C:\Windows\Temp\vmctl\task.cmdline'
host$ vmrun -T fusion -gu labadmin -gp 'Passw0rd!' runProgramInGuest "$VMX" C:\\Windows\\System32\\schtasks.exe "/Run /TN VMCTL-Elevated"
# wait for C:\Windows\Temp\vmctl\elevated.done to appear, then pull elevated.log
```

**Security trade-off:** this is a deliberate, persistent privilege-escalation
path. Remove it when you're done ([19](#19-manual-clean-up)).

**Option C (not recommended): disable UAC** with `EnableLUA=0` and reboot.
Every admin process then runs fully privileged with no prompt.

### 15.3 Manual patching

**GUI:** Settings > Windows Update > Check for updates. Install, reboot,
repeat until nothing is offered. Then Windows Security > Virus & threat
protection > Protection updates > Check for updates.

**Command line:**

```powershell
# Defender signatures first (fast, independent of Windows Update)
PS> Update-MpSignature
PS> & "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -SignatureUpdate   # fallback

# List pending updates via the Windows Update API (what Invoke-Patching.ps1 -Scan does)
PS> $s = New-Object -ComObject Microsoft.Update.Session
PS> $r = $s.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
PS> $r.Updates | Select-Object Title, MsrcSeverity

# Trigger a scan/download/install through the built-in orchestrator (Win10/11)
PS> UsoClient StartInteractiveScan

# Is a reboot pending?
PS> Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
PS> Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
```

If the search fails, check that `wuauserv` isn't disabled
(`Get-Service wuauserv`), that the guest has a network route, and, behind a
TLS-inspecting proxy, that the proxy's root CA is in
`Cert:\LocalMachine\Root`.

### 15.4 Back up before you change anything

The scripts journal every value. By hand, export the keys you'll touch so
you can re-import them:

```powershell
PS> mkdir C:\hardening-backup
PS> reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" C:\hardening-backup\uac.reg /y
PS> reg export "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"                    C:\hardening-backup\lsa.reg /y
PS> reg export "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders"      C:\hardening-backup\secproviders.reg /y
PS> reg export "HKLM\SOFTWARE\Policies"                                       C:\hardening-backup\policies.reg /y
PS> reg export "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"     C:\hardening-backup\tcpip.reg /y
PS> reg export "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server"        C:\hardening-backup\rdp.reg /y
PS> auditpol /backup /file:C:\hardening-backup\auditpol.csv
PS> net accounts > C:\hardening-backup\net-accounts.txt
PS> Get-Service | Select-Object Name, StartType, Status | Export-Csv C:\hardening-backup\services.csv -NoTypeInformation
PS> Get-NetFirewallProfile | Export-Clixml C:\hardening-backup\fwprofiles.xml
```

Undo any registry change later with `reg import C:\hardening-backup\<file>.reg`.
Note that import adds and overwrites values but does **not delete** values
that didn't exist before. Delete those with `Remove-ItemProperty`.

### 15.5 Manual hardening, control by control

A helper so each registry control is one line:

```powershell
PS> function Set-Reg($Path, $Name, $Value, $Type = 'DWord') {
      if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
      New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    }
PS> $sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
PS> $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
```

#### Identity and authentication

| ID | Profile | Do it | Undo |
|---|---|---|---|
| HD-ID-001 | B | `Set-Reg $sys EnableLUA 1` (UAC on, needs reboot) | restore from `uac.reg` |
| HD-ID-002 | B | `Set-Reg $sys ConsentPromptBehaviorAdmin 2` (prompt on secure desktop) | default is `5` |
| HD-ID-003 | B | `Set-Reg $sys FilterAdministratorToken 1` | `0` |
| HD-ID-004 | B | `Set-Reg $sys InactivityTimeoutSecs 900` | `Remove-ItemProperty $sys InactivityTimeoutSecs` |
| HD-ID-005 | B | `Set-Reg $lsa LimitBlankPasswordUse 1` | `0` |
| HD-ID-006 | B | `Set-Reg $lsa RestrictAnonymous 1` | `0` |
| HD-ID-007 | B | `Set-Reg $lsa RestrictAnonymousSAM 1` | `0` |
| HD-ID-008 | S | `Set-Reg $lsa RunAsPPL 1` (reboot). LSASS becomes a protected process, so Mimikatz-style dumping fails. Some old AV/credential providers break. | `Remove-ItemProperty $lsa RunAsPPL` + reboot. On UEFI with Secure Boot it can be stored in a UEFI variable; see Microsoft's "Configure added LSA protection" to remove. |
| HD-ID-009 | B | `Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' UseLogonCredential 0` | remove the value |
| HD-ID-010 | B | `net accounts /minpwlen:14 /uniquepw:5 /maxpwage:90` | values in `net-accounts.txt` |
| HD-ID-011 | B | `net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15` | `net accounts /lockoutthreshold:0` |
| HD-ID-012 | B | `Disable-LocalUser Guest` | `Enable-LocalUser Guest` |

#### Microsoft Defender

| ID | Profile | Do it | Undo |
|---|---|---|---|
| HD-DEF-001 | B | `Set-MpPreference -DisableRealtimeMonitoring $false` | `$true` |
| HD-DEF-002 | B | `Set-MpPreference -DisableBehaviorMonitoring $false` | `$true` |
| HD-DEF-003 | B | `Set-MpPreference -DisableScriptScanning $false -DisableIOAVProtection $false` | `$true` |
| HD-DEF-004 | B | `Set-MpPreference -PUAProtection Enabled` | `Disabled` |
| HD-DEF-005 | B | `Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples -CloudBlockLevel High -CloudExtendedTimeout 50` | `-CloudBlockLevel Default` |
| HD-DEF-006 | S | `Set-MpPreference -EnableNetworkProtection Enabled` | `Disabled` |
| HD-DEF-007 | P | `Set-MpPreference -EnableControlledFolderAccess Enabled` (can block legitimate apps writing to Documents) | `Disabled` |
| HD-DEF-008 | S | ASR rules in block mode; the full list of GUIDs is under "ASR rules applied by `-Profile Strict`" in Part 5. `Add-MpPreference -AttackSurfaceReductionRules_Ids <guid> -AttackSurfaceReductionRules_Actions Enabled` | `Remove-MpPreference -AttackSurfaceReductionRules_Ids <guid>`, or set the action to `AuditMode` to observe first |

If **Tamper Protection** is on, some `Set-MpPreference` changes are silently
ignored. Check with `(Get-MpComputerStatus).IsTamperProtected`. Toggle it
in Windows Security > Virus & threat protection settings.

#### Firewall

```powershell
PS> Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow   # HD-FW-001 (B)
PS> Set-NetFirewallProfile -All -LogBlocked True -LogMaxSizeKilobytes 16384 `
      -LogFileName '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'                               # HD-FW-002 (B)
PS> Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' |
      Where-Object { $_.Profile -match 'Public' } | Disable-NetFirewallRule                              # HD-FW-003 (S)
```

`DefaultInboundAction Block` still allows inbound traffic that matches an
**allow rule** (RDP, WinRM, if enabled). VMware Tools uses VMCI, not the
network, so guest operations keep working. Undo:
`Set-NetFirewallProfile -All -DefaultInboundAction NotConfigured`.

#### Attack surface

| ID | Profile | Do it | Why |
|---|---|---|---|
| HD-SU-001 | B | `Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' EnableMulticast 0` | LLMNR poisoning (Responder) |
| HD-SU-002 | B | `Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' NoDriveTypeAutoRun 255` | AutoRun malware |
| HD-SU-003 | B | `Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' NoAutorun 1` | AutoRun commands |
| HD-SU-004 | B | NetBIOS over TCP/IP off: `Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' \| % { Set-ItemProperty $_.PSPath NetbiosOptions 2 }` (undo: `0` = DHCP default) | NBT-NS poisoning |
| HD-SU-005 | B | `Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force; Set-SmbClientConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force` | NTLM relay over SMB |
| HD-SU-006 | S | `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart` (undo: `Enable-...`) | EternalBlue/WannaCry class |
| HD-SU-007 | S | `Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart` | PSv2 bypasses AMSI and logging |
| HD-SU-008 | S | `Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' Enabled 0` | .vbs/.js droppers |
| HD-SU-009 | B | `Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' UserAuthentication 1` | RDP requires NLA |
| HD-SU-010 | B | `Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' MinEncryptionLevel 3` | RDP high encryption |

#### Services

```powershell
PS> foreach ($s in 'RemoteRegistry','SSDPSRV','upnphost') {                  # Baseline
      Stop-Service $s -Force -ErrorAction SilentlyContinue; Set-Service $s -StartupType Disabled }
PS> foreach ($s in 'Spooler','SharedAccess','RemoteAccess') { ... same ... } # Strict
PS> foreach ($s in 'WinRM','TermService') { ... same ... }                   # Paranoid: removes RDP + WinRM!
```

Undo: `Set-Service <name> -StartupType Manual` (or `Automatic`; check
`services.csv` from 15.4), then `Start-Service <name>`. The scripted rollback
does this for you from the journal.

#### Logging and audit

```powershell
PS> Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' EnableScriptBlockLogging 1   # HD-LOG-001
PS> Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' EnableModuleLogging 1             # HD-LOG-002
PS> Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' '*' '*' String        # HD-LOG-003
PS> Set-Reg "$sys\Audit" ProcessCreationIncludeCmdLine_Enabled 1                                                    # HD-LOG-004
# HD-LOG-005: audit policy (back up first: auditpol /backup /file:C:\hardening-backup\auditpol.csv)
PS> 'Process Creation','Special Logon','Logoff' | % { auditpol /set /subcategory:"$_" /success:enable /failure:disable }
PS> 'Logon','Account Lockout','Security Group Management','User Account Management','Audit Policy Change',
    'Authentication Policy Change','Sensitive Privilege Use','Security System Extension','System Integrity' |
    % { auditpol /set /subcategory:"$_" /success:enable /failure:enable }
# HD-LOG-006: bigger logs (192 MB)
PS> 'Security','System','Application' | % { wevtutil sl $_ /ms:201326592 }
```

Undo the audit policy: `auditpol /restore /file:C:\hardening-backup\auditpol.csv`.
Where to look afterwards: Event Viewer > Applications and Services Logs >
Microsoft > Windows > PowerShell > Operational (event 4104), and Security
log events 4688, 4624, 4625, 4740.

> Subcategory names in `auditpol` are **localized**. On a non-English Windows,
> use the GUIDs from `auditpol /list /subcategory:* /v`.

#### Network and TLS

```powershell
# HD-NET-001..010 (Strict): SSL 2.0/3.0, TLS 1.0/1.1 off; TLS 1.2 on, for Server and Client
PS> $sc = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
PS> foreach ($p in 'SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1') { foreach ($r in 'Server','Client') { Set-Reg "$sc\$p\$r" Enabled 0 } }
PS> foreach ($r in 'Server','Client') { Set-Reg "$sc\TLS 1.2\$r" Enabled 1 }
PS> Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' AllowInsecureGuestAuth 0  # HD-NET-100 (B)
PS> Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' NC_AllowNetBridge_NLA 0           # HD-NET-101 (S)
PS> Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' DisableIPSourceRouting 2              # HD-NET-102 (B)
PS> Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' EnableICMPRedirect 0                  # HD-NET-103 (B)
```

Disabling TLS 1.0/1.1 breaks old clients and old SQL Server/.NET apps that
don't negotiate TLS 1.2. Test what talks to the box first.

### 15.6 Reboot and verify

```powershell
PS> Restart-Computer
```

Settings that **need a reboot**: `EnableLUA`, `RunAsPPL`, SMBv1/PSv2 feature
removal, SCHANNEL/TLS. Verify after the reboot by re-running the block from
15.1, and spot-check:

```powershell
PS> Get-Process lsass | Select-Object Name, Id    # then try: procdump -ma lsass -> should fail with RunAsPPL
PS> Get-WinEvent -FilterHashtable @{LogName='System'; Id=12} -MaxEvents 1   # LSA protection startup event
PS> Resolve-DnsName -LlmnrOnly nonexistent-host   # should fail fast with LLMNR off
```

## 16. Manual Active Directory procedure

Run in an elevated PowerShell **on a DC** (or a member with RSAT) as a
Domain Admin. `Import-Module ActiveDirectory` first.

### 16.1 Back up

1. Snapshot **every** DC (VM powered off is best).
2. Export what you'll change:

```powershell
PS> $d = Get-ADDomain
PS> Get-ADObject $d.DistinguishedName -Properties ms-DS-MachineAccountQuota | Select-Object ms-DS-MachineAccountQuota
PS> Get-ADDefaultDomainPasswordPolicy | Export-Clixml C:\ad-backup\pwpolicy.xml
PS> 'Domain Admins','Account Operators','Server Operators','Print Operators' |
      % { Get-ADGroupMember $_ -Recursive | Select-Object @{n='Group';e={$_}}, SamAccountName } |
      Export-Csv C:\ad-backup\groups.csv -NoTypeInformation
PS> Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Select SamAccountName | Export-Csv C:\ad-backup\nopreauth.csv
PS> Get-ADComputer -Filter {TrustedForDelegation -eq $true} | Select Name | Export-Csv C:\ad-backup\unconstrained.csv
PS> reg export HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters C:\ad-backup\ntds.reg /y
PS> auditpol /backup /file:C:\ad-backup\auditpol.csv
```

### 16.2 Manual audit (the highest-value checks)

```powershell
PS> Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties ServicePrincipalName, PasswordLastSet |
      Select SamAccountName, PasswordLastSet                          # kerberoastable accounts
PS> Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}              # AS-REP roastable
PS> Get-ADComputer -Filter {TrustedForDelegation -eq $true}           # unconstrained delegation
PS> Get-ADUser krbtgt -Properties PasswordLastSet                     # should be < 180 days
PS> Get-ADGroupMember 'Domain Admins' -Recursive
PS> Get-ADOptionalFeature -Filter * | Select Name, EnabledScopes       # Recycle Bin
PS> Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters |
      Select LDAPServerIntegrity, LdapEnforceChannelBinding
PS> Get-Service Spooler
PS> repadmin /replsummary
PS> dcdiag /q
```

AD CS (ESC1-ESC4) needs `certutil -v -template` or a tool such as Certify or
Certipy, and judgement about who legitimately enrols. Those findings are
reported, never auto-fixed.

### 16.3 Manual hardening, control by control

| ID | Profile | Do it | Undo / risk |
|---|---|---|---|
| ADH-001 | B | `Set-ADObject (Get-ADDomain).DistinguishedName -Replace @{'ms-DS-MachineAccountQuota'=0}` | Default is `10`. With 0, ordinary users can no longer join computers to the domain (blocks RBCD abuse). |
| ADH-002 | B | `Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target (Get-ADForest).Name` | **Irreversible.** Safe and recommended. |
| ADH-003 | B | `Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DNSRoot -MinPasswordLength 14 -PasswordHistoryCount 24 -ComplexityEnabled $true -LockoutThreshold 5 -LockoutDuration 00:15:00 -LockoutObservationWindow 00:15:00 -ReversibleEncryptionEnabled $false` | Restore values from `pwpolicy.xml`. |
| ADH-010 | B | `Get-ADGroupMember 'Domain Admins' -Recursive \| ? objectClass -eq user \| % { Set-ADUser $_ -AccountNotDelegated $true }` | `-AccountNotDelegated $false` |
| ADH-011 | S | Remove all members of Account/Server/Print Operators: `Remove-ADGroupMember '<group>' -Members <user> -Confirm:$false` | re-add from `groups.csv` |
| ADH-012 | B | `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true -and Enabled -eq $true} \| Set-ADAccountControl -DoesNotRequirePreAuth $false` | from `nopreauth.csv` |
| ADH-013 | B | `Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq $true} \| Set-ADUser -AllowReversiblePasswordEncryption $false` | |
| ADH-014 | S | For each non-DC in `unconstrained.csv`: `Set-ADAccountControl <computer> -TrustedForDelegation $false` | Breaks apps that rely on unconstrained delegation; move them to constrained/RBCD. |

DC-local settings (run on **each** DC):

| ID | Profile | Do it | Risk |
|---|---|---|---|
| ADH-020 | B | `Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' LDAPServerIntegrity 2` | Rejects unsigned simple binds. Check Directory Service event 2889 first to find clients that would break. |
| ADH-021 | B | `... LdapEnforceChannelBinding 1` (when supported) | Low: only clients that send channel-binding tokens are checked. |
| ADH-028 | S | `... LdapEnforceChannelBinding 2` (always) | Rejects LDAPS clients without CBT support. |
| ADH-022 | B | `Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled` | A DC almost never needs to print. Blocks the PrinterBug coercion. |
| ADH-023 | B | `Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' AuditReceivingNTLMTraffic 2` | Audit only. Read Applications and Services > Microsoft > Windows > NTLM > Operational. |
| ADH-024 | P | `... RestrictNTLMInDomain 7` | **Denies all NTLM.** Only after weeks of auditing show nothing breaks. |
| ADH-025 | S | `Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' RunAsPPL 1` + reboot | as HD-ID-008 |
| ADH-026 | B | `Set-SmbServerConfiguration -RequireSecuritySignature $true -Force` | |
| ADH-027 | S | `Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' SupportedEncryptionTypes 24` | AES only. **Rotate `krbtgt` twice and any old service-account passwords first**, or accounts without AES keys can't get tickets. |
| ADH-030 | B | `auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable`, and the same for Directory Service Access, Kerberos Authentication Service, Kerberos Service Ticket Operations, Credential Validation, Security Group / User Account / Computer Account Management, Logon, Account Lockout; Process Creation success only | `auditpol /restore /file:C:\ad-backup\auditpol.csv` |
| ADH-031 | B | `wevtutil sl Security /ms:1073741824` (1 GB) | |

Production domains normally set these through **Group Policy** (Default
Domain Controllers Policy) rather than direct registry writes, so they stay
consistent and can't drift. In a lab, direct writes are fine.

### 16.4 Replication and verification

```powershell
PS> repadmin /syncall /AdeP          # push changes now
PS> repadmin /replsummary            # 0 fails before you touch the next DC
PS> dcdiag /q                        # no output = healthy
PS> Restart-Computer                 # LSASS PPL, LDAP signing, Kerberos enc types
```

## 17. Manual Linux procedure

All commands run as root (`sudo -i`) in the guest. Keep **two SSH sessions
open** the whole time.

### 17.1 Manual audit

```bash
$ . /etc/os-release; echo "$PRETTY_NAME"; uname -r
# Identity
$ awk -F: '($2 == "") {print $1}' /etc/shadow           # empty passwords (ID-001)
$ awk -F: '($3 == 0) {print $1}' /etc/passwd            # UID 0 accounts (ID-002)
$ grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|UMASK)' /etc/login.defs
$ grep -rE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/
# SSH: the EFFECTIVE config (includes drop-ins and defaults)
$ sshd -T | grep -E '^(permitrootlogin|passwordauthentication|permitemptypasswords|x11forwarding|maxauthtries|clientalive|logingracetime|hostbased|ignorerhosts|permituserenvironment|allowtcpforwarding|loglevel) '
$ ls -l /etc/ssh/ssh_host_*_key
# Kernel
$ sysctl net.ipv4.ip_forward net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects \
         net.ipv4.conf.all.rp_filter kernel.randomize_va_space kernel.kptr_restrict kernel.yama.ptrace_scope
# Filesystem
$ stat -c '%a %n' /etc/passwd /etc/group /etc/shadow /etc/ssh/sshd_config
$ find / -xdev -type f -perm -0002 -not -path '/proc/*' -not -path '/tmp/*' 2>/dev/null | head
$ find / -xdev -type f -perm -4000 2>/dev/null | wc -l
$ findmnt /tmp
# Services, network, firewall
$ systemctl list-units --type=service --state=running
$ ss -lntup
$ ufw status verbose || firewall-cmd --list-all || nft list ruleset
# Logging, MAC
$ systemctl is-active auditd rsyslog systemd-journald; auditctl -l | head
$ getenforce 2>/dev/null || aa-status 2>/dev/null | head -3
```

### 17.2 Manual patching

| Distro | Refresh + list | Install all | Security only |
|---|---|---|---|
| Debian/Ubuntu | `apt-get update && apt list --upgradable` | `apt-get -o Dpkg::Options::=--force-confold --with-new-pkgs upgrade` | `apt-get install unattended-upgrades && unattended-upgrade -v` |
| RHEL/Rocky/Alma/Fedora | `dnf check-update` (exit 100 = updates) | `dnf -y upgrade` | `dnf -y upgrade --security` |
| SUSE | `zypper refresh && zypper list-updates` | `zypper update` | `zypper patch --category security` |
| Alpine | `apk update && apk version -l '<'` | `apk upgrade` | - |
| Arch | `pacman -Sy && pacman -Qu` | `pacman -Su` | - |

Why `--with-new-pkgs`: plain `apt-get upgrade` **keeps back** packages that
need a new dependency, and new kernels are exactly that. Why
`--force-confold`: keeps your edited config files instead of stopping to ask.

Reboot needed?

```bash
$ [ -f /var/run/reboot-required ] && cat /var/run/reboot-required      # Debian/Ubuntu
$ needs-restarting -r                                                    # RHEL family (dnf-utils)
$ ls /lib/modules/"$(uname -r)" >/dev/null || echo "running kernel removed: reboot"   # Arch/Alpine
```

### 17.3 Back up before you change anything

```bash
$ B=/var/backups/manual-harden-$(date +%Y%m%d-%H%M%S); mkdir -p -m 700 "$B"
$ cp -a /etc/ssh /etc/login.defs /etc/security /etc/sysctl.d /etc/issue /etc/issue.net /etc/motd "$B"/ 2>/dev/null
$ stat -c '%a %n' /etc/passwd /etc/group /etc/shadow /etc/ssh/sshd_config > "$B/perms.txt"
$ systemctl list-unit-files --state=enabled > "$B/enabled-units.txt"
```

### 17.4 Manual hardening, area by area

#### Kernel parameters (HD-KN-001..017)

Put them in one file, so undo is deleting it:

```bash
$ cat > /etc/sysctl.d/99-lab-hardening.conf <<'EOF'
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
kernel.randomize_va_space = 2
fs.suid_dumpable = 0
kernel.dmesg_restrict = 1
# strict:
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
EOF
$ sysctl --system                       # apply now
```

Don't set `ip_forward = 0` on a host that runs Docker, Kubernetes, libvirt
NAT, or is a router; it breaks container networking. `ptrace_scope = 1`
breaks attaching `gdb`/`strace` to processes you didn't start.
**Undo:** `rm /etc/sysctl.d/99-lab-hardening.conf && sysctl --system` (live
values return to defaults fully only after a reboot).

#### SSH daemon (HD-SSH-001..013)

First decide **where** settings go. sshd keeps the **first** value it reads
for each keyword:

```bash
$ grep -n '^Include' /etc/ssh/sshd_config
```

- If you see `Include /etc/ssh/sshd_config.d/*.conf`: create
  `/etc/ssh/sshd_config.d/00-lab-hardening.conf` (the `00-` makes it load
  first, ahead of `50-cloud-init.conf` and similar).
- If not: edit `/etc/ssh/sshd_config` and put the lines **above** any
  `Match` block.

```bash
$ cat > /etc/ssh/sshd_config.d/00-lab-hardening.conf <<'EOF'
PermitRootLogin no
PermitEmptyPasswords no
MaxAuthTries 4
X11Forwarding no
IgnoreRhosts yes
HostbasedAuthentication no
ClientAliveInterval 300
ClientAliveCountMax 3
LoginGraceTime 60
PermitUserEnvironment no
LogLevel VERBOSE
# strict - ONLY after proving key login works in another session:
# PasswordAuthentication no
# AllowTcpForwarding no
EOF
$ sshd -t && echo SYNTAX_OK              # never restart without this
$ sshd -T | grep -E '^(permitrootlogin|passwordauthentication|x11forwarding|clientalivecountmax) '
$ systemctl restart ssh 2>/dev/null || systemctl restart sshd
```

Then, **from a new terminal**, log in again. Only close the old session if
that works.

Notes:
- `ClientAliveCountMax 0` used to mean "disconnect on first missed
  keepalive". Since OpenSSH 8.2 it **disables** that termination, so `3` is
  used.
- Before `PasswordAuthentication no`, confirm a key works:
  `ssh -o PreferredAuthentications=publickey -o PasswordAuthentication=no user@host true`.

**Undo:** `rm /etc/ssh/sshd_config.d/00-lab-hardening.conf` (or restore
`sshd_config` from the backup), `sshd -t`, restart.

#### Accounts and passwords (HD-ID-001..013)

```bash
# /etc/login.defs: affects NEW accounts and new password changes
$ sed -i -E 's/^#?[[:space:]]*PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/; s/^#?[[:space:]]*PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/; s/^#?[[:space:]]*PASS_WARN_AGE.*/PASS_WARN_AGE\t7/; s/^#?[[:space:]]*UMASK.*/UMASK\t\t027/' /etc/login.defs
$ chage -M 90 -m 1 -W 7 labadmin          # existing accounts are NOT changed by login.defs

# password quality (Debian: apt install libpam-pwquality)
$ sed -i -E 's/^#?[[:space:]]*minlen.*/minlen = 14/' /etc/security/pwquality.conf
#   strict: dcredit = -1, ucredit = -1, lcredit = -1, ocredit = -1

# lockout (faillock)
$ sed -i -E 's/^#?[[:space:]]*deny.*/deny = 5/; s/^#?[[:space:]]*unlock_time.*/unlock_time = 900/' /etc/security/faillock.conf
#   faillock.conf only takes effect if pam_faillock is in the PAM stack:
#   RHEL: authselect enable-feature with-faillock | Ubuntu: add pam_faillock to common-auth
$ faillock --user labadmin                # see / reset with --reset

# no core dumps
$ echo '* hard core 0' > /etc/security/limits.d/99-lab-hardening.conf
```

If a `grep` for the key shows nothing (the line didn't exist), `sed` changed
nothing. Append it instead, e.g. `echo 'minlen = 14' >> /etc/security/pwquality.conf`.

#### Services (HD-SV-001..009)

```bash
$ for s in avahi-daemon cups rpcbind telnet.socket; do systemctl disable --now "$s" 2>/dev/null; done   # baseline
$ for s in vsftpd snmpd nfs-server smbd xinetd;   do systemctl disable --now "$s" 2>/dev/null; done   # strict
```

Some come back through **socket activation** (`cups.socket`,
`rpcbind.socket`, `avahi-daemon.socket`). Disable the socket too, or
`systemctl mask <unit>` to block it completely.
**Undo:** `systemctl enable --now <unit>` (check `enabled-units.txt`).

#### Firewall (HD-FW-001)

Find the SSH port first: `sshd -T | awk '$1=="port"'`.

```bash
# Debian/Ubuntu
$ ufw default deny incoming && ufw default allow outgoing
$ ufw allow 22/tcp            # your real SSH port
$ ufw --force enable && ufw status verbose
# undo: ufw disable

# RHEL/Fedora/SUSE
$ systemctl enable --now firewalld
$ firewall-cmd --permanent --add-service=ssh   # or --add-port=2222/tcp
$ firewall-cmd --reload && firewall-cmd --list-all
# undo: systemctl disable --now firewalld
```

#### Logging and audit (HD-LG-001..003)

```bash
$ apt install auditd || dnf install audit      # if missing
$ systemctl enable --now auditd
$ mkdir -p /var/log/journal && systemd-tmpfiles --create --prefix /var/log/journal   # persistent journal
$ systemctl restart systemd-journald
```

Audit rules (strict). Only add `-w` watches for paths that **exist**; a
missing path makes `auditctl` reject the rule:

```bash
$ cat > /etc/audit/rules.d/99-lab-hardening.rules <<'EOF'
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid_exec
-a always,exit -F arch=b64 -S init_module,delete_module -k modules
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
EOF
$ augenrules --load && auditctl -l
$ ausearch -k identity -ts recent        # see what got logged
```

#### Filesystem (HD-FS-001..006)

```bash
$ chmod 644 /etc/passwd /etc/group
$ chmod 600 /etc/ssh/sshd_config
$ chmod 640 /etc/shadow        # Debian/Ubuntu (group shadow); RHEL ships 000
# strict: stop rarely-used kernel modules from loading
$ for m in cramfs freevxfs jffs2 hfs hfsplus udf dccp sctp rds tipc; do echo "install $m /bin/true"; done \
    > /etc/modprobe.d/99-lab-hardening.conf
```

`udf` is needed to mount some DVD/ISO images. Remove its line if you use
them. **Undo:** `chmod` back to the modes in `perms.txt`; delete the modprobe
file.

`/tmp` with `noexec,nosuid,nodev` (paranoid) is **manual only**. A wrong
`fstab` line can stop the system booting:

```bash
$ systemctl cat tmp.mount            # many distros ship one
$ mkdir -p /etc/systemd/system/tmp.mount.d
$ printf '[Mount]\nOptions=mode=1777,strictatime,nosuid,nodev,noexec\n' > /etc/systemd/system/tmp.mount.d/options.conf
$ systemctl daemon-reload && systemctl enable --now tmp.mount && findmnt /tmp
```

Some installers and package scripts execute from `/tmp`. If one fails, set
`TMPDIR=/var/tmp` for that run.

#### Login banner (HD-BN-001)

```bash
$ msg='Authorized access only. All activity is monitored and logged.'
$ for f in /etc/issue /etc/issue.net /etc/motd; do printf '%s\n' "$msg" > "$f"; done
$ echo 'Banner /etc/issue.net' > /etc/ssh/sshd_config.d/01-banner.conf   # show it before SSH login too
```

### 17.5 Verify

```bash
$ sshd -t && sshd -T | grep -E '^(permitrootlogin|passwordauthentication) '
$ sysctl kernel.randomize_va_space net.ipv4.conf.all.accept_redirects
$ ufw status || firewall-cmd --state
$ reboot                                   # sysctl + modules settle fully
```

### 17.6 Manual rollback

```bash
$ cp -a "$B"/ssh/. /etc/ssh/ && rm -f /etc/ssh/sshd_config.d/00-lab-hardening.conf
$ cp -a "$B"/login.defs /etc/ && cp -a "$B"/security/. /etc/security/
$ rm -f /etc/sysctl.d/99-lab-hardening.conf /etc/modprobe.d/99-lab-hardening.conf \
        /etc/security/limits.d/99-lab-hardening.conf /etc/audit/rules.d/99-lab-hardening.rules
$ while read -r mode path; do chmod "$mode" "$path"; done < "$B/perms.txt"
$ sshd -t && systemctl restart ssh 2>/dev/null || systemctl restart sshd
$ sysctl --system; augenrules --load 2>/dev/null
```

## 18. Manual verification: comparing before and after

Scripted: `vmctl.sh compare baseline.json after.json` prints the score
change, every check that improved, every check that **regressed**, and the
Critical/High failures still open. It exits `1` if anything regressed.

By hand with `jq`:

```bash
host$ jq -r '.results[] | "\(.id) \(.status)"' baseline-linux.json | sort > before.txt
host$ jq -r '.results[] | "\(.id) \(.status)"' after-linux.json    | sort > after.txt
host$ diff before.txt after.txt
# Windows JSON uses capitalised keys and a BOM:
host$ sed '1s/^\xEF\xBB\xBF//' after-win.json | jq -r '.Results[] | "\(.Id) \(.Status)"'
```

What to look for:

- **Regressions** (PASS to FAIL/WARN): something you changed broke
  something else, or a reboot reverted a setting. Investigate before going on.
- **Still failing Critical/High:** usually needs a manual decision (BitLocker,
  GRUB password, AD CS templates, remote log collector).
- **Unknown:** usually the audit ran non-elevated. Re-run elevated.

## 19. Manual clean-up

```powershell
# Windows: remove the elevation path and the temp folder
PS> .\Enable-AgentElevation.ps1 -Remove
#   or by hand:
PS> Unregister-ScheduledTask -TaskName VMCTL-Elevated -Confirm:$false
PS> Remove-Item C:\Windows\Temp\vmctl -Recurse -Force
PS> net user labadmin *          # rotate the password that sat in .vmctl.env
```

```bash
# Linux: remove the temporary sudo rule and the copied scripts
$ rm -f /etc/sudoers.d/90-lab-temp /tmp/vmctl/*
# Host
host$ rm .vmctl.env              # or at least blank GUEST_PASS
host$ vmrun -T fusion snapshot "$VMX" hardened-$(date +%Y%m%d)   # known-good point
```

---

# Part 5 - Reference

# Windows checks

`scripts/windows/Invoke-HardeningAudit.ps1` — 61 checks. Run with
`-Format Console,Json,Csv,Markdown`, filter with `-Category`.

Manual commands below are PowerShell unless stated. Run elevated where noted.

## Identity and authentication (ID-001 — ID-010)

| ID | Check | Why it matters |
|---|---|---|
| ID-001 | UAC enabled (`EnableLUA=1`) | With UAC off, every admin process runs fully privileged with no prompt. Also the reason guest-ops elevation works differently. |
| ID-002 | UAC admin consent prompt | `ConsentPromptBehaviorAdmin=0` auto-elevates silently — malware inherits admin without a prompt. |
| ID-003 | `LocalAccountTokenFilterPolicy` not set | Value `1` grants full-token remote admin to local accounts, enabling pass-the-hash lateral movement. |
| ID-004 | Local Administrators membership | Every extra admin is another credential worth stealing. |
| ID-005 | Guest account disabled | Anonymous foothold. |
| ID-006 | No enabled accounts without password requirement | Such accounts authenticate with a blank password. |
| ID-007 | No non-expiring passwords | Static credentials survive every rotation policy. |
| ID-008 | Minimum password length ≥ 14 | Below 14, offline cracking of NTLM is fast. |
| ID-009 | Lockout threshold set (1–10) | `0` means unlimited online guessing. |
| ID-010 | Maximum password age bounded | Unbounded age means a leaked password is valid forever. |

**Check manually**

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' |
  Select-Object EnableLUA, ConsentPromptBehaviorAdmin, LocalAccountTokenFilterPolicy
Get-LocalGroupMember -Group Administrators
Get-LocalUser | Select-Object Name, Enabled, PasswordRequired, PasswordNeverExpires
net accounts
```

**Fix manually**

```powershell
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' EnableLUA 1
Disable-LocalUser -Name Guest
net accounts /minpwlen:14 /uniquepw:5 /maxpwage:90
net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15
```

**Undo:** restore the prior registry values; `net accounts /minpwlen:0`.
Corresponding hardening IDs: `HD-ID-001`…`HD-ID-012`.

---

## Patching (PA-001 — PA-006)

| ID | Check | Why it matters |
|---|---|---|
| PA-001 | OS build recorded | Establishes whether the build is still serviced. |
| PA-002 | OS install date | Context for drift. |
| PA-003 | Most recent hotfix within 45 days | Longer gaps mean known-exploited CVEs stay open. |
| PA-004 | Installed hotfix count | Sanity check against a baseline image. |
| PA-005 | No pending updates | Counts critical/important separately. |
| PA-006 | No reboot pending | Patches are not active until the reboot completes. |

**Check manually**

```powershell
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5
(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().
  Search("IsInstalled=0 and IsHidden=0").Updates | Select-Object Title, MsrcSeverity
Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
```

**Fix:** `Invoke-Patching.ps1 -Install` (elevated), then reboot.

---

## Microsoft Defender (DF-001 — DF-010)

| ID | Check | Why it matters |
|---|---|---|
| DF-001 | Real-time protection enabled | The single highest-value control. |
| DF-002 | Antivirus service running | A disabled service means no protection regardless of settings. |
| DF-003 | Behavior monitoring enabled | Catches fileless and living-off-the-land attacks signatures miss. |
| DF-004 | Tamper protection enabled | Stops malware disabling Defender. Cannot be set by script — UI or Intune only. |
| DF-005 | Signature age ≤ 7 days | Stale signatures miss current threats. |
| DF-006 | Network inspection (NIS) enabled | Blocks exploit traffic at the network layer. |
| DF-007 | PUA protection enabled | Blocks adware and bundled tooling. |
| DF-008 | Cloud protection (MAPS) enabled | Cloud lookup catches threats before local signatures ship. |
| DF-009 | Exclusions reviewed | **Every exclusion is a deliberate AV blind spot.** Attackers add their own. |
| DF-010 | ASR rules configured | Attack Surface Reduction blocks documented initial-access techniques. |

**Check manually**

```powershell
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, BehaviorMonitorEnabled,
  IsTamperProtected, AntivirusSignatureAge, NISEnabled
Get-MpPreference | Select-Object PUAProtection, MAPSReporting,
  ExclusionPath, ExclusionProcess, AttackSurfaceReductionRules_Ids
```

**Fix manually**

```powershell
Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false
Set-MpPreference -PUAProtection Enabled -MAPSReporting Advanced `
                 -SubmitSamplesConsent SendSafeSamples -CloudBlockLevel High
Update-MpSignature
```

### ASR rules applied by `-Profile Strict` (HD-DEF-008)

| GUID | Blocks |
|---|---|
| `56a863a9-…` | Abuse of exploited vulnerable signed drivers |
| `7674ba52-…` | Adobe Reader child processes |
| `d4f940ab-…` | Office apps creating child processes |
| `9e6c4e1f-…` | **Credential theft from LSASS** |
| `be9ba2d9-…` | Executable content from email/webmail |
| `01443614-…` | Untrusted/unsigned executables from USB |
| `5beb7efe-…` | Obfuscated script execution |
| `d3e037e1-…` | JS/VBS launching downloaded content |
| `3b576869-…` | Office creating executable content |
| `75668c1f-…` | Office injecting into other processes |
| `26190899-…` | Office communication app child processes |
| `e6db77e5-…` | **Persistence via WMI event subscription** |
| `d1e49aac-…` | Process creation from PSExec/WMI |
| `b2b3f03d-…` | Untrusted processes from USB |
| `c1db55ab-…` | Advanced ransomware protection |

**Undo one rule:**
`Add-MpPreference -AttackSurfaceReductionRules_Ids <guid> -AttackSurfaceReductionRules_Actions Disabled`

---

## Firewall (FW-001 — FW-005)

| ID | Check | Why it matters |
|---|---|---|
| FW-001/2/3 | Firewall enabled on Domain / Private / Public | A disabled profile exposes every listening service on that network type. |
| FW-004 | Default inbound action blocks | `NotConfigured` inherits the Windows default (Block) and is reported as **Warn**, not Fail — only an explicit `Allow` is a real finding. |
| FW-005 | Inbound allow-rule count | Windows ships ~100 rules; each enabled one is a potential path. |

**Check manually**

```powershell
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow | Measure-Object
```

**Fix manually**

```powershell
Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
Set-NetFirewallProfile -All -LogBlocked True -LogMaxSizeKilobytes 16384
```

**Undo:** `Set-NetFirewallProfile -All -DefaultInboundAction NotConfigured`

---

## Encryption and boot integrity (BL-001 — BL-003)

| ID | Check | Why it matters |
|---|---|---|
| BL-001 | OS volume BitLocker on | Without it, the virtual disk file can be mounted and read on the host. |
| BL-002 | TPM present and ready | Required for BitLocker without a startup PIN, and for Credential Guard. |
| BL-003 | Secure Boot enabled | Blocks bootkits and unsigned drivers. |

**Check manually (elevated)**

```powershell
Get-BitLockerVolume
Get-Tpm
Confirm-SecureBootUEFI
```

**Fix:** These are **hypervisor-layer**, not guest-layer.
On VMware Fusion a vTPM requires **VM encryption first** — adding
`vtpm.present = "TRUE"` to the VMX is silently discarded otherwise.
Use `vmctl.sh audit-host` to see the current VMX posture.

---

## Services (SV-001 — SV-008)

Each is checked for both running state and start mode.

| ID | Service | Risk |
|---|---|---|
| SV-001 | RemoteRegistry | Remote registry read/write; recon and persistence. |
| SV-002 | TermService (RDP) | Remote access; brute-force target. |
| SV-003 | SSDPSRV | UPnP discovery; information disclosure. |
| SV-004 | upnphost | UPnP device host. |
| SV-005 | WinRM | Remote PowerShell; lateral movement. |
| SV-006 | Spooler | **PrintNightmare (CVE-2021-34527) and PrinterBug coercion.** |
| SV-007 | SharedAccess | Internet Connection Sharing; turns the host into a router. |
| SV-008 | RemoteAccess | Routing and Remote Access. |

**Check manually**

```powershell
'RemoteRegistry','TermService','SSDPSRV','upnphost','WinRM','Spooler' | ForEach-Object {
  Get-CimInstance Win32_Service -Filter "Name='$_'" |
    Select-Object Name, State, StartMode
}
```

**Fix / undo**

```powershell
Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled
Set-Service Spooler -StartupType Automatic; Start-Service Spooler    # undo
```

---

## Attack surface (SU-001 — SU-008)

| ID | Check | Why it matters |
|---|---|---|
| SU-001 | SMBv1 disabled | WannaCry/EternalBlue protocol. No modern use. |
| SU-002 | SMB signing required | Unsigned SMB enables **NTLM relay** to SYSTEM. |
| SU-003 | LLMNR disabled | LLMNR poisoning (Responder) harvests NetNTLM hashes on any flat network. |
| SU-004 | NetBIOS over TCP/IP disabled | NBT-NS poisoning, same attack class as LLMNR. |
| SU-005 | Windows Script Host disabled | Blocks `.vbs`/`.js` double-click execution. |
| SU-006 | AutoRun disabled for all drives | Removable-media execution. |
| SU-007 | **PowerShell v2 engine removed** | PSv2 **bypasses AMSI and script-block logging entirely** — a one-line downgrade defeats your logging. |
| SU-008 | RDP disabled, or NLA enforced | Without NLA, pre-auth attack surface is exposed on 3389. |

**Check manually**

```powershell
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol, MicrosoftWindowsPowerShellV2Root |
  Select-Object FeatureName, State
Get-SmbServerConfiguration | Select-Object RequireSecuritySignature
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' EnableMulticast
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' |
  ForEach-Object { (Get-ItemProperty $_.PSPath).NetbiosOptions }
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' fDenyTSConnections
```

**Fix manually (elevated)**

```powershell
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
New-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' EnableMulticast -Value 0 -PropertyType DWord -Force
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' |
  ForEach-Object { Set-ItemProperty $_.PSPath NetbiosOptions 2 }
```

**Undo:** re-enable the optional features; set `EnableMulticast=1`;
`NetbiosOptions=0` (default).

> **Breakage warning:** disabling PSv2 and WSH breaks legacy scripts.
> Disabling SMBv1 breaks very old NAS devices and printers.

---

## Logging and audit (LG-001 — LG-004, LG-101 — LG-103)

| ID | Check | Why it matters |
|---|---|---|
| LG-001 | PowerShell script block logging | Event 4104 records deobfuscated script content — the single most useful IR artefact on Windows. |
| LG-002 | PowerShell module logging | Pipeline-level detail. |
| LG-003 | Process creation includes command line | Event 4688 without the command line is nearly useless. |
| LG-004 | Audit subcategories configured | Default policy misses most attacker activity. |
| LG-101/2/3 | Security / System / Application log ≥ 128 MB | Default sizes roll over in hours under load, destroying evidence. |

**Check manually**

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' EnableScriptBlockLogging
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' ProcessCreationIncludeCmdLine_Enabled
auditpol /get /category:*
Get-WinEvent -ListLog Security | Select-Object MaximumSizeInBytes
```

**Fix manually (elevated)**

```powershell
New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force
New-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
  EnableScriptBlockLogging -Value 1 -PropertyType DWord -Force
auditpol /set /subcategory:"Process Creation" /success:enable
wevtutil sl Security /ms:201326592
```

---

## Network and TLS (NW-001 — NW-003, HD-NET-001 — HD-NET-103)

| ID | Check | Why it matters |
|---|---|---|
| NW-001 | Externally-bound listening ports | Each `0.0.0.0` listener is network-reachable. |
| NW-002 | Network category | `Public` applies the most restrictive firewall profile. |
| NW-003 | IPv6 configuration | Recorded; disabling IPv6 is usually the wrong move. |
| HD-NET-001…020 | SSL 2.0/3.0, TLS 1.0/1.1 disabled; TLS 1.2 enabled | Legacy protocols are vulnerable to POODLE, BEAST, downgrade attacks. |
| HD-NET-100 | Insecure SMB guest auth blocked | Guest fallback enables silent MITM. |
| HD-NET-102 | IP source routing disabled | Anti-spoofing. |
| HD-NET-103 | ICMP redirects ignored | Route hijacking. |

**Check manually**

```powershell
Get-NetTCPConnection -State Listen | Where-Object LocalAddress -in '0.0.0.0','::'
Get-NetConnectionProfile
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols' -Recurse
```

> TLS changes require a reboot and can break old applications and management
> agents. They are in `Strict`/`Paranoid` only.

---

## Server role checks (SR-001 — SR-009)

Only evaluated when `ProductType` is 2 (DC) or 3 (server).

| ID | Check | Why it matters |
|---|---|---|
| SR-001 | System role identified | Drives which other checks apply. |
| SR-002 | Domain controller detected | Prompts you to run `Invoke-ADAudit.ps1`. |
| SR-003 | Installed roles minimal | Each role adds services and patch burden. |
| SR-004 | Server Core preferred | No shell/browser surface. |
| SR-005 | SMB1 feature removed | Server SKUs track SMB1 as a separate feature (`FS-SMB1`). |
| SR-006 | Domain joined | Context. |
| SR-007 | Secure channel healthy | A broken channel breaks GPO and authentication. |
| SR-008 | Cached logon count ≤ 4 | Each cached domain credential is offline-crackable. Servers should use `0`. |
| SR-009 | LDAP client signing required | Mitigates LDAP relay originating from this host. |

**Check manually**

```powershell
Get-WindowsFeature | Where-Object Installed
Test-ComputerSecureChannel
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' CachedLogonsCount
```

---

## Hypervisor integration (HV-001 — HV-002)

| ID | Check | Why it matters |
|---|---|---|
| HV-001 | VMware Tools running | Provides the guest-ops channel this toolkit uses. |
| HV-002 | VBS / Credential Guard running | Protects LSASS secrets in a hypervisor-isolated process. Needs nested virtualization **and** a vTPM. |

---

## Host-side VMX checks (`vmctl.sh audit-host`)

No guest script can see or fix these.

| Setting | Why it matters | VMX fix |
|---|---|---|
| `firmware` | UEFI enables Secure Boot. | `firmware = "efi"` |
| `uefi.secureBoot.enabled` | Blocks bootkits. | `= "TRUE"` |
| vTPM present | Required for BitLocker, Credential Guard, VBS. | **Encrypt the VM first**, then add the TPM device |
| VM encryption | Protects the disk at rest; prerequisite for vTPM. | Fusion → Settings → Encryption |
| CD-ROM connected at boot | Boot-order hijack and a data path. | `sata0:0.startConnected = "FALSE"` |
| Shared folders | Host↔guest data path. | disable unless needed |
| Drag-and-drop | Host↔guest data path. | `isolation.tools.dnd.disable = "TRUE"` |
| Copy/paste | Host↔guest data path. | `isolation.tools.copy.disable = "TRUE"` |
| 3D acceleration | Large driver surface; also a stability risk on Apple Silicon. | `mks.enable3d = "FALSE"` |

> **Fusion silently strips VMX keys it dislikes** (`vtpm.present`, a second
> CD-ROM on the same controller). Always re-read the file after editing.

---

# Active Directory checks

`scripts/windows/Invoke-ADAudit.ps1`. Needs the `ActiveDirectory` module
(RSAT). Run on a DC or an RSAT-equipped member.

## Domain configuration (AD-010 — AD-014)

| ID | Check | Why it matters |
|---|---|---|
| AD-010/011 | Domain / forest functional level ≥ 2016 | Older levels block Credential Guard, PAM, and modern Kerberos defaults. |
| AD-013 | AD Recycle Bin enabled | Without it, recovering a deleted OU needs an authoritative restore. |
| AD-014 | **`ms-DS-MachineAccountQuota` = 0** | Default is **10** — *any* domain user can join 10 computers, which is the pivot for resource-based constrained delegation escalation. |

```powershell
Get-ADDomain | Select-Object DomainMode
Get-ADObject (Get-ADDomain).DistinguishedName -Properties ms-DS-MachineAccountQuota
# fix:
Set-ADObject (Get-ADDomain).DistinguishedName -Replace @{'ms-DS-MachineAccountQuota'=0}
```

## Privileged access (AD-020 — AD-034)

| ID | Check | Why it matters |
|---|---|---|
| AD-020…027 | Membership of Domain/Enterprise/Schema Admins, Administrators, Account/Backup/Server/Print Operators | **Account, Server, and Print Operators should be empty** — each grants an indirect path to Domain Admin. |
| AD-030 | DAs flagged `AccountNotDelegated` | Prevents delegation-based credential theft. |
| AD-031 | **No Domain Admin has an SPN** | A DA with an SPN is kerberoastable — offline cracking straight to domain compromise. |
| AD-032 | DA passwords rotated within a year | |
| AD-033 | Protected Users group in use | Blocks NTLM, unconstrained delegation, and credential caching for members. |
| AD-034 | Built-in Administrator (RID 500) unused | First target in any domain. |

```powershell
Get-ADGroupMember 'Domain Admins' -Recursive
Get-ADUser -Filter {AdminCount -eq 1} -Properties ServicePrincipalName, AccountNotDelegated
Get-ADGroupMember 'Account Operators'   # should be empty
```

## Kerberos (AD-040 — AD-046)

| ID | Check | Attack |
|---|---|---|
| AD-040 | Kerberoastable accounts minimised | **Kerberoasting** — any domain user requests a service ticket for an SPN account and cracks it offline. Fix: Group Managed Service Accounts (120-char random passwords). |
| AD-041 | Service account passwords rotated | Old passwords are likely weak. |
| AD-042 | No accounts with pre-auth disabled | **AS-REP roasting** — needs *no credentials at all*. |
| AD-043 | **No unconstrained delegation outside DCs** | A host with unconstrained delegation caches any TGT sent to it. Combined with coercion (PrinterBug), that is a DA TGT. |
| AD-044 | Protocol transition reviewed | S4U2Self lets the host impersonate any user to the target service. |
| AD-045 | **krbtgt password rotated within 180 days** | A stolen krbtgt hash forges **Golden Tickets** indefinitely. Must be reset **twice**, waiting for replication between resets. |
| AD-046 | RC4 not explicitly enabled | RC4 tickets crack far faster than AES. |

```powershell
Get-ADUser -Filter {ServicePrincipalName -like '*' -and Enabled -eq $true} -Properties ServicePrincipalName
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}
Get-ADComputer -Filter {TrustedForDelegation -eq $true}
Get-ADUser krbtgt -Properties PasswordLastSet
```

## Accounts and password policy (AD-050 — AD-059)

| ID | Check |
|---|---|
| AD-050 | Few non-expiring passwords |
| AD-051 | No `PasswordNotRequired` accounts (blank password login) |
| AD-052/053 | Stale user / computer accounts (90 days) |
| AD-054 | **No reversible password encryption** — stores passwords recoverably |
| AD-055 | Minimum length ≥ 14 |
| AD-056 | Complexity enabled |
| AD-057 | Lockout threshold 1–10 |
| AD-058 | Password history ≥ 24 |
| AD-059 | Reversible encryption off domain-wide |

```powershell
Get-ADDefaultDomainPasswordPolicy
Get-ADUser -Filter {PasswordNotRequired -eq $true -and Enabled -eq $true}
```

## AD Certificate Services (AD-060 — AD-065)

AD CS misconfiguration is one of the most reliable domain-escalation paths.

| ID | Check | Attack |
|---|---|---|
| AD-061 | **ESC1** — template allows requester-supplied subject + client auth EKU + no manager approval | Any user requests a certificate *as a Domain Admin*. |
| AD-062 | **ESC2** — Any Purpose or empty EKU | The certificate can be used for authentication. |
| AD-063 | **ESC3** — Certificate Request Agent EKU | Enroll on behalf of any user. |
| AD-064 | **ESC4** — weak template ACLs (`WriteDacl`/`WriteOwner`/`GenericAll` for Authenticated Users) | Attacker reconfigures the template into ESC1. |

```powershell
$cfg = (Get-ADRootDSE).configurationNamingContext
Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$cfg" `
  -Filter {objectClass -eq 'pKICertificateTemplate'} `
  -Properties msPKI-Certificate-Name-Flag, msPKI-Enrollment-Flag, pKIExtendedKeyUsage
```

> Fixing AD CS is **not** automated here — the correct change depends on who
> legitimately needs each template. Remediate manually: remove
> `ENROLLEE_SUPPLIES_SUBJECT`, require manager approval, or tighten the ACL.

## LAPS (AD-070 — AD-071)

| ID | Check | Why |
|---|---|---|
| AD-070 | LAPS schema present | Without LAPS, every machine shares a local admin password — one compromise becomes lateral movement everywhere. |
| AD-071 | LAPS deployed to ≥ 90% of computers | Partial deployment leaves the gap open. |

## Domain controller posture (AD-080 — AD-089)

| ID | Check | Why |
|---|---|---|
| AD-081 | More than one DC | Resilience. |
| AD-083 | **LDAP signing required** (`LDAPServerIntegrity=2`) | Blocks LDAP relay. |
| AD-084 | **LDAP channel binding enforced** | Blocks relay to LDAPS. Hardening sets `1` (when supported) in Baseline (ADH-021) and `2` (always) in Strict (ADH-028). |
| AD-085 | SMB signing required on DC | Unsigned SMB on a DC enables NTLM relay to SYSTEM. |
| AD-086 | **Print Spooler disabled on DC** | PrinterBug coerces DC authentication to an attacker host. |
| AD-087 | NTLM auditing enabled | Audit before restricting, so you know what breaks. |
| AD-088 | DSRM logon behaviour not `2` | Value `2` lets the DSRM account log on normally — a persistence backdoor. |
| AD-089 | No replication failures | |

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' |
  Select-Object LDAPServerIntegrity, LdapEnforceChannelBinding
Get-Service Spooler
repadmin /replsummary
```

## Trusts and GPO (AD-090 — AD-102)

| ID | Check | Why |
|---|---|---|
| AD-091 | SID filtering on external trusts | Without it, a compromised trusted domain injects SID history to become DA here. |
| AD-101 | No unlinked GPOs | Config debt; can be re-linked maliciously. |
| AD-102 | **No `cpassword` in SYSVOL (MS14-025)** | Group Policy Preferences passwords are encrypted with a **published** AES key — any domain user can decrypt them. |

```powershell
Get-ADTrust -Filter * | Select-Object Name, Direction, SIDFilteringQuarantined
Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies" -Recurse -Include *.xml |
  Select-String cpassword
```

---

# Linux checks

`scripts/linux/audit.sh` — POSIX `sh`, no dependencies. Tested on
Debian 12, Rocky 9, and Alpine 3.20.

## System and identity (SY-001 — SY-003, ID-001 — ID-011)

| ID | Check | Why it matters |
|---|---|---|
| ID-001 | No accounts with empty passwords | Immediate authentication bypass. |
| ID-002 | **Only root has UID 0** | A second UID 0 account is a persistent backdoor that survives password changes. |
| ID-003/004/005 | `PASS_MAX_DAYS` ≤ 365, `PASS_MIN_DAYS` ≥ 1, `PASS_WARN_AGE` ≥ 7 | Password aging hygiene. |
| ID-006 | Default `UMASK` 027 or stricter | `022` makes new files world-readable. |
| ID-007 | `pam_pwquality` with `minlen` ≥ 14 | Without it, any password is accepted. |
| ID-008 | `pam_faillock` configured | Unlimited online guessing otherwise. |
| ID-009 | Root console logins restricted | |
| ID-010 | **No passwordless sudo** | `NOPASSWD` lets any compromised shell escalate silently. |
| ID-011 | sudo logging configured | |

```bash
awk -F: '($2 == "") {print $1}' /etc/shadow        # empty passwords
awk -F: '($3 == 0) {print $1}' /etc/passwd         # UID 0 accounts
grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|UMASK)' /etc/login.defs
grep -rE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/
```

## SSH daemon (SSH-001 — SSH-011)

Read via `sshd -T` (authoritative effective config, needs root) with a config-file fallback that follows sshd's **first-match-wins** rule, reads `sshd_config.d/` drop-ins first when they are `Include`d, and ignores `Match` blocks.

| ID | Setting | Why it matters |
|---|---|---|
| SSH-001 | `PermitRootLogin no` | Root over SSH is the most brute-forced account on the internet. |
| SSH-002 | `PasswordAuthentication no` | Keys-only defeats brute force entirely. **Confirm a working key first.** |
| SSH-003 | `PermitEmptyPasswords no` | |
| SSH-004 | `X11Forwarding no` | X11 forwarding can expose the client's display. |
| SSH-005 | `MaxAuthTries 4` | Limits guesses per connection. |
| SSH-006 | `ClientAliveInterval` ≤ 900 (with `ClientAliveCountMax 3`) | Dead sessions are reaped. Note `ClientAliveCountMax 0` *disables* this on OpenSSH ≥ 8.2. |
| SSH-007 | `LoginGraceTime` ≤ 60 | Limits unauthenticated connection slots. |
| SSH-008 | `HostbasedAuthentication no` | Trust-based auth is spoofable. |
| SSH-009 | `IgnoreRhosts yes` | Legacy trust files. |
| SSH-010 | `PermitUserEnvironment no` | Blocks `LD_PRELOAD`-style injection via `authorized_keys`. |
| SSH-011 | Host private keys `0600` | A readable host key enables server impersonation. |

```bash
sudo sshd -T | grep -E 'permitrootlogin|passwordauthentication|maxauthtries'
sudo sshd -t          # ALWAYS validate before restarting
```

> **Always keep a second session open** when changing SSH. `harden.sh` runs
> `sshd -t` and reports failure rather than leaving you locked out.

## Kernel parameters (KN-001 — KN-017)

| ID | Parameter | Expected | Why |
|---|---|---|---|
| KN-001 | `net.ipv4.ip_forward` | 0 | Routing turns the host into a pivot. |
| KN-002/003 | `accept_redirects`, `send_redirects` | 0 | ICMP redirect route hijacking. |
| KN-004 | `accept_source_route` | 0 | Source routing enables spoofing. |
| KN-005 | `rp_filter` | 1 | Drops spoofed source addresses. |
| KN-006 | `log_martians` | 1 | Logs impossible addresses. |
| KN-007 | `icmp_echo_ignore_broadcasts` | 1 | Smurf amplification. |
| KN-008 | `tcp_syncookies` | 1 | SYN flood mitigation. |
| KN-009 | **`kernel.randomize_va_space`** | **2** | Full ASLR. Anything less materially weakens exploit mitigation. |
| KN-010 | `fs.suid_dumpable` | 0 | SUID core dumps leak secrets. |
| KN-011 | `kernel.dmesg_restrict` | 1 | Kernel log leaks addresses. |
| KN-012 | `kernel.kptr_restrict` | 2 | Hides kernel pointers. |
| KN-013 | `net.ipv6.conf.all.accept_redirects` | 0 | IPv6 equivalent of KN-002. |
| KN-014 | **`kernel.yama.ptrace_scope`** | 1 | Restricts `ptrace` to descendants; blocks cross-process credential theft. |
| KN-015 | `net.ipv4.conf.default.accept_redirects` | 0 | `all` only covers interfaces that exist now; `default` covers ones created later (VPN, containers). |
| KN-016 | `net.ipv4.conf.default.accept_source_route` | 0 | Same, for source routing. |
| KN-017 | `net.ipv6.conf.default.accept_redirects` | 0 | Same, for IPv6 redirects. |

```bash
sysctl net.ipv4.ip_forward kernel.randomize_va_space kernel.yama.ptrace_scope
# fix (persistent):
echo 'kernel.randomize_va_space = 2' | sudo tee -a /etc/sysctl.d/99-lab-hardening.conf
sudo sysctl --system
```

## Filesystem (FS-001 — FS-009)

| ID | Check | Why |
|---|---|---|
| FS-001/002 | `/etc/passwd`, `/etc/group` = 644 | Must be readable, must not be writable. |
| FS-003 | `/etc/shadow` not world-readable | Hashes enable offline cracking. Debian uses `640`, RHEL `000`. |
| FS-004 | `/etc/ssh/sshd_config` = 600 | |
| FS-005 | No world-writable files outside temp | Any user can replace the contents. |
| FS-006 | No unowned files | A new UID silently inherits them. |
| FS-007 | SUID binary count ≤ 40 | Each SUID binary is a potential escalation path (see GTFOBins). |
| FS-008 | `/tmp` mounted `noexec,nosuid,nodev` | Blocks payload execution from a world-writable directory. |
| FS-009 | Core dumps disabled | Cores can contain credentials and keys. |

```bash
find / -xdev -type f -perm -0002 -not -path '/proc/*' -not -path '/tmp/*'
find / -xdev -type f -perm -4000       # SUID inventory
mount | grep ' /tmp '
```

## Services, network, firewall (SV-001 — SV-014, NW-001, FW-001 — FW-004)

Checked for active state: `telnet`, `rsh`, `rlogin`, `vsftpd`,
`avahi-daemon`, `cups`, `rpcbind`, `nfs-server`, `smbd`, `snmpd`,
`xinetd`, `dovecot`, `slapd`, `named`.

| ID | Check | Why |
|---|---|---|
| SV-* | Legacy/unneeded services disabled | telnet/rsh/rlogin are **cleartext**; SNMP often ships a default community string. |
| NW-001 | Externally-bound listening sockets minimal | Each `0.0.0.0` listener is reachable. |
| FW-001…004 | ufw / firewalld / nftables / iptables present with default deny | No host firewall means every listener is exposed. (ufw is matched on `Status: active` exactly; `inactive` is a FAIL.) |

```bash
ss -lntu | grep -E '0\.0\.0\.0|\[::\]'
sudo ufw status verbose          # or: firewall-cmd --list-all
```

## Logging, MAC, patching, boot (LG-001 — LG-005, MAC-001/002, PA-001 — PA-003, BT-001 — BT-003)

| ID | Check | Why |
|---|---|---|
| LG-001/002 | `auditd` running with rules | Syscall-level forensic trail. |
| LG-003 | rsyslog or journald active | |
| LG-004 | Journal persisted to disk | Volatile logs vanish on reboot — exactly when you need them. |
| LG-005 | **Logs forwarded to a remote collector** | Local-only logs are deleted by any attacker who gets root. |
| MAC-001 | SELinux enforcing | Contains a compromised service to its own domain. |
| MAC-002 | AppArmor profiles enforced | Same, on Debian/Ubuntu/SUSE. |
| PA-001 | No pending package updates | |
| PA-002 | Automatic security updates enabled | |
| PA-003 | No reboot pending | A patched-but-unbooted kernel is still vulnerable. |
| BT-001 | GRUB config not world-readable | |
| BT-002 | **GRUB password set** | Without it, console access means `init=/bin/bash` → instant root. |
| BT-003 | Secure Boot enabled | |

```bash
sudo auditctl -l
getenforce            # or: sudo aa-status
sudo apt-get -s --with-new-pkgs upgrade | grep ^Inst
```

---

## Hardening profiles

| Profile | Windows | Linux | AD | Risk |
|---|---|---|---|---|
| **Baseline** | UAC, password/lockout policy, LSA anonymous restrictions, WDigest off, Defender core, firewall inbound block + logging, LLMNR/NetBIOS off, SMB signing, AutoRun off, RDP NLA, PowerShell logging, audit policy, log sizes, Remote Registry/SSDP/UPnP off | sysctl set (incl. `default.*`), SSH core settings, password aging, pwquality minlen, faillock, umask 027, core dumps off, avahi/cups/rpcbind/telnet off, firewall default-deny, auditd, persistent journal, file modes, banners | MachineAccountQuota 0, Recycle Bin, password policy, DAs not delegable, pre-auth on, no reversible encryption, LDAP signing, channel binding (when supported), DC Spooler off, NTLM audit, DC SMB signing, AD audit policy, 1 GB Security log | Low |
| **Strict** | + LSASS PPL, 15 ASR rules, network protection, SMBv1 off, PowerShell v2 off, WSH off, TLS 1.0/1.1 off, no bridging, Spooler/ICS/RRAS off, File & Printer Sharing closed on Public | + keys-only SSH (guarded), no TCP forwarding, password complexity, `kptr_restrict`, `ptrace_scope`, audit rules, module blacklist, FTP/SNMP/NFS/Samba/xinetd off | + empty Operators groups, no unconstrained delegation, LSASS PPL, AES-only Kerberos, channel binding always | Medium |
| **Paranoid** | + Controlled Folder Access, WinRM off, RDP off | + umask 077, `/tmp noexec` guidance | + deny all NTLM | High |

> `Paranoid` removes remote management. Don't apply it to a VM you can only
> reach over the network.

---

## Rollback

**Windows.** Each run writes a JSON journal, saved **after every single
change**, so it survives a crash, reboot, or host timeout part-way through:

```bash
./scripts/vmctl.sh run-elevated scripts/windows/Invoke-Hardening.ps1 \
  -RollbackFile 'C:\Windows\Temp\vmctl\rollback\rollback-<stamp>.json'
./scripts/vmctl.sh run-elevated scripts/windows/Invoke-ADHardening.ps1 \
  -RollbackFile 'C:\Windows\Temp\vmctl\rollback\ad-rollback-<stamp>.json'
```

**Linux.** Each run writes a directory with the original files, their
modes, and a list of files it created:

```bash
sudo sh harden.sh --rollback /var/backups/lab-harden/<stamp>
sudo sshd -t && sudo systemctl restart ssh   # or sshd
sudo sysctl --system
```

What reverts automatically and what doesn't:

| Change | Windows | AD | Linux |
|---|---|---|---|
| Registry values / config files | yes | yes | yes |
| File permissions | - | - | yes |
| Files the run created (drop-ins, sysctl, modprobe, audit rules) | - | - | yes, deleted |
| Service start type + running state | yes | Spooler: yes | listed, manual |
| Audit policy (`auditpol`) | yes (from a `/backup` CSV) | yes | - |
| `ms-DS-MachineAccountQuota` | - | yes | - |
| Firewall profile state | listed, manual | - | listed, manual |
| Windows optional features (SMBv1, PSv2) | manual: `Enable-WindowsOptionalFeature` | - | - |
| Other AD object changes | - | prior state printed for manual undo | - |
| Live sysctl values | - | - | file restored; reboot to fully reset |

The blunt fallback is always the snapshot:

```bash
./scripts/vmctl.sh revert pre-hardening
```

---

## Safety rules

- **Snapshot before every change.** Non-negotiable. For AD, every DC.
- **Dry-run before every apply.** `-WhatIf` (Windows) / `--dry-run` (Linux),
  and actually read the output.
- **Patch before hardening.**
- **Keep a second SSH session open** when hardening Linux, and test a new
  login before closing the old one.
- **One profile at a time.** Re-audit between Baseline, Strict, and Paranoid.
- **AD:** apply on one DC, let replication converge
  (`repadmin /replsummary`), then continue.
- `.vmctl.env` holds a plaintext password. Use throwaway lab credentials,
  `chmod 600` it, and don't commit it (it's in `.gitignore`).
- `Enable-AgentElevation.ps1` creates a **persistent local privilege
  escalation path**. Remove it with `-Remove` when you're finished.
- Never switch NAT to bridged to get around a corporate TLS proxy. Install
  the proxy's root CA in the guest instead.
- AD CS findings (ESC1–ESC4) are reported but **never auto-remediated**.

---

## Troubleshooting quick reference

Full list with verbatim error text: `reference/troubleshooting.md`.

| Symptom | Cause | Fix |
|---|---|---|
| `Access is denied` writing HKLM from the host | UAC-filtered guest token | Elevation task ([2.3](#23-uac-token-filtering-why-administrator-is-not-elevated)) |
| `run-elevated`: `elevation task ... not found` | bootstrap not run, or a different `ELEV_TASK` | run `Enable-AgentElevation.ps1` in the guest |
| `run-elevated`: push failed / access denied on `C:\Windows\Temp\vmctl` | folder ACL doesn't include `GUEST_USER` | re-run `Enable-AgentElevation.ps1 -AgentUser <DOMAIN\user>` |
| `run-elevated` times out during patching | Windows Update is slow | `ELEV_TIMEOUT=3600`; the task keeps running, so check `elevated.log` later |
| `A positional parameter cannot be found that accepts argument ' '` | `-File` through `cmd /c` | use `-Command "& 'script'"` (vmctl does) |
| vmrun exit 1, no output, Windows 11 ARM64 | launching `powershell.exe` directly | launch `cmd.exe /c powershell ...` (vmctl does) |
| Garbled output (`ÿþ`, spaced letters) | UTF-16LE output read as UTF-8 | decode by BOM (`iconv -f UTF-16LE`) |
| `vmrun stop soft` hangs | Tools not responding | `vmctl.sh stop 60` (enforces a deadline) |
| Locked out of SSH after hardening | passwords off with no working key, or firewall port | console in through VMware, `harden.sh --rollback <dir>` |
| `sshd -t`: `Missing privilege separation directory: /run/sshd` | sshd not running yet | `mkdir -p /run/sshd` (harden.sh does) |
| `sudo: a password is required` in `lrun --sudo` | no passwordless sudo | see [2.4](#24-linux-privilege-sudo-without-a-terminal) |
| apt upgrade hangs | conffile prompt with no TTY | `-o Dpkg::Options::=--force-confold` (patch.sh does) |
| Audit says `Unknown` a lot | ran non-elevated / non-root | re-run elevated / with sudo |
| `ERR_CERT_AUTHORITY_INVALID` in the guest | TLS-inspecting proxy | import the proxy root CA into the guest |

---

## Glossary

| Term | Meaning |
|---|---|
| **ASR** | Attack Surface Reduction: Defender rules that block common malware behaviours (Office spawning processes, credential theft from LSASS, ...). |
| **AS-REP roasting** | Requesting a Kerberos AS-REP for an account with pre-authentication disabled and cracking it offline. |
| **CBT / channel binding** | Ties an LDAPS authentication to the TLS channel, so it can't be relayed. |
| **CIS** | Center for Internet Security. Publishes the benchmarks these checks are aligned with. |
| **DC** | Domain controller. |
| **ESC1–ESC4** | Classes of AD Certificate Services misconfiguration that let a user obtain a certificate for someone else (e.g. a Domain Admin). |
| **Kerberoasting** | Requesting service tickets for accounts with SPNs and cracking them offline. |
| **LAPS** | Local Administrator Password Solution: unique, rotated local admin passwords stored in AD. |
| **LLMNR / NBT-NS** | Fallback name-resolution protocols that tools like Responder spoof to capture hashes. |
| **LSASS / PPL** | The process holding credentials in memory / Protected Process Light, which stops other processes reading it. |
| **NLA** | Network Level Authentication: RDP authenticates before a session is created. |
| **NTLM relay** | Forwarding a captured NTLM authentication to another service. Stopped by SMB/LDAP signing and channel binding. |
| **RBCD** | Resource-Based Constrained Delegation. With a non-zero MachineAccountQuota, any user can create a computer account and abuse it. |
| **Rollback journal** | The record of prior values a hardening run writes so its changes can be undone. |
| **UAC token filtering** | Windows giving admin accounts a standard-rights token until elevation is approved. |
| **Unconstrained delegation** | A computer that caches users' TGTs and can impersonate them anywhere. |
| **VMware Tools / vmrun** | Guest agent / host CLI that together run programs and copy files in the guest without networking. |
| **VMX** | The VM's configuration file on the host. |

---

## Testing status

| Component | Verification |
|---|---|
| `linux/audit.sh` | Debian 12, Rocky 9, Alpine 3.20, Ubuntu 24.04 - valid JSON, correct exit codes |
| `linux/harden.sh` | Debian 12 applied + rolled back. Ubuntu 24.04: strict apply with an `Include` + cloud-init drop-in (settings land in `00-lab-hardening.conf`), `Match`-block insertion, keys-only guard, and byte-identical rollback of files and modes |
| `linux/patch.sh` | Debian 12 (apt), Rocky 9 (dnf), Ubuntu 24.04 (scan, JSON) |
| `compare-audit.py` | Linux before/after reports; Windows-format keys and BOM handled |
| `vmctl.sh` vmrun transport | live Windows 11 ARM64 VM |
| `vmctl.sh` SSH transport | Dockerised sshd: `ssh`, `lpush`, `lpull`, `lrun`, `lrun --sudo` |
| `Invoke-HardeningAudit.ps1` | live VM: 61 checks, role detection |
| `Invoke-ADAudit.ps1` | live VM: graceful degradation on a non-domain host |
| Elevated runner argument passing | PowerShell 7: named parameters, switches, quoted paths with spaces |
| All PowerShell | parsed with the PowerShell AST parser |
| All shell | `shellcheck -S warning` clean, `dash -n` |

Not yet verified: `run-elevated` end-to-end against a live guest after the
runner and ACL changes, and the AD scripts against a real domain controller
(this lab has no DC). The AD logic follows documented Microsoft attributes
and the standard ESC1–ESC4 definitions, but treat first use against a real
domain as validation, with snapshots.
