---
name: vm-lab-assistant
description: Control, audit, harden, and patch lab VMs end to end - Windows 10/11, Windows Server, Active Directory domain controllers, and Linux. Use when the user says harden a VM, audit VM security, CIS baseline, patch a guest, secure a domain controller, AD security audit, kerberoasting, AD CS ESC1, LAPS, Linux hardening, sshd hardening, sysctl hardening, run commands inside a guest OS, vmrun guest operations, or when debugging guest access denied, UAC token filtering, VM boot and install failures, TPM 2.0 bypass, VMware Tools black screen, or ERR_CERT_AUTHORITY_INVALID inside a VM. Covers establish control, elevate, baseline audit, patch, harden with profiles, verify, and roll back.
license: MIT
compatibility: Host - macOS/Linux/WSL with bash 3.2+. Guests - Windows 10/11/Server 2016+ (PowerShell 5.1+, VMware Tools) and Linux (POSIX sh, SSH). Hypervisor - VMware Fusion/Workstation; guest scripts are hypervisor-agnostic.
---

# VM Lab Assistant

End-to-end control, auditing, hardening, and patching for lab virtual
machines across four target types.

## When to use this

- "Harden this VM" / "run a CIS baseline" / "audit VM security"
- "Secure my domain controller" / "audit Active Directory"
- "Harden this Linux box" / "check sshd and sysctl settings"
- "Patch the guest" / "run a command inside the VM"
- Guest returns `Access is denied` despite being an administrator
- VM boot/install failures, TPM 2.0 blocks, black screen after Tools,
  certificate errors behind a TLS-inspecting proxy

## Target matrix

| Target | Audit | Harden | Patch | Transport |
|---|---|---|---|---|
| Windows client/server | `windows/Invoke-HardeningAudit.ps1` | `windows/Invoke-Hardening.ps1` | `windows/Invoke-Patching.ps1` | vmrun |
| AD domain controller | `windows/Invoke-ADAudit.ps1` | `windows/Invoke-ADHardening.ps1` | `windows/Invoke-Patching.ps1` | vmrun |
| Linux | `linux/audit.sh` | `linux/harden.sh` | `linux/patch.sh` | SSH |
| Hypervisor layer | `vmctl.sh audit-host` | manual VMX edits | — | host |

`README.md` documents **every individual check** with rationale, the manual
command, and how to undo it. Read `reference/checklist.md` for the runbook
and `reference/troubleshooting.md` the moment anything misbehaves.

## Setup

```bash
cp .vmctl.env.example .vmctl.env    # set VMX + GUEST_USER/GUEST_PASS, or SSH_*
./scripts/vmctl.sh status
./scripts/vmctl.sh detect           # identifies the guest, suggests scripts
```

Always run `detect` first — it reports OS family and, for Windows, whether
the guest is a domain controller.

## The workflow

Identical five phases for every target. Do not reorder them.

### 1. Snapshot

```bash
./scripts/vmctl.sh snapshot pre-hardening
```

Non-negotiable. Hardening touches LSA, SCHANNEL, sshd, and services; a bad
combination can leave the guest unbootable or unreachable.

### 2. Audit (read-only)

```bash
./scripts/vmctl.sh audit-host                                            # hypervisor layer
./scripts/vmctl.sh run-script scripts/windows/Invoke-HardeningAudit.ps1  # Windows
./scripts/vmctl.sh run-elevated scripts/windows/Invoke-ADAudit.ps1       # if a DC
./scripts/vmctl.sh lrun scripts/linux/audit.sh                           # Linux
```

Save the JSON as your baseline. `Unknown` results while non-elevated are
expected, not a bug.

### 3. Elevate

**Windows** — guest ops run with a **UAC-filtered token**. Administrators
membership is *not* elevation; `HKLM` policy writes fail with
`Access is denied`. Confirm with `vmctl.sh whoami` (`Elevated=False`).

Have the user run **once**, from an elevated PowerShell inside the guest:

```powershell
.\Enable-AgentElevation.ps1
```

Then `run-elevated` works from the host. Remove it afterwards with
`-Remove`. If the user runs it from a different account than `GUEST_USER`,
add `-AgentUser 'DOMAIN\user'` so the host account can write the control
file.

**Linux** — use `lrun --sudo`. Passwordless sudo or a configured askpass is
required for non-interactive runs.

### 4. Patch before hardening

Hardening can disable services that the update path depends on.

```bash
ELEV_TIMEOUT=3600 ./scripts/vmctl.sh run-elevated scripts/windows/Invoke-Patching.ps1 -Install
./scripts/vmctl.sh lrun --sudo scripts/linux/patch.sh --install
./scripts/vmctl.sh restart
```

Repeat the scan until it reports zero pending.

### 5. Harden, dry-run first

```bash
# Windows
./scripts/vmctl.sh run-elevated scripts/windows/Invoke-Hardening.ps1 -Profile Baseline -WhatIf
./scripts/vmctl.sh run-elevated scripts/windows/Invoke-Hardening.ps1 -Profile Baseline

# Active Directory (snapshot EVERY DC first)
./scripts/vmctl.sh run-elevated scripts/windows/Invoke-ADHardening.ps1 -Profile Baseline -WhatIf

# Linux
./scripts/vmctl.sh lrun --sudo scripts/linux/harden.sh --dry-run
./scripts/vmctl.sh lrun --sudo scripts/linux/harden.sh --profile baseline
```

| Profile | Risk |
|---|---|
| `baseline` | Low — safe defaults, broadly reversible |
| `strict` | Medium — ASR rules, LSASS PPL, SMBv1/PSv2 off, keys-only SSH |
| `paranoid` | High — disables WinRM/RDP, umask 077 |

Escalate one profile at a time, re-auditing between each.

### 6. Verify and clean up

Re-audit, then diff against the baseline (exit 1 means something regressed):

```bash
./scripts/vmctl.sh compare baseline.json after.json
```

Confirm no regressions, then remove the elevation task and rotate the
bootstrap password. `README.md` Part 4 has the by-hand version of every
phase if the user wants to do or learn it manually.

## Rollback

Every hardening run writes a journal.

```bash
# Windows
./scripts/vmctl.sh run-elevated scripts/windows/Invoke-Hardening.ps1 -RollbackFile '<path>.json'
# Linux
./scripts/vmctl.sh lrun --sudo scripts/linux/harden.sh --rollback /var/backups/lab-harden/<stamp>
# blunt fallback
./scripts/vmctl.sh revert pre-hardening
```

Registry values, config files, Linux file modes, Windows service state, and
audit policy revert automatically. Windows optional features, firewall
profiles, and most AD object changes are recorded (prior state printed) but
need manual revert. Journals are saved after every change, so they survive a
mid-run crash or host timeout.

## Hard-won facts

These cost real debugging time. Trust them.

1. **`vmrun` must launch `cmd.exe`, not `powershell.exe`.** Direct
   invocation fails with exit code 1 and no output on Windows 11 ARM64.
2. **Use `-Command "& 'script'"`, never `-File`.** Via `cmd /c`, `-File`
   gets a stray empty argument and fails with
   `A positional parameter cannot be found that accepts argument ' '`.
3. **Guest ops are UAC-filtered.** Group membership is not elevation.
4. **Decode guest output by BOM.** PowerShell 5.1 emits UTF-16LE for `>` but
   UTF-8-with-BOM for `Set-Content -Encoding UTF8`. Guessing yields mojibake.
5. **Set `$ProgressPreference='SilentlyContinue'`** in remote snippets or
   CLIXML progress records pollute stdout.
6. **In `sed`, never use `|` as the delimiter** when the pattern contains an
   alternation like `([[:space:]]|=)` — it silently fails.
7. **`grep -c` exits non-zero on zero matches**, so `$(... || echo 0)` can
   produce `"0\n0"` and break `[ ]` numeric tests.
8. **Back up each file once per run.** Thirteen sshd controls calling backup
   thirteen times will overwrite the pristine copy with a modified one.
9. **VMware Fusion silently strips VMX keys** (`vtpm.present`, a second
   CD-ROM on the same controller). Re-read the file after editing; use a
   separate controller (`sata1:0`).
10. **A vTPM requires VM encryption first** on Fusion — no BitLocker,
    Credential Guard, or VBS without it.
11. **`vmrun stop soft` hangs without VMware Tools.** Enforce your own
    deadline and escalate.
12. **The NVRAM file is named `nvram`, no extension** — a `*.nvram` glob
    misses it, and a stale one caches failed EFI boot entries.
13. **Before blaming storage drivers, check whether the disk is growing.**
    Rising `DISKLIB-LIB numIOs` means storage works.
14. **`mks.enable3d = "FALSE"`** if the guest goes black after installing
    VMware Tools on Apple Silicon.
15. **Use `vmxnet3`, not `e1000e`,** on Windows 11 ARM64.
16. **Always run `sshd -t` before restarting sshd**, and keep a second
    session open.
17. **sshd keeps the FIRST value it reads.** With `Include sshd_config.d/*.conf`
    at the top, a cloud-init drop-in beats anything appended to
    `sshd_config`; anything appended after a `Match` line only applies to
    that match. `harden.sh` writes `sshd_config.d/00-lab-hardening.conf` and
    checks the result with `sshd -T`.
18. **Splatting a string array does not bind `-Name` parameters** in
    PowerShell: `& $script @('-Profile','Strict')` binds `-Profile` as a
    positional value. The elevated runner parses the argument line with the
    PowerShell parser instead.
19. **`ufw status` prints `Status: inactive`**, which contains "active".
    Match `^Status: active`.
20. **`ClientAliveCountMax 0` disables keepalive termination** on
    OpenSSH 8.2+; use 3.

## Safety rules

- Always snapshot first; always dry-run first.
- Patch before hardening.
- Keep a second SSH session open when hardening Linux.
- Snapshot **every** DC before AD changes; apply to one and let replication
  converge first.
- Treat `Enable-AgentElevation.ps1` as temporary; remove it when done.
- `.vmctl.env` holds a plaintext password — throwaway lab credentials only.
- Never switch NAT→bridged to bypass a corporate TLS proxy; install the
  proxy root CA in the guest instead.
- AD CS findings (ESC1–ESC4) are reported but **not auto-remediated** — the
  correct fix depends on who legitimately needs each template.
