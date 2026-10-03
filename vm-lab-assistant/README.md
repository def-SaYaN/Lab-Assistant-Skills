# VM Lab Assistant

A portable AI skill plus standalone scripts for controlling, auditing,
hardening, and patching lab virtual machines — **Windows client, Windows
Server, Active Directory domain controllers, and Linux**.

Every check in this document includes **what it checks, why it matters, the
manual command to run it yourself, and how to undo it.** You can use this
purely as a study reference and never run a script at all.

---

## Contents

- [Scope and design](#scope-and-design)
- [Install](#install)
- [Configuration](#configuration)
- [The workflow](#the-workflow)
- [`vmctl.sh` command reference](#vmctlsh-command-reference)
- [**Windows checks (61)**](#windows-checks)
- [**Active Directory checks (45+)**](#active-directory-checks)
- [**Linux checks (70+)**](#linux-checks)
- [Hardening profiles](#hardening-profiles)
- [Rollback](#rollback)
- [Safety](#safety)

---

## Scope and design

| Target | Audit | Harden | Patch | Transport |
|---|---|---|---|---|
| Windows 10/11 client | `windows/Invoke-HardeningAudit.ps1` | `windows/Invoke-Hardening.ps1` | `windows/Invoke-Patching.ps1` | vmrun guest ops |
| Windows Server | same + role checks | same | same | vmrun guest ops |
| AD domain controller | `windows/Invoke-ADAudit.ps1` | `windows/Invoke-ADHardening.ps1` | `windows/Invoke-Patching.ps1` | vmrun guest ops |
| Linux (any major distro) | `linux/audit.sh` | `linux/harden.sh` | `linux/patch.sh` | SSH |

Design rules this toolkit follows:

1. **Audit is always read-only.** It never writes, never changes state.
2. **Hardening always supports dry-run** and writes a rollback journal.
3. **Scripts are standalone.** Each runs by hand with no framework, no
   modules to install, no internet access.
4. **Degrade, never crash.** A check that cannot run reports `Unknown`,
   it does not abort the run.
5. **Exit codes are meaningful:** `0` clean, `1` warnings, `2` failures.

### Files

```
SKILL.md                             portable skill definition
README.md                            this file
.vmctl.env.example                   config template
scripts/vmctl.sh                     host control wrapper (vmrun + SSH)
scripts/windows/
  Invoke-HardeningAudit.ps1          61 checks, read-only
  Invoke-Hardening.ps1               remediation, 3 profiles, rollback
  Invoke-Patching.ps1                Windows Update + Defender
  Invoke-ADAudit.ps1                 45+ AD checks, read-only
  Invoke-ADHardening.ps1             AD remediation, rollback
  Enable-AgentElevation.ps1          one-time UAC elevation bootstrap
scripts/linux/
  audit.sh                           70+ CIS-aligned checks, read-only
  harden.sh                          remediation, 3 profiles, rollback
  patch.sh                           apt/dnf/yum/zypper/apk/pacman
reference/checklist.md               phase-by-phase runbook
reference/troubleshooting.md         verbatim symptoms and fixes
```

---

## Install

### Claude Code / opencode

```bash
mkdir -p ~/.claude/skills
cp -r vm-lab-assistant ~/.claude/skills/vm-lab-assistant
```

opencode also auto-loads `~/.agents/skills/` and `.opencode/skills/`.

### Any other assistant (ChatGPT, Gemini, Cursor)

Point it at `SKILL.md`, or paste that file into the system prompt. Keep
`scripts/` and `reference/` beside it.

### Standalone (no AI)

Nothing to install. Copy `scripts/` to the host and run them.

---

## Configuration

```bash
cp .vmctl.env.example .vmctl.env
```

```bash
# VMware target (Windows guests)
VMX="$HOME/Virtual Machines.localized/MyVM.vmwarevm/MyVM.vmx"
GUEST_USER=Administrator
GUEST_PASS=changeme
VM_TYPE=fusion

# SSH target (Linux guests). SSH_HOST autodetects from VMware Tools if unset.
SSH_HOST=192.168.1.50
SSH_USER=labadmin
SSH_KEY=~/.ssh/lab_key
SSH_PORT=22
```

Verify, and let the tool identify the guest:

```bash
./scripts/vmctl.sh env
./scripts/vmctl.sh status
./scripts/vmctl.sh detect     # identifies OS family and suggests scripts
```

---

## The workflow

Same five phases for every target type.

```
0. SNAPSHOT        vmctl.sh snapshot pre-hardening
1. AUDIT           establish a baseline, save the JSON
2. ELEVATE         Windows: UAC bootstrap | Linux: sudo
3. PATCH           always before hardening
4. HARDEN          --dry-run, snapshot, apply, reboot
5. VERIFY          re-audit, compare, clean up
```

### Windows client or server

```bash
./scripts/vmctl.sh snapshot pre-hardening
./scripts/vmctl.sh audit-host
./scripts/vmctl.sh run-script scripts/windows/Invoke-HardeningAudit.ps1
# one-time, inside the guest, elevated:  .\Enable-AgentElevation.ps1
./scripts/vmctl.sh run-elevated scripts/windows/Invoke-Patching.ps1 -Install
./scripts/vmctl.sh restart
./scripts/vmctl.sh run-elevated scripts/windows/Invoke-Hardening.ps1 -Profile Baseline -WhatIf
./scripts/vmctl.sh run-elevated scripts/windows/Invoke-Hardening.ps1 -Profile Baseline
./scripts/vmctl.sh restart
./scripts/vmctl.sh run-elevated scripts/windows/Invoke-HardeningAudit.ps1
```

### Active Directory domain controller

```bash
./scripts/vmctl.sh snapshot pre-ad-hardening     # snapshot EVERY DC
./scripts/vmctl.sh run-elevated scripts/windows/Invoke-ADAudit.ps1
./scripts/vmctl.sh run-elevated scripts/windows/Invoke-ADHardening.ps1 -Profile Baseline -WhatIf
./scripts/vmctl.sh run-elevated scripts/windows/Invoke-ADHardening.ps1 -Profile Baseline
./scripts/vmctl.sh restart
./scripts/vmctl.sh run-elevated scripts/windows/Invoke-ADAudit.ps1
```

> AD changes are forest-wide. Snapshot **all** DCs, apply to one first, and
> let replication converge (`repadmin /replsummary`) before the next.

### Linux

```bash
./scripts/vmctl.sh lrun scripts/linux/audit.sh
./scripts/vmctl.sh lrun --sudo scripts/linux/patch.sh --install
./scripts/vmctl.sh lrun --sudo scripts/linux/harden.sh --dry-run
./scripts/vmctl.sh lrun --sudo scripts/linux/harden.sh --profile baseline
./scripts/vmctl.sh lrun scripts/linux/audit.sh
```

Or directly on the box:

```bash
sudo ./audit.sh --json /tmp/audit.json
sudo ./harden.sh --dry-run
sudo ./harden.sh --profile baseline
```

> **Never close your only SSH session** after hardening. Open a second one
> and confirm you can still log in. `harden.sh` runs `sshd -t` automatically
> and refuses to claim success on an invalid config.

---

## `vmctl.sh` command reference

| Command | Purpose |
|---|---|
| `env` | show resolved configuration |
| `status` | running / tools / IP |
| `detect` | identify guest OS and suggest scripts |
| `start [gui\|nogui]` | power on, wait for Tools |
| `stop [secs] [soft\|hard]` | graceful stop with hard fallback |
| `restart [secs]` | stop then start |
| `wait-tools [secs]` | block until Tools responds |
| `snapshot <name>` / `snapshots` / `revert <name>` / `delete-snapshot <name>` | snapshot management |
| `push <local> <guest>` / `pull <guest> <local>` | file copy (Windows) |
| `exists <path>` / `mkdir-guest <dir>` / `ps-list` | guest filesystem/process |
| `ps '<code>'` / `psout '<code>'` | run PowerShell; `psout` captures stdout |
| `run-script <ps1> [args]` | run a script non-elevated |
| `run-elevated <ps1> [args]` | run a script with full admin rights |
| `whoami` | guest identity and elevation state |
| `ssh '<cmd>'` | run a command on a Linux guest |
| `lpush` / `lpull` | file copy over SSH |
| `lrun [--sudo] <sh> [args]` | copy and execute a shell script |
| `audit-host` | inspect the `.vmx` for hypervisor-layer issues |

Exit codes: `0` ok, `2` usage, `3` config, `4` vmrun, `5` guest, `6` timeout.

---

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
| AD-084 | **LDAP channel binding enforced** | Blocks relay to LDAPS. |
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

Read via `sshd -T` (authoritative effective config) with a config-file fallback.

| ID | Setting | Why it matters |
|---|---|---|
| SSH-001 | `PermitRootLogin no` | Root over SSH is the most brute-forced account on the internet. |
| SSH-002 | `PasswordAuthentication no` | Keys-only defeats brute force entirely. **Confirm a working key first.** |
| SSH-003 | `PermitEmptyPasswords no` | |
| SSH-004 | `X11Forwarding no` | X11 forwarding can expose the client's display. |
| SSH-005 | `MaxAuthTries 4` | Limits guesses per connection. |
| SSH-006 | `ClientAliveInterval` ≤ 900 | Idle sessions are hijackable. |
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

## Kernel parameters (KN-001 — KN-014)

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

```bash
sysctl net.ipv4.ip_forward kernel.randomize_va_space kernel.yama.ptrace_scope
# fix (persistent):
echo 'kernel.randomize_va_space = 2' | sudo tee -a /etc/sysctl.d/99-hardening.conf
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
| FW-001…004 | ufw / firewalld / nftables / iptables present with default deny | No host firewall means every listener is exposed. |

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
sudo apt-get -s upgrade | grep ^Inst
```

---

## Hardening profiles

| Profile | Windows | Linux | Risk |
|---|---|---|---|
| **Baseline** | UAC, password/lockout policy, LSA anonymous restrictions, WDigest off, Defender core, firewall inbound block, LLMNR/NetBIOS off, SMB signing, AutoRun off, RDP NLA, PowerShell logging, audit policy, log sizes, low-value services off | sysctl set, SSH core settings, password aging, faillock, umask 027, core dumps off, legacy services off, firewall default-deny, auditd, persistent journal, banners | Low |
| **Strict** | + LSASS PPL (`RunAsPPL`), 15 ASR rules, network protection, SMBv1 off, PowerShell v2 off, WSH off, TLS 1.0/1.1 off, Spooler/ICS/RRAS off | + keys-only SSH, no TCP forwarding, password complexity, `kptr_restrict`, `ptrace_scope`, audit rules, module blacklist, more services off | Medium |
| **Paranoid** | + controlled folder access, WinRM off, RDP off | + umask 077, `/tmp noexec` guidance | High |

> `Paranoid` disables remote management. Do not apply it to a VM you can only
> reach over the network.

---

## Rollback

**Windows** — each run writes a JSON journal:

```bash
./scripts/vmctl.sh run-elevated scripts/windows/Invoke-Hardening.ps1 \
  -RollbackFile 'C:\Windows\Temp\vmctl\rollback\rollback-<stamp>.json'
```

**Linux** — each run writes a directory of original files:

```bash
sudo ./harden.sh --rollback /var/backups/lab-harden/<stamp>
```

Registry values and config files revert automatically. **Service state,
Windows optional features, and AD object changes are recorded but must be
reverted manually** — they are listed in the journal output.

The blunt fallback is always the snapshot:

```bash
./scripts/vmctl.sh revert pre-hardening
```

---

## Safety

- **Snapshot before every change.** Non-negotiable.
- **Dry-run before every apply.** `-WhatIf` (Windows) / `--dry-run` (Linux).
- **Patch before hardening** — hardening can disable services Windows Update
  or `apt` depend on.
- **Keep a second SSH session open** when hardening Linux.
- **Snapshot every DC** before AD changes, apply to one, let replication
  converge, then continue.
- `.vmctl.env` holds a plaintext password. Use throwaway lab credentials.
- `Enable-AgentElevation.ps1` creates a **persistent local privilege
  escalation path**. Remove it with `-Remove` when finished.
- Never switch NAT→bridged to bypass a corporate TLS proxy. Install the
  proxy's root CA in the guest instead.

---

## Testing status

Verified against real systems, not just written:

| Component | Verification |
|---|---|
| `linux/audit.sh` | Debian 12, Rocky 9, Alpine 3.20 — valid JSON, correct exit codes |
| `linux/harden.sh` | Debian 12 — applied (score 50%→69%), `sshd -t` valid, rollback restored originals |
| `linux/patch.sh` | Debian 12 (apt) and Rocky 9 (dnf) — scan and install, converges to 0 pending |
| `vmctl.sh` vmrun transport | Live Windows 11 ARM64 VM |
| `vmctl.sh` SSH transport | Dockerised sshd — `ssh`, `lpush`, `lpull`, `lrun`, `lrun --sudo` |
| `Invoke-HardeningAudit.ps1` | Live VM — 61 checks, role detection |
| `Invoke-ADAudit.ps1` | Live VM — graceful degradation on a non-domain host |
| All PowerShell | Parsed with the PowerShell AST parser |
| All shell | `sh -n` and bash 3.2 syntax check |

Not yet verified: `run-elevated` end-to-end (needs the one-time in-guest
bootstrap), and the AD checks against a real domain controller — this lab
has no DC. The AD logic follows documented Microsoft attributes and the
standard ESC1–ESC4 definitions, but treat first use against a real domain
as validation.
