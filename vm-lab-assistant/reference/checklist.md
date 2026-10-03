# End-to-End Hardening Checklist

Four target paths. Phases 0–1 and 5 are shared; pick the middle phases that
match your guest.

Legend: `[H]` host, `[G]` in-guest, `[M]` manual/UI.

---

## Phase 0 — Establish control (all targets)

| # | Step | Command | Done when |
|---|---|---|---|
| 0.1 | Config present | `[H] ./scripts/vmctl.sh env` | `VMRUN` resolves; creds set |
| 0.2 | Guest reachable | `[H] ./scripts/vmctl.sh status` | `running=yes`, `tools=running` |
| 0.3 | **Identify the target** | `[H] ./scripts/vmctl.sh detect` | OS family + DC status reported |
| 0.4 | Guest exec works | `[H] ./scripts/vmctl.sh whoami` (Win) / `ssh 'id'` (Linux) | identity printed |
| 0.5 | **Snapshot** | `[H] ./scripts/vmctl.sh snapshot pre-hardening` | listed in `snapshots` |

> For AD: snapshot **every** DC, not just the one you are changing.

---

## Phase 1 — Baseline audit (all targets)

| # | Step | Command |
|---|---|---|
| 1.1 | Hypervisor layer | `[H] ./scripts/vmctl.sh audit-host` |
| 1.2 | Guest audit | Windows: `run-script windows/Invoke-HardeningAudit.ps1`<br>Linux: `lrun linux/audit.sh` |
| 1.3 | AD audit (if DC) | `[H] run-elevated windows/Invoke-ADAudit.ps1` |
| 1.4 | Save baseline | pull `audit-latest.json` to the host |

Record the score. You will compare against it in Phase 5.

---

## Phase 2 — Elevation

### Windows

Guest ops run with a **UAC-filtered token**. Pick one:

| Option | Trade-off |
|---|---|
| **A. Scheduled-task runner (recommended)** | UAC stays on; host can trigger SYSTEM-level runs |
| B. Disable UAC (`EnableLUA=0`, reboot) | Simple, but every admin process is silently full-privilege |
| C. Run interactively in the guest | No persistent escalation path, no automation |

**Option A:**
1. `[M]` In the VM: Start → `powershell` → right-click → **Run as administrator**
2. `[G]` `.\Enable-AgentElevation.ps1`
3. Expect `SUCCESS: elevated runner is working.`
4. `[H]` Verify: `run-elevated windows/Invoke-HardeningAudit.ps1` → `elevated=True`

### Linux

`lrun --sudo` needs passwordless sudo or a configured askpass. Verify:

```bash
[H] ./scripts/vmctl.sh ssh 'sudo -n true && echo SUDO_OK'
```

---

## Phase 3 — Patch (before hardening)

| # | Step | Windows | Linux |
|---|---|---|---|
| 3.1 | Scan | `run-script windows/Invoke-Patching.ps1 -Scan` | `lrun linux/patch.sh --scan` |
| 3.2 | AV signatures | `run-elevated windows/Invoke-Patching.ps1 -SignaturesOnly` | n/a |
| 3.3 | Install | `run-elevated windows/Invoke-Patching.ps1 -Install` | `lrun --sudo linux/patch.sh --install` |
| 3.4 | Reboot | `[H] ./scripts/vmctl.sh restart` | same |
| 3.5 | Repeat | until the scan reports 0 pending | |

---

## Phase 4 — Harden

### 4A. Windows client / member server

```bash
[H] run-elevated windows/Invoke-Hardening.ps1 -Profile Baseline -WhatIf
[H] ./scripts/vmctl.sh snapshot pre-baseline-apply
[H] run-elevated windows/Invoke-Hardening.ps1 -Profile Baseline
[H] ./scripts/vmctl.sh restart
[H] run-elevated windows/Invoke-HardeningAudit.ps1
```

Then repeat with `-Profile Strict`, and `Paranoid` only if the VM is not
managed remotely.

### 4B. Active Directory domain controller

```bash
[H] run-elevated windows/Invoke-ADHardening.ps1 -Profile Baseline -WhatIf
[H] ./scripts/vmctl.sh snapshot pre-ad-apply       # every DC
[H] run-elevated windows/Invoke-ADHardening.ps1 -Profile Baseline
[H] ./scripts/vmctl.sh restart
[G] repadmin /replsummary                           # confirm convergence
[H] run-elevated windows/Invoke-ADAudit.ps1
```

Apply to **one DC at a time**. Let replication converge before the next.

Manual AD work the scripts deliberately do not automate:

| Task | Why manual |
|---|---|
| AD CS template fixes (ESC1–ESC4) | Correct fix depends on who legitimately enrols |
| krbtgt password reset | Must be done **twice**, waiting for replication between resets |
| Service accounts → gMSA | Requires per-application migration |
| LAPS deployment | Needs schema extension and GPO rollout |
| Tiered admin model | Organisational design, not a setting |

### 4C. Linux

```bash
[H] lrun --sudo linux/harden.sh --dry-run
[H] ./scripts/vmctl.sh snapshot pre-baseline-apply
[H] lrun --sudo linux/harden.sh --profile baseline
[H] ssh 'sudo sshd -t && echo SSHD_OK'        # BEFORE restarting sshd
[H] ssh 'sudo systemctl restart sshd'
```

> **Open a second SSH session and confirm login works before closing the
> first.** This is the most common way to lock yourself out of a lab box.

Then reboot for sysctl and module changes, and re-audit.

---

## Phase 5 — Verify and close out (all targets)

| # | Check |
|---|---|
| 5.1 | Score improved vs the Phase 1 baseline: `[H] ./scripts/vmctl.sh compare baseline.json after.json` |
| 5.2 | No regressions (`compare` exits 0) and no new `Fail` results |
| 5.3 | Guest still reachable (`status` / `ssh 'id'`) |
| 5.4 | Required applications still work |
| 5.5 | Remove the elevation task: `[G] .\Enable-AgentElevation.ps1 -Remove` |
| 5.6 | Rotate the bootstrap password |
| 5.7 | Final snapshot: `[H] ./scripts/vmctl.sh snapshot hardened-baseline` |

---

## Host-side items no guest script can fix

Surface them with `vmctl.sh audit-host`, fix in the VM settings UI.

| Item | Fix |
|---|---|
| Secure Boot off | VM Settings → firmware → enable |
| No vTPM | **Encrypt the VM first**, then add the TPM device |
| ISO still connected | `sata0:0.startConnected = "FALSE"` |
| Shared folders enabled | disable unless needed |
| Drag-and-drop / copy-paste | `isolation.tools.dnd.disable`, `isolation.tools.copy.disable` = `"TRUE"` |
| 3D acceleration | `mks.enable3d = "FALSE"` |
| Nested virtualization (for VBS) | `vhv.enable = "TRUE"` |

> Fusion silently strips VMX keys it dislikes. Re-read the file after every
> edit and confirm the key survived.

---

## Control coverage map

| Area | Windows audit | Windows harden | AD audit | Linux audit | Linux harden |
|---|---|---|---|---|---|
| Identity / auth | `ID-001`–`ID-010` | `HD-ID-*` | `AD-050`–`AD-059` | `ID-001`–`ID-011` | `HD-ID-*` |
| Patching | `PA-001`–`PA-006` | `Invoke-Patching` | — | `PA-001`–`PA-003` | `patch.sh` |
| Endpoint AV | `DF-001`–`DF-010` | `HD-DEF-*` | — | — | — |
| Firewall | `FW-001`–`FW-005` | `HD-FW-*` | — | `FW-001`–`FW-004` | `HD-FW-001` |
| Disk / boot | `BL-001`–`BL-003` | host-side | — | `BT-001`–`BT-003` | manual |
| Services | `SV-001`–`SV-008` | `HD-SVC-*` | `AD-086` | `SV-001`–`SV-014` | `HD-SV-*` |
| Attack surface | `SU-001`–`SU-008` | `HD-SU-*` | — | `KN-*`, `FS-*` | `HD-KN-*`, `HD-FS-*` |
| Logging / audit | `LG-*` | `HD-LOG-*` | `AD-087`, `ADH-030` | `LG-001`–`LG-005` | `HD-LG-*` |
| Network / TLS | `NW-001`–`NW-003` | `HD-NET-*` | `AD-083`–`AD-085` | `NW-001`, `KN-*` | `HD-KN-*` |
| Server role | `SR-001`–`SR-009` | — | `AD-080`–`AD-089` | — | — |
| Kerberos | — | — | `AD-040`–`AD-046` | — | — |
| AD CS | — | — | `AD-060`–`AD-065` | — | — |
| LAPS | — | — | `AD-070`–`AD-071` | — | — |
| Trusts / GPO | — | — | `AD-090`–`AD-102` | — | — |
| SSH | — | — | — | `SSH-001`–`SSH-011` | `HD-SSH-*` |
| MAC (SELinux/AppArmor) | — | — | — | `MAC-001`–`MAC-002` | manual |
| Hypervisor | `HV-001`–`HV-002` | `audit-host` | — | — | — |
