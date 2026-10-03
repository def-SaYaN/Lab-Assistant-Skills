# Troubleshooting

Every entry below was hit and solved on a real VMware Fusion 26.0.1 /
Windows 11 ARM64 / VMware Tools 13349 build. Symptoms are quoted verbatim so
they can be matched by search.

---

## 1. Guest execution

### `vmrun` returns exit code 1 and produces no output when running PowerShell

**Symptom**
```
Guest program exited with non-zero exit code: 1
Error: A file was not found
```
…yet `cmd.exe` works fine through the same `vmrun` call.

**Cause** — Invoking `powershell.exe` *directly* as the `runProgramInGuest`
program fails on Windows 11 ARM64. `cmd.exe` as the program works.

**Fix** — Always route through `cmd /c`:
```bash
vmrun ... runProgramInGuest "$VMX" -interactive 'C:\Windows\System32\cmd.exe' \
  '/c C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -Command "..."'
```
`vmctl.sh` does this for you.

---

### `A positional parameter cannot be found that accepts argument ' '`

**Cause** — `powershell.exe -File script.ps1` invoked via `cmd /c` receives a
stray empty argument. PowerShell binds it positionally and fails. It happens
even with no arguments.

**Fix** — Use `-Command "& 'script' args"` instead of `-File`:
```bash
powershell.exe -NoProfile -Command "& 'C:\path\script.ps1' -Scan"
```

---

### Output is mojibake (`믯䒿卅呋偏`)

**Cause** — Windows PowerShell 5.1 writes UTF-16LE for `>` redirection, but
`Set-Content -Encoding UTF8` writes UTF-8 **with BOM**. Decoding one as the
other produces CJK garbage.

**Fix** — Sniff the BOM before converting. `vmctl.sh _decode()` handles
`ff fe` (UTF-16LE), `fe ff` (UTF-16BE), `ef bb bf` (UTF-8 BOM), and a
no-BOM UTF-16LE heuristic.

---

### Output contains `#< CLIXML` and `<Objs Version=...>`

**Cause** — PowerShell serialises progress records to stderr.

**Fix** — Set `$ProgressPreference = 'SilentlyContinue'` at the top of every
remote snippet.

---

### `Command requires valid user name and password for the guest OS`

**Cause** — Guest ops attempted without `-gu` / `-gp`, or wrong credentials.

**Fix** — Set `GUEST_USER` / `GUEST_PASS`. Use `.\user` or `HOST\user` for a
local account if plain `user` is ambiguous.

---

### `Anonymous guest operations are not allowed`

**Cause** — Guest ops before VMware Tools is up — e.g. during firmware boot or
Windows Setup.

**Fix** — `vmctl.sh wait-tools 180`. During WinPE/Setup there is no Tools, so
no guest ops are possible at all.

---

## 2. Privileges

### Everything fails with `Access is denied` even though the user is an admin

**Symptom**
```
certutil -addstore -f Root cert.cer
  → Administrator permissions are needed to use the selected options.
  → CertUtil: -addstore command FAILED: 0x80070005 ERROR_ACCESS_DENIED
```
but `whoami /groups` shows `BUILTIN\Administrators`.

**Cause** — VMware guest ops get a **UAC-filtered token**. Group membership is
present but the admin privileges are stripped. `IsInRole(Administrator)`
returns `False`.

**Confirm**
```bash
./scripts/vmctl.sh whoami     # Elevated=False
```

**Fix** — Three options, in order of preference:

1. **Scheduled-task runner** (keeps UAC on):
   ```powershell
   .\Enable-AgentElevation.ps1     # once, elevated, inside the guest
   ```
   then `vmctl.sh run-elevated ...`
2. **Disable UAC** (blunt, needs reboot):
   ```
   reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
   ```
3. **Run interactively** in an elevated PowerShell inside the guest.

> `LocalAccountTokenFilterPolicy=1` only affects *remote* logons. It does
> **not** elevate VMware guest ops.

---

### `C:\Windows\Temp` is not writable

**Cause** — Non-elevated token.

**Fix** — Use `C:\Users\<user>\AppData\Local\Temp`, or set
`GUEST_TMP` accordingly.

---

## 3. VMX configuration

### Edits to the `.vmx` vanish on power-on

**Cause** — Fusion rewrites the VMX at power-on and **silently drops keys it
considers invalid**. Confirmed losses: `vtpm.present`, a second CD-ROM on the
same SATA controller (`sata0:1`).

**Fix** — Re-read the file after starting and confirm the key survived:
```bash
grep -n 'vtpm.present' "$VMX" || echo "STRIPPED"
```
For a second CD-ROM, use a *separate controller*: `sata1:0`, not `sata0:1`.

---

### `Cannot read the virtual machine configuration file`

**Cause** — A stale `vmware-vmx` process still holds the lock. The VMX itself
is fine.

**Fix**
```bash
pgrep -fl vmware-vmx
kill -9 <pid>
rm -rf "<vmdir>"/*.lck
```

---

### `vmrun stop ... soft` hangs forever

**Cause** — Soft stop needs VMware Tools. Without it, `vmrun` waits
indefinitely.

**Fix** — `vmctl.sh stop` backgrounds the soft stop, enforces a deadline, then
escalates to `hard`, then `kill -9`.

---

### VM powers on but shows `No operating system was found`

**Cause** — One of:
- the `nvram` file cached a failed EFI boot entry (file is named `nvram`, with
  **no extension** — a `*.nvram` glob misses it)
- boot order points at an empty device
- the ISO needs a keypress at *"Press any key to boot from CD"* and timed out

**Fix**
```bash
rm -f "<vmdir>/nvram"
# then set boot order explicitly
bios.bootOrder = "hdd,cdrom"
```

---

### Windows installed successfully but Setup keeps restarting

**Cause** — Boot order still prefers the CD, so Setup relaunches from the ISO
while the installed OS on disk is never reached.

**Confirm** — Scan the VMDK for an installed system:
```bash
# look for: EFI PART, NTFS, BCD, bootmgfw
python3 -c "..."   # see session transcript
```
Growth beyond ~15 GB plus `bootmgfw.efi` means Windows is installed.

**Fix**
```
sata0:0.startConnected = "FALSE"
bios.bootOrder         = "hdd,cdrom"
```

---

## 4. Install-time blockers

### `This PC can't run Windows 11` / `This PC must support TPM 2.0`

**Cause** — No vTPM. Fusion will not attach one unless the VM is **encrypted
first** — `vtpm.present = "TRUE"` alone is silently discarded.

**Fix A (proper)** — VM Settings → Encryption → set a password → add the TPM
device.

**Fix B (lab bypass)** — At the error screen press `Shift`+`F10` (on a Mac
keyboard `Shift`+`fn`+`F10`):
```
reg add HKLM\SYSTEM\Setup\LabConfig /v BypassTPMCheck /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\Setup\LabConfig /v BypassSecureBootCheck /t REG_DWORD /d 1 /f
```
then **Back**, then **Next**.

**Fix C (unattended)** — Attach a second tiny ISO containing
`autounattend.xml` with those `LabConfig` keys in a `windowsPE` /
`RunSynchronous` block. Mount it on a *separate controller* (`sata1:0`).

---

### Setup shows "Install driver" and lists no disks

**Check whether the disk is genuinely missing before loading any driver.**

```bash
ls -l "<vmdir>"/*.vmdk          # is it growing?
grep -i "DISKLIB-LIB.*numIOs" "<vmdir>/vmware.log"
```
Growth and rising I/O counts mean storage works and no driver is needed.

**Real cause (if the disk is truly absent)** — adapter mismatch. A VMDK
created with `-a lsilogic` attached to an **NVMe** controller may enumerate
the controller but no namespace. Telltale: NVMe resets in the log with no
namespace lines.

**Fix** — Put the disk on SATA, which Windows 11 ARM64 supports natively:
```
sata0:2.present    = "TRUE"
sata0:2.deviceType = "disk"
sata0:2.fileName   = "disk.vmdk"
```

> Note: a second CD-ROM can also make Setup render that dialog. Try removing
> it before assuming a driver problem.

---

### Setup dialog buttons are off-screen

**Cause** — WinPE runs at 1024x768 from the EFI framebuffer. `svga.maxWidth` /
`svga.maxHeight` have **no effect** during Setup; they only apply once Tools
is installed.

**Fix** — `Escape` to dismiss, drag the dialog by its title bar, `Alt`+`N` for
Next, or `Shift`+`F10` for a command prompt that always works.

---

## 5. Post-install

### Black screen after installing VMware Tools

**Cause** — The Tools 3D/WDDM driver (`vm3dmp.sys`) can hang the display on
Apple Silicon. The log shows `VM3DService ... Exit` followed by Tools going
unresponsive.

**Fix**
```
mks.enable3d = "FALSE"
```
Then restart. The guest loses 3D acceleration but boots reliably.

---

### No network adapter in Windows

**Cause** — `e1000e` has no in-box driver on Windows 11 ARM64.

**Fix** — Switch to `vmxnet3` (driver ships with VMware Tools):
```
ethernet0.virtualDev = "vmxnet3"
```
If Tools is not installed yet, build a driver ISO from
`/Applications/VMware Fusion.app/Contents/Library/isoimages/arm64/drivers-arm64.zip`
and point the "Install driver" browse dialog at the `vmxnet3` folder.

---

### Browser shows `ERR_CERT_AUTHORITY_INVALID` behind a TLS-inspecting proxy

**Cause** — Corporate proxies (Zscaler, Netskope, Palo Alto) re-sign TLS. The
host trusts the proxy root CA; a fresh guest does not.

**Fix** — Export the root CA from the host and install it in the guest's
machine store:
```bash
# macOS host
security find-certificate -a -c "Zscaler Root CA" -p \
  /Library/Keychains/System.keychain > root.pem
./scripts/vmctl.sh push root.pem 'C:\Users\<u>\Desktop\root.cer'
```
```powershell
# guest, ELEVATED
certutil -addstore -f Root C:\Users\<u>\Desktop\root.cer
```
Fully restart the browser. Edge and Chrome use the Windows store; Firefox
needs `security.enterprise_roots.enabled = true`.

> **Do not switch NAT→bridged to "fix" this.** On a corporate network the
> traffic is inspected either way, and bypassing inspection is a policy
> decision, not a technical workaround.

---

### `getGuestIPAddress` returns an error but the guest has network

**Cause** — Tools reports the IP only after the network stack settles.

**Fix** — Retry, or `vmctl.sh status` after `wait-tools`.

---

## 6. Audit result interpretation

| Result | Meaning |
|--------|---------|
| `Unknown` + "Access denied" | Needs elevation. Re-run via `run-elevated`. |
| `FW-004` Warn, `NotConfigured` | Not a failure. Windows defaults inbound to Block; the policy is simply not explicit. |
| `BL-002` Fail, `Present=; Ready=` | No vTPM. Host-side fix. |
| `DF-005` Fail, large signature age | Offline or never updated. `-SignaturesOnly`. |
| `HV-002` Warn, `VBS status=0` | Needs nested virtualization + vTPM. |

---

## 7. Hypervisor quick reference

| Task | VMware Fusion / Workstation |
|------|------------------------------|
| List running | `vmrun list` |
| Tools state | `vmrun checkToolsState <vmx>` |
| Guest IP | `vmrun getGuestIPAddress <vmx>` |
| Snapshot | `vmrun snapshot <vmx> <name>` |
| Revert | `vmrun revertToSnapshot <vmx> <name>` |
| Copy in | `vmrun -gu U -gp P CopyFileFromHostToGuest <vmx> <src> <dst>` |
| Copy out | `vmrun -gu U -gp P CopyFileFromGuestToHost <vmx> <src> <dst>` |
| Run program | `vmrun -gu U -gp P runProgramInGuest <vmx> -interactive <exe> <args>` |
| Disk tool | `.../Contents/Library/vmware-vdiskmanager` (note: **Library**, not Public) |

Equivalents on other platforms: Hyper-V `PowerShell Direct`
(`Invoke-Command -VMName`), VirtualBox `VBoxManage guestcontrol`,
Proxmox/KVM `qm guest exec`. The PowerShell scripts in this toolkit are
hypervisor-agnostic; only `vmctl.sh` is VMware-specific.
