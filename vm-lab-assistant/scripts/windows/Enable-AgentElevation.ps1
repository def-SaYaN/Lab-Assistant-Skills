<#
.SYNOPSIS
    One-time bootstrap: create a scheduled task that lets the host run
    PowerShell scripts in the guest with full administrator rights.

.DESCRIPTION
    VMware guest operations (vmrun / VMware Tools) execute with a UAC-filtered
    token. Even when the account is in Administrators, commands run
    non-elevated and cannot touch HKLM policy keys, Defender settings,
    firewall policy, BitLocker, or optional Windows features.

    This script registers a scheduled task that runs as SYSTEM (or the
    specified principal) with HighestAvailable run level. The host then
    triggers it with `schtasks /Run`, and the task executes whatever script
    path is named in the control file:

        <GuestTmp>\task.cmdline     line 1 = script path, line 2 = arguments

    The task writes:
        <GuestTmp>\elevated.log     combined stdout/stderr
        <GuestTmp>\elevated.done    the exit code (sentinel for the host)

    RUN THIS ONCE, FROM AN ELEVATED POWERSHELL INSIDE THE GUEST.

.PARAMETER GuestTmp
    Working directory for control/log files. Default C:\Windows\Temp\vmctl

.PARAMETER TaskName
    Scheduled task name. Must match ELEV_TASK in vmctl.sh.

.PARAMETER RunAsUser
    Principal for the task. Default 'SYSTEM'. Use a named admin account if
    you need a user-context profile.

.PARAMETER AgentUser
    Account that vmrun authenticates as (GUEST_USER in .vmctl.env). It is
    granted Modify on GuestTmp so the host can drop task.cmdline there.
    Required because guest operations run with a UAC-filtered token, in
    which the Administrators group is deny-only, so an Administrators-only
    ACL would lock the host out. Defaults to the account running this
    script. Pass '' to grant nothing beyond SYSTEM and Administrators
    (only works when GUEST_USER is the unfiltered built-in Administrator).

.PARAMETER Remove
    Unregister the task and delete the working directory.

.SECURITY
    This is a deliberate, persistent local privilege-escalation path: anyone
    who can write <GuestTmp>\task.cmdline and trigger the task gets SYSTEM.
    The ACL below restricts the directory to SYSTEM, Administrators, and the
    single AgentUser account.
    Remove the task (-Remove) when the engagement ends. Do not use this on a
    production or internet-exposed host.

.EXAMPLE
    .\Enable-AgentElevation.ps1
.EXAMPLE
    .\Enable-AgentElevation.ps1 -Remove
#>
[CmdletBinding()]
param(
    [string] $GuestTmp  = 'C:\Windows\Temp\vmctl',
    [string] $TaskName  = 'VMCTL-Elevated',
    [string] $RunAsUser = 'SYSTEM',
    [string] $AgentUser = ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME),
    [switch] $Remove
)

$ErrorActionPreference = 'Stop'

function Test-Elevated {
    ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Elevated)) {
    Write-Error @"
This script must run ELEVATED.

Inside the VM:
  1. Start -> type 'powershell'
  2. Right-click 'Windows PowerShell' -> Run as administrator -> Yes
  3. cd to this script's folder and run it again.
"@
    exit 3
}

# ------------------------------------------------------------------ remove --

if ($Remove) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Output "Removed scheduled task: $TaskName"
    } else {
        Write-Output "Task not present: $TaskName"
    }
    if (Test-Path $GuestTmp) {
        Remove-Item -LiteralPath $GuestTmp -Recurse -Force -ErrorAction SilentlyContinue
        Write-Output "Removed working directory: $GuestTmp"
    }
    Write-Output 'Elevation bootstrap removed.'
    exit 0
}

# ------------------------------------------------------------- directory ----

New-Item -ItemType Directory -Force -Path $GuestTmp | Out-Null

# Lock the directory down: SYSTEM + Administrators full, plus Modify for the
# one account the host authenticates as. Without this, any local user could
# plant task.cmdline and get SYSTEM.
#
# The AgentUser grant is by user SID on purpose: vmrun guest operations carry
# a UAC-filtered token where BUILTIN\Administrators is deny-only, so the
# Administrators ACE alone would make every push into this directory fail
# with "Access is denied".
try {
    $acl = Get-Acl -LiteralPath $GuestTmp
    $acl.SetAccessRuleProtection($true, $false)   # disable inheritance, drop inherited
    foreach ($r in @($acl.Access)) { [void]$acl.RemoveAccessRule($r) }
    foreach ($id in @('NT AUTHORITY\SYSTEM','BUILTIN\Administrators')) {
        $acl.AddAccessRule(
            (New-Object System.Security.AccessControl.FileSystemAccessRule(
                $id, 'FullControl',
                'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    $granted = 'SYSTEM + Administrators'
    if ($AgentUser) {
        $acl.AddAccessRule(
            (New-Object System.Security.AccessControl.FileSystemAccessRule(
                $AgentUser, 'Modify',
                'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        $granted += " + $AgentUser (Modify)"
    }
    Set-Acl -LiteralPath $GuestTmp -AclObject $acl
    Write-Output "Hardened ACL on $GuestTmp ($granted)"
} catch {
    Write-Warning "Could not harden ACL on ${GuestTmp}: $($_.Exception.Message)"
}

# ------------------------------------------------------------- runner ps1 ---

# The runner is what the task actually executes. It reads the control file,
# runs the requested script, and writes the log + sentinel.
$runnerPath = Join-Path $GuestTmp 'elevated-runner.ps1'
$runner = @'
$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
$base    = Split-Path -Parent $MyInvocation.MyCommand.Path
$cmdFile = Join-Path $base 'task.cmdline'
$logFile = Join-Path $base 'elevated.log'
$doneFile= Join-Path $base 'elevated.done'

Remove-Item -LiteralPath $doneFile -Force -ErrorAction SilentlyContinue
$code = 0
try {
    if (-not (Test-Path $cmdFile)) { throw "control file not found: $cmdFile" }
    $lines  = @(Get-Content -LiteralPath $cmdFile)
    $script = $lines[0]
    $argline= if ($lines.Count -gt 1) { $lines[1] } else { '' }
    if (-not (Test-Path $script)) { throw "target script not found: $script" }

    # Let the PowerShell parser handle the argument line so named parameters,
    # switches, and quoted values bind exactly as they would when typed.
    # (Splatting a string array would bind '-Profile' as a positional VALUE,
    # not a parameter name, and every call with arguments would fail.)
    $global:LASTEXITCODE = $null
    $invoke = [scriptblock]::Create("& '" + $script.Replace("'", "''") + "' " + $argline)
    $out = & $invoke 2>&1 | Out-String -Width 400

    $code = if ($LASTEXITCODE -ne $null) { $LASTEXITCODE } else { 0 }
    $out | Set-Content -LiteralPath $logFile -Encoding UTF8
}
catch {
    $code = 1
    "ELEVATED RUNNER ERROR: $($_.Exception.Message)" |
        Set-Content -LiteralPath $logFile -Encoding UTF8
}
finally {
    "$code" | Set-Content -LiteralPath $doneFile -Encoding UTF8
}
'@
Set-Content -LiteralPath $runnerPath -Value $runner -Encoding UTF8
Write-Output "Wrote runner: $runnerPath"

# ---------------------------------------------------------------- task ------

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Output "Replaced existing task: $TaskName"
}

$psExe  = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$action = New-ScheduledTaskAction -Execute $psExe `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$runnerPath`""

$principal = if ($RunAsUser -eq 'SYSTEM') {
    New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
} else {
    New-ScheduledTaskPrincipal -UserId $RunAsUser -LogonType S4U -RunLevel Highest
}

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Hours 4)

Register-ScheduledTask -TaskName $TaskName -Action $action `
    -Principal $principal -Settings $settings `
    -Description 'Host-triggered elevated script runner for VM hardening toolkit.' | Out-Null

Write-Output "Registered scheduled task: $TaskName (RunAs=$RunAsUser, RunLevel=Highest)"

# ----------------------------------------------------------------- verify ---

$selfTest = Join-Path $GuestTmp 'selftest.ps1'
@'
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = [Security.Principal.WindowsPrincipal]$id
"Identity : $($id.Name)"
"Elevated : $($pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
'@ | Set-Content -LiteralPath $selfTest -Encoding UTF8

"$selfTest`r`n`r`n" | Set-Content -LiteralPath (Join-Path $GuestTmp 'task.cmdline') -Encoding ASCII
Start-ScheduledTask -TaskName $TaskName

$done = Join-Path $GuestTmp 'elevated.done'
$log  = Join-Path $GuestTmp 'elevated.log'
$ok = $false
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 1
    if (Test-Path $done) { $ok = $true; break }
}

Write-Output ''
if ($ok) {
    Write-Output '--- self-test output ---'
    if (Test-Path $log) { Get-Content -LiteralPath $log }
    Write-Output '------------------------'
    Write-Output 'SUCCESS: elevated runner is working.'
    Write-Output ''
    Write-Output 'From the host you can now run:'
    Write-Output '  ./scripts/vmctl.sh run-elevated scripts/windows/Invoke-Hardening.ps1 -Profile Baseline -WhatIf'
    Remove-Item -LiteralPath $done -Force -ErrorAction SilentlyContinue
    exit 0
} else {
    Write-Warning 'Self-test did not complete within 30s. Inspect:'
    Write-Warning "  Task Scheduler -> $TaskName -> History"
    Write-Warning "  $log"
    exit 1
}
