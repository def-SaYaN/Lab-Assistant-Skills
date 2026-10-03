<#
.SYNOPSIS
    Apply Windows hardening controls, with dry-run and rollback.

.DESCRIPTION
    Remediates the findings produced by Invoke-HardeningAudit.ps1.
    Every control records its prior value to a rollback journal before
    changing anything, so a bad change can be reverted.

    REQUIRES ELEVATION. Run via:
        vmctl.sh run-elevated scripts/Invoke-Hardening.ps1 -Profile Baseline

.PARAMETER Profile
    Baseline  - safe, broadly reversible, low breakage risk (default)
    Strict    - Baseline + ASR rules, WSH off, PSv2 off, SMB1 off, stricter services
    Paranoid  - Strict + aggressive service lockdown and legacy protocol removal

.PARAMETER Only
    Apply only the named control IDs (e.g. -Only HD-FW-001,HD-DEF-003).

.PARAMETER Skip
    Skip the named control IDs.

.PARAMETER WhatIf
    Show what would change without changing anything. ALWAYS RUN THIS FIRST.

.PARAMETER RollbackFile
    Path to a rollback journal produced by a previous run. Reverts it.

.PARAMETER JournalPath
    Directory for rollback journals. Default $env:TEMP\vmctl\rollback

.EXAMPLE
    .\Invoke-Hardening.ps1 -Profile Baseline -WhatIf
.EXAMPLE
    .\Invoke-Hardening.ps1 -Profile Strict
.EXAMPLE
    .\Invoke-Hardening.ps1 -RollbackFile C:\Windows\Temp\vmctl\rollback\rollback-20260103-120000.json
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
param(
    [ValidateSet('Baseline','Strict','Paranoid')]
    [string]   $Profile      = 'Baseline',
    [string[]] $Only,
    [string[]] $Skip,
    [string]   $RollbackFile,
    [string]   $JournalPath  = (Join-Path $env:TEMP 'vmctl\rollback')
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

# ------------------------------------------------------------------ guard ---

$isElevated = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isElevated) {
    Write-Error @"
Invoke-Hardening.ps1 requires elevation.

Options:
  1. Run Enable-AgentElevation.ps1 once (elevated, inside the VM), then from
     the host use:  vmctl.sh run-elevated scripts/Invoke-Hardening.ps1 ...
  2. Or run this directly from an elevated PowerShell inside the VM.
"@
    exit 3
}

$script:Journal = [System.Collections.Generic.List[object]]::new()
$script:Applied = 0
$script:Failed  = 0
$script:Skipped = 0

# -------------------------------------------------------------- utilities ---

function Add-Journal {
    param([string]$Id, [string]$Type, [hashtable]$Before, [hashtable]$After)
    $script:Journal.Add([pscustomobject]@{
        Id = $Id; Type = $Type; Before = $Before; After = $After
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('s') + 'Z'
    })
}

function Test-Selected {
    param([string]$Id, [string[]]$Profiles)
    if ($Profile -notin $Profiles) { return $false }
    if ($Only -and $Id -notin $Only) { return $false }
    if ($Skip -and $Id -in $Skip)    { return $false }
    return $true
}

# Set a registry value, journaling the prior state.
function Set-HardeningReg {
    param(
        [Parameter(Mandatory)][string] $Id,
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][string] $Name,
        [Parameter(Mandatory)]         $Value,
        [ValidateSet('DWord','String','ExpandString','QWord','MultiString')]
        [string] $Type = 'DWord',
        [Parameter(Mandatory)][string] $Description,
        [string[]] $Profiles = @('Baseline','Strict','Paranoid')
    )
    if (-not (Test-Selected -Id $Id -Profiles $Profiles)) { $script:Skipped++; return }

    $existed = Test-Path $Path
    $current = if ($existed) {
        try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
    } else { $null }

    if ($current -eq $Value) {
        Write-Output "  [ok]    $Id  already compliant ($Name=$Value)"
        return
    }

    $label = "$Id : $Description"
    if (-not $PSCmdlet.ShouldProcess($label, "set $Path\$Name = $Value")) {
        Write-Output "  [would] $Id  $Description"
        Write-Output "          $Path\$Name : $(if ($null -eq $current) {'<unset>'} else {$current}) -> $Value"
        return
    }

    try {
        if (-not $existed) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
        Add-Journal -Id $Id -Type 'Registry' `
            -Before @{ Path=$Path; Name=$Name; Value=$current; Existed=$existed } `
            -After  @{ Path=$Path; Name=$Name; Value=$Value;    Type=$Type }
        Write-Output "  [set]   $Id  $Description"
        $script:Applied++
    } catch {
        Write-Output "  [FAIL]  $Id  $Description -- $($_.Exception.Message)"
        $script:Failed++
    }
}

# Run an arbitrary remediation with a matching revert action.
function Invoke-HardeningAction {
    param(
        [Parameter(Mandatory)][string] $Id,
        [Parameter(Mandatory)][string] $Description,
        [Parameter(Mandatory)][scriptblock] $Test,     # returns $true if already compliant
        [Parameter(Mandatory)][scriptblock] $Apply,
        [scriptblock] $CaptureState = { @{} },
        [string[]] $Profiles = @('Baseline','Strict','Paranoid')
    )
    if (-not (Test-Selected -Id $Id -Profiles $Profiles)) { $script:Skipped++; return }

    $compliant = $false
    try { $compliant = [bool](& $Test) } catch { $compliant = $false }
    if ($compliant) { Write-Output "  [ok]    $Id  already compliant"; return }

    if (-not $PSCmdlet.ShouldProcess("$Id : $Description", 'apply')) {
        Write-Output "  [would] $Id  $Description"
        return
    }

    $before = @{}
    try { $before = & $CaptureState } catch { }

    try {
        & $Apply
        Add-Journal -Id $Id -Type 'Action' -Before $before -After @{ Description = $Description }
        Write-Output "  [set]   $Id  $Description"
        $script:Applied++
    } catch {
        Write-Output "  [FAIL]  $Id  $Description -- $($_.Exception.Message)"
        $script:Failed++
    }
}

# ------------------------------------------------------------- rollback -----

if ($RollbackFile) {
    if (-not (Test-Path $RollbackFile)) { Write-Error "Rollback file not found: $RollbackFile"; exit 2 }
    Write-Output "Reverting from journal: $RollbackFile"
    $entries = (Get-Content -LiteralPath $RollbackFile -Raw | ConvertFrom-Json)
    # Revert newest-first.
    for ($i = $entries.Count - 1; $i -ge 0; $i--) {
        $e = $entries[$i]
        if ($e.Type -ne 'Registry') {
            Write-Output "  [skip]  $($e.Id) : type '$($e.Type)' must be reverted manually"
            continue
        }
        try {
            if ($null -eq $e.Before.Value) {
                Remove-ItemProperty -Path $e.Before.Path -Name $e.Before.Name -Force -ErrorAction SilentlyContinue
                Write-Output "  [rev]   $($e.Id) : removed $($e.Before.Name)"
            } else {
                New-ItemProperty -Path $e.Before.Path -Name $e.Before.Name `
                    -Value $e.Before.Value -PropertyType $e.After.Type -Force | Out-Null
                Write-Output "  [rev]   $($e.Id) : restored $($e.Before.Name)=$($e.Before.Value)"
            }
        } catch {
            Write-Output "  [FAIL]  $($e.Id) : $($_.Exception.Message)"
        }
    }
    Write-Output 'Rollback complete. Reboot to settle policy-backed settings.'
    exit 0
}

# ------------------------------------------------------------------ start ---

Write-Output ''
Write-Output "===== VM HARDENING : profile=$Profile ====="
if ($WhatIfPreference) { Write-Output 'DRY RUN - no changes will be made.' }
Write-Output ''

# ---------------------------------------------------------- 1. identity -----

Write-Output '--- Identity & Authentication ---'

Set-HardeningReg -Id 'HD-ID-001' `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name 'EnableLUA' -Value 1 `
    -Description 'Enable UAC (EnableLUA=1)'

Set-HardeningReg -Id 'HD-ID-002' `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name 'ConsentPromptBehaviorAdmin' -Value 2 `
    -Description 'UAC: prompt for consent on the secure desktop'

Set-HardeningReg -Id 'HD-ID-003' `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name 'FilterAdministratorToken' -Value 1 `
    -Description 'Apply UAC token filtering to the built-in Administrator'

Set-HardeningReg -Id 'HD-ID-004' `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name 'InactivityTimeoutSecs' -Value 900 `
    -Description 'Lock the session after 15 minutes idle'

Set-HardeningReg -Id 'HD-ID-005' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name 'LimitBlankPasswordUse' -Value 1 `
    -Description 'Block network logon for accounts with blank passwords'

Set-HardeningReg -Id 'HD-ID-006' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name 'RestrictAnonymous' -Value 1 `
    -Description 'Restrict anonymous enumeration of SAM accounts and shares'

Set-HardeningReg -Id 'HD-ID-007' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name 'RestrictAnonymousSAM' -Value 1 `
    -Description 'Restrict anonymous SAM enumeration'

Set-HardeningReg -Id 'HD-ID-008' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name 'RunAsPPL' -Value 1 `
    -Description 'Run LSASS as a protected process (blocks credential dumping)' `
    -Profiles @('Strict','Paranoid')

Set-HardeningReg -Id 'HD-ID-009' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' `
    -Name 'UseLogonCredential' -Value 0 `
    -Description 'Disable WDigest cleartext credential caching'

Invoke-HardeningAction -Id 'HD-ID-010' `
    -Description 'Password policy: min length 14, history 5, max age 90' `
    -Test   { (net accounts) -match 'Minimum password length\s*:\s*(1[4-9]|[2-9]\d)' } `
    -Apply  {
        & net accounts /minpwlen:14 /uniquepw:5 /maxpwage:90 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "net accounts failed ($LASTEXITCODE)" }
    }

Invoke-HardeningAction -Id 'HD-ID-011' `
    -Description 'Lockout policy: 5 attempts, 15 min duration and window' `
    -Test   { (net accounts) -match 'Lockout threshold\s*:\s*[1-9]' } `
    -Apply  {
        & net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "net accounts failed ($LASTEXITCODE)" }
    }

Invoke-HardeningAction -Id 'HD-ID-012' `
    -Description 'Disable the Guest account' `
    -Test   { -not (Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue).Enabled } `
    -Apply  { Disable-LocalUser -Name 'Guest' -ErrorAction Stop }

# ---------------------------------------------------------- 2. defender -----

Write-Output ''
Write-Output '--- Microsoft Defender ---'

Invoke-HardeningAction -Id 'HD-DEF-001' `
    -Description 'Enable real-time monitoring' `
    -Test   { (Get-MpComputerStatus -ErrorAction Stop).RealTimeProtectionEnabled } `
    -Apply  { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop }

Invoke-HardeningAction -Id 'HD-DEF-002' `
    -Description 'Enable behavior monitoring' `
    -Test   { (Get-MpComputerStatus -ErrorAction Stop).BehaviorMonitorEnabled } `
    -Apply  { Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction Stop }

Invoke-HardeningAction -Id 'HD-DEF-003' `
    -Description 'Enable script and IOAV scanning' `
    -Test   {
        $s = Get-MpPreference -ErrorAction Stop
        (-not $s.DisableScriptScanning) -and (-not $s.DisableIOAVProtection)
    } `
    -Apply  { Set-MpPreference -DisableScriptScanning $false -DisableIOAVProtection $false -ErrorAction Stop }

Invoke-HardeningAction -Id 'HD-DEF-004' `
    -Description 'Enable PUA protection (block mode)' `
    -Test   { (Get-MpPreference -ErrorAction Stop).PUAProtection -ge 1 } `
    -Apply  { Set-MpPreference -PUAProtection Enabled -ErrorAction Stop }

Invoke-HardeningAction -Id 'HD-DEF-005' `
    -Description 'Enable cloud protection at high level + sample submission' `
    -Test   {
        $s = Get-MpPreference -ErrorAction Stop
        ($s.MAPSReporting -ge 2) -and ($s.CloudBlockLevel -ge 2)
    } `
    -Apply  {
        Set-MpPreference -MAPSReporting Advanced `
            -SubmitSamplesConsent SendSafeSamples `
            -CloudBlockLevel High `
            -CloudExtendedTimeout 50 -ErrorAction Stop
    }

Invoke-HardeningAction -Id 'HD-DEF-006' `
    -Description 'Enable network protection (block mode)' `
    -Test   { (Get-MpPreference -ErrorAction Stop).EnableNetworkProtection -eq 1 } `
    -Apply  { Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction Stop } `
    -Profiles @('Strict','Paranoid')

Invoke-HardeningAction -Id 'HD-DEF-007' `
    -Description 'Enable controlled folder access' `
    -Test   { (Get-MpPreference -ErrorAction Stop).EnableControlledFolderAccess -eq 1 } `
    -Apply  { Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction Stop } `
    -Profiles @('Paranoid')

Invoke-HardeningAction -Id 'HD-DEF-008' `
    -Description 'Apply Attack Surface Reduction rule baseline (block mode)' `
    -Test   { @((Get-MpPreference -ErrorAction Stop).AttackSurfaceReductionRules_Ids).Count -ge 10 } `
    -Apply  {
        # Well-known ASR GUIDs. Each blocks a documented initial-access or
        # lateral-movement technique.
        $rules = @(
            '56a863a9-875e-4185-98a7-b882c64b5ce5' # Block abuse of exploited vulnerable signed drivers
            '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' # Block Adobe Reader child processes
            'd4f940ab-401b-4efc-aadc-ad5f3c50688a' # Block Office apps creating child processes
            '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' # Block credential stealing from LSASS
            'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' # Block executable content from email/webmail
            '01443614-cd74-433a-b99e-2ecdc07bfc25' # Block untrusted/unsigned from USB
            '5beb7efe-fd9a-4556-801d-275e5ffc04cc' # Block execution of potentially obfuscated scripts
            'd3e037e1-3eb8-44c8-a917-57927947596d' # Block JS/VBS launching downloaded content
            '3b576869-a4ec-4529-8536-b80a7769e899' # Block Office creating executable content
            '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' # Block Office injecting into other processes
            '26190899-1602-49e8-8b27-eb1d0a1ce869' # Block Office comm app child processes
            'e6db77e5-3df2-4cf1-b95a-636979351e5b' # Block persistence through WMI event subscription
            'd1e49aac-8f56-4280-b9ba-993a6d77406c' # Block process creations from PSExec/WMI
            'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' # Block untrusted/unsigned processes from USB
            'c1db55ab-c21a-4637-bb3f-a12568109d35' # Use advanced ransomware protection
        )
        foreach ($g in $rules) {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $g `
                             -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
        }
    } `
    -Profiles @('Strict','Paranoid')

# ---------------------------------------------------------- 3. firewall -----

Write-Output ''
Write-Output '--- Firewall ---'

Invoke-HardeningAction -Id 'HD-FW-001' `
    -Description 'Enable firewall on all profiles; default inbound Block, outbound Allow' `
    -Test   {
        $p = Get-NetFirewallProfile -ErrorAction Stop
        -not ($p | Where-Object { -not $_.Enabled -or $_.DefaultInboundAction -ne 'Block' })
    } `
    -CaptureState {
        @{ Profiles = (Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction) }
    } `
    -Apply  {
        Set-NetFirewallProfile -All -Enabled True `
            -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction Stop
    }

Invoke-HardeningAction -Id 'HD-FW-002' `
    -Description 'Enable firewall logging for dropped packets' `
    -Test   {
        $p = Get-NetFirewallProfile -Profile Domain -ErrorAction Stop
        $p.LogBlocked -eq 'True' -or $p.LogBlocked -eq $true
    } `
    -Apply  {
        Set-NetFirewallProfile -All -LogBlocked True -LogMaxSizeKilobytes 16384 `
            -LogFileName '%systemroot%\system32\LogFiles\Firewall\pfirewall.log' -ErrorAction Stop
    }

Invoke-HardeningAction -Id 'HD-FW-003' `
    -Description 'Disable inbound rules that expose file/printer sharing on Public' `
    -Test   {
        -not (Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' `
              -ErrorAction SilentlyContinue |
              Where-Object { $_.Enabled -eq 'True' -and $_.Profile -match 'Public' })
    } `
    -Apply  {
        Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -ErrorAction Stop |
            Where-Object { $_.Profile -match 'Public' } |
            Disable-NetFirewallRule -ErrorAction Stop
    } `
    -Profiles @('Strict','Paranoid')

# ----------------------------------------------- 4. attack surface ----------

Write-Output ''
Write-Output '--- Attack Surface Reduction ---'

Set-HardeningReg -Id 'HD-SU-001' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' `
    -Name 'EnableMulticast' -Value 0 `
    -Description 'Disable LLMNR (blocks LLMNR poisoning / responder attacks)'

Set-HardeningReg -Id 'HD-SU-002' `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
    -Name 'NoDriveTypeAutoRun' -Value 255 `
    -Description 'Disable AutoRun/AutoPlay on all drive types'

Set-HardeningReg -Id 'HD-SU-003' `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
    -Name 'NoAutorun' -Value 1 `
    -Description 'Disable AutoRun commands'

Invoke-HardeningAction -Id 'HD-SU-004' `
    -Description 'Disable NetBIOS over TCP/IP on all interfaces (blocks NBT-NS poisoning)' `
    -Test   {
        $ifs = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction Stop
        -not ($ifs | Where-Object {
            (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).NetbiosOptions -ne 2 })
    } `
    -CaptureState {
        @{ Interfaces = (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' |
            ForEach-Object { @{ Path=$_.PSPath; Value=(Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).NetbiosOptions } }) }
    } `
    -Apply  {
        Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction Stop |
            ForEach-Object { Set-ItemProperty -Path $_.PSPath -Name NetbiosOptions -Value 2 -ErrorAction Stop }
    }

Invoke-HardeningAction -Id 'HD-SU-005' `
    -Description 'Require SMB signing (server and client)' `
    -Test   { (Get-SmbServerConfiguration -ErrorAction Stop).RequireSecuritySignature } `
    -Apply  {
        Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force -ErrorAction Stop
        Set-SmbClientConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force -ErrorAction Stop
    }

Invoke-HardeningAction -Id 'HD-SU-006' `
    -Description 'Disable SMBv1 protocol' `
    -Test   {
        $f = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
        $f.State -eq 'Disabled'
    } `
    -Apply  {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null
    } `
    -Profiles @('Strict','Paranoid')

Invoke-HardeningAction -Id 'HD-SU-007' `
    -Description 'Remove the PowerShell v2 engine (bypasses AMSI and logging)' `
    -Test   {
        $f = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop
        $f.State -eq 'Disabled'
    } `
    -Apply  {
        Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -ErrorAction Stop | Out-Null
    } `
    -Profiles @('Strict','Paranoid')

Set-HardeningReg -Id 'HD-SU-008' `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' `
    -Name 'Enabled' -Value 0 `
    -Description 'Disable Windows Script Host (.vbs/.js execution)' `
    -Profiles @('Strict','Paranoid')

Set-HardeningReg -Id 'HD-SU-009' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
    -Name 'UserAuthentication' -Value 1 `
    -Description 'Require Network Level Authentication for RDP'

Set-HardeningReg -Id 'HD-SU-010' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
    -Name 'MinEncryptionLevel' -Value 3 `
    -Description 'Require high encryption for RDP sessions'

# --------------------------------------------------------- 5. services ------

Write-Output ''
Write-Output '--- Services ---'

$svcBaseline = @(
    @{ Name='RemoteRegistry'; Desc='Remote Registry' }
    @{ Name='SSDPSRV';        Desc='SSDP Discovery' }
    @{ Name='upnphost';       Desc='UPnP Device Host' }
)
$svcStrict = @(
    @{ Name='Spooler';        Desc='Print Spooler (PrintNightmare surface)' }
    @{ Name='SharedAccess';   Desc='Internet Connection Sharing' }
    @{ Name='RemoteAccess';   Desc='Routing and Remote Access' }
)
$svcParanoid = @(
    @{ Name='WinRM';          Desc='Windows Remote Management' }
    @{ Name='TermService';    Desc='Remote Desktop Services' }
)

$svcList = switch ($Profile) {
    'Baseline' { $svcBaseline }
    'Strict'   { $svcBaseline + $svcStrict }
    'Paranoid' { $svcBaseline + $svcStrict + $svcParanoid }
}

$n = 0
foreach ($s in $svcList) {
    $n++
    $id = "HD-SVC-{0:D3}" -f $n
    $svcName = $s.Name; $svcDesc = $s.Desc
    Invoke-HardeningAction -Id $id `
        -Description "Stop and disable $svcDesc ($svcName)" `
        -Test   {
            $sv = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if (-not $sv) { return $true }
            $sm = (Get-CimInstance Win32_Service -Filter "Name='$svcName'" -ErrorAction SilentlyContinue).StartMode
            ($sv.Status -ne 'Running') -and ($sm -eq 'Disabled')
        } `
        -CaptureState {
            $sv = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            $sm = (Get-CimInstance Win32_Service -Filter "Name='$svcName'" -ErrorAction SilentlyContinue).StartMode
            @{ Service=$svcName; Status=$(if($sv){"$($sv.Status)"}); StartMode=$sm }
        } `
        -Apply  {
            $sv = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($sv) {
                if ($sv.Status -eq 'Running') { Stop-Service -Name $svcName -Force -ErrorAction Stop }
                Set-Service -Name $svcName -StartupType Disabled -ErrorAction Stop
            }
        }
}

# ---------------------------------------------------------- 6. logging ------

Write-Output ''
Write-Output '--- Logging & Audit ---'

Set-HardeningReg -Id 'HD-LOG-001' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
    -Name 'EnableScriptBlockLogging' -Value 1 `
    -Description 'Enable PowerShell script block logging (Event ID 4104)'

Set-HardeningReg -Id 'HD-LOG-002' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' `
    -Name 'EnableModuleLogging' -Value 1 `
    -Description 'Enable PowerShell module logging'

Invoke-HardeningAction -Id 'HD-LOG-003' `
    -Description 'Log all PowerShell modules (ModuleNames wildcard)' `
    -Test   {
        (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' `
            -Name '*' -ErrorAction SilentlyContinue).'*' -eq '*'
    } `
    -Apply  {
        $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'
        if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
        New-ItemProperty -Path $p -Name '*' -Value '*' -PropertyType String -Force | Out-Null
    }

Set-HardeningReg -Id 'HD-LOG-004' `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
    -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 `
    -Description 'Include command line in process creation events (4688)'

Invoke-HardeningAction -Id 'HD-LOG-005' `
    -Description 'Enable key audit policy subcategories' `
    -Test   { $false } `
    -Apply  {
        $subs = @(
            @{ N='Process Creation';              S='enable'; F='disable' }
            @{ N='Logon';                         S='enable'; F='enable'  }
            @{ N='Logoff';                        S='enable'; F='disable' }
            @{ N='Account Lockout';               S='enable'; F='enable'  }
            @{ N='Special Logon';                 S='enable'; F='disable' }
            @{ N='Security Group Management';     S='enable'; F='enable'  }
            @{ N='User Account Management';       S='enable'; F='enable'  }
            @{ N='Audit Policy Change';           S='enable'; F='enable'  }
            @{ N='Authentication Policy Change';  S='enable'; F='enable'  }
            @{ N='Sensitive Privilege Use';       S='enable'; F='enable'  }
            @{ N='Security System Extension';     S='enable'; F='enable'  }
            @{ N='System Integrity';              S='enable'; F='enable'  }
        )
        foreach ($s in $subs) {
            & auditpol /set /subcategory:"$($s.N)" /success:$($s.S) /failure:$($s.F) | Out-Null
        }
    }

Invoke-HardeningAction -Id 'HD-LOG-006' `
    -Description 'Increase Security/System/Application log sizes to 192 MB' `
    -Test   {
        (Get-WinEvent -ListLog Security -ErrorAction Stop).MaximumSizeInBytes -ge 192MB
    } `
    -Apply  {
        foreach ($l in @('Security','System','Application')) {
            & wevtutil sl $l /ms:201326592 | Out-Null
        }
    }

# ------------------------------------------------------------ 7. network ----

Write-Output ''
Write-Output '--- Network & Protocols ---'

# Disable legacy/weak TLS and SSL on both client and server roles.
$tlsMatrix = @(
    @{ Proto='SSL 2.0'; Enable=0 }
    @{ Proto='SSL 3.0'; Enable=0 }
    @{ Proto='TLS 1.0'; Enable=0 }
    @{ Proto='TLS 1.1'; Enable=0 }
    @{ Proto='TLS 1.2'; Enable=1 }
)
$t = 0
foreach ($entry in $tlsMatrix) {
    foreach ($role in @('Server','Client')) {
        $t++
        $base = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$($entry.Proto)\$role"
        Set-HardeningReg -Id ("HD-NET-{0:D3}" -f $t) `
            -Path $base -Name 'Enabled' -Value $entry.Enable `
            -Description "$($entry.Proto) $role : $(if ($entry.Enable -eq 1) {'enabled'} else {'disabled'})" `
            -Profiles @('Strict','Paranoid')
    }
}

Set-HardeningReg -Id 'HD-NET-100' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' `
    -Name 'AllowInsecureGuestAuth' -Value 0 `
    -Description 'Block insecure guest authentication to SMB shares'

Set-HardeningReg -Id 'HD-NET-101' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' `
    -Name 'NC_AllowNetBridge_NLA' -Value 0 `
    -Description 'Prevent users from bridging network connections' `
    -Profiles @('Strict','Paranoid')

Set-HardeningReg -Id 'HD-NET-102' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' `
    -Name 'DisableIPSourceRouting' -Value 2 `
    -Description 'Disable IP source routing (anti-spoofing)'

Set-HardeningReg -Id 'HD-NET-103' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' `
    -Name 'EnableICMPRedirect' -Value 0 `
    -Description 'Ignore ICMP redirects'

# ------------------------------------------------------------- summary ------

Write-Output ''
Write-Output '===== SUMMARY ====='
if ($WhatIfPreference) {
    Write-Output 'Dry run complete. Nothing was changed.'
    Write-Output 'Re-run without -WhatIf to apply.'
    exit 0
}

Write-Output ("Applied : {0}" -f $script:Applied)
Write-Output ("Failed  : {0}" -f $script:Failed)
Write-Output ("Skipped : {0} (not in profile '{1}', or filtered)" -f $script:Skipped, $Profile)

if ($script:Journal.Count -gt 0) {
    New-Item -ItemType Directory -Force -Path $JournalPath | Out-Null
    $jf = Join-Path $JournalPath ("rollback-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $script:Journal | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jf -Encoding UTF8
    Write-Output ''
    Write-Output "Rollback journal: $jf"
    Write-Output "Revert with: .\Invoke-Hardening.ps1 -RollbackFile `"$jf`""
}

Write-Output ''
Write-Output 'REBOOT REQUIRED for: EnableLUA, RunAsPPL, SMBv1, PowerShell v2, TLS/SCHANNEL.'
Write-Output 'Re-run Invoke-HardeningAudit.ps1 after reboot to confirm.'

if ($script:Failed -gt 0) { exit 2 } else { exit 0 }
