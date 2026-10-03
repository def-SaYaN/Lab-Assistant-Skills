<#
.SYNOPSIS
    Scan for, download, and install Windows updates plus Defender signatures.

.DESCRIPTION
    Uses the Windows Update COM API (Microsoft.Update.Session) directly, so it
    works on a stock image with no PSWindowsUpdate module and no internet
    access to the PowerShell Gallery.

    -Scan (default) is read-only and works non-elevated.
    -Install requires elevation.

.PARAMETER Scan
    List pending updates only. Default when no other mode is given.

.PARAMETER Install
    Download and install. REQUIRES ELEVATION.

.PARAMETER SignaturesOnly
    Update Defender signatures and skip Windows Update entirely.

.PARAMETER IncludeOptional
    Also include non-software updates (drivers). By default the search is
    limited to Type='Software'.

.PARAMETER MaxUpdates
    Cap how many updates to install in one pass. Default 0 (no cap).

.PARAMETER AutoReboot
    Reboot automatically if the install requires it.

.PARAMETER RebootDelaySeconds
    Delay before an automatic reboot. Default 60.

.PARAMETER OutputPath
    Directory for the JSON report. Default $env:TEMP\vmctl\patch

.EXAMPLE
    .\Invoke-Patching.ps1 -Scan
.EXAMPLE
    .\Invoke-Patching.ps1 -Install -AutoReboot
.EXAMPLE
    .\Invoke-Patching.ps1 -SignaturesOnly
#>
[CmdletBinding(DefaultParameterSetName='Scan')]
param(
    [Parameter(ParameterSetName='Scan')]    [switch] $Scan,
    [Parameter(ParameterSetName='Install')] [switch] $Install,
    [switch] $SignaturesOnly,
    [switch] $IncludeOptional,
    [int]    $MaxUpdates = 0,
    [switch] $AutoReboot,
    [int]    $RebootDelaySeconds = 60,
    [string] $OutputPath = (Join-Path $env:TEMP 'vmctl\patch')
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

$isElevated = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$report = [ordered]@{
    Computer     = $env:COMPUTERNAME
    TimestampUtc = (Get-Date).ToUniversalTime().ToString('s') + 'Z'
    Elevated     = $isElevated
    Mode         = $PSCmdlet.ParameterSetName
    Defender     = $null
    Pending      = @()
    Installed    = @()
    Failed       = @()
    RebootNeeded = $false
}

function Test-RebootPending {
    $r = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $r += 'CBS' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $r += 'WindowsUpdate' }
    try {
        if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
             -Name PendingFileRenameOperations -ErrorAction Stop).PendingFileRenameOperations) { $r += 'PendingFileRename' }
    } catch { }
    return ,$r
}

# ------------------------------------------------------- defender updates ---

Write-Output ''
Write-Output '===== DEFENDER SIGNATURES ====='
try {
    $before = Get-MpComputerStatus -ErrorAction Stop
    Write-Output ("Current : v{0}, age {1} day(s), last {2}" -f `
        $before.AntivirusSignatureVersion, $before.AntivirusSignatureAge, $before.AntivirusSignatureLastUpdated)

    if ($Install -or $SignaturesOnly) {
        if (-not $isElevated) {
            Write-Warning 'Signature update needs elevation; skipping.'
        } else {
            Write-Output 'Updating signatures...'
            try {
                Update-MpSignature -ErrorAction Stop
            } catch {
                # Fall back to MpCmdRun when the cmdlet path is blocked.
                Write-Warning "Update-MpSignature failed: $($_.Exception.Message)"
                $mp = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
                if (Test-Path $mp) {
                    Write-Output 'Falling back to MpCmdRun.exe -SignatureUpdate'
                    & $mp -SignatureUpdate | Out-Null
                }
            }
            $after = Get-MpComputerStatus -ErrorAction SilentlyContinue
            if ($after) {
                Write-Output ("Updated : v{0}, age {1} day(s)" -f `
                    $after.AntivirusSignatureVersion, $after.AntivirusSignatureAge)
            }
            $report.Defender = @{
                Before = "$($before.AntivirusSignatureVersion)"
                After  = "$($after.AntivirusSignatureVersion)"
                AgeDays= $after.AntivirusSignatureAge
            }
        }
    } else {
        $report.Defender = @{
            Before = "$($before.AntivirusSignatureVersion)"
            AgeDays= $before.AntivirusSignatureAge
        }
        if ($before.AntivirusSignatureAge -gt 7) {
            Write-Output 'STALE: signatures older than 7 days. Run with -Install or -SignaturesOnly.'
        }
    }
} catch {
    Write-Warning "Defender status unavailable: $($_.Exception.Message)"
}

if ($SignaturesOnly) {
    New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
    $report | ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath (Join-Path $OutputPath 'patch-latest.json') -Encoding UTF8
    Write-Output ''
    Write-Output 'Signature-only run complete.'
    exit 0
}

# ------------------------------------------------------------ WU: search ----

Write-Output ''
Write-Output '===== WINDOWS UPDATE ====='

$session  = $null
$searcher = $null
try {
    $session  = New-Object -ComObject Microsoft.Update.Session
    $session.ClientApplicationID = 'vm-hardening-toolkit'
    $searcher = $session.CreateUpdateSearcher()
} catch {
    Write-Error "Cannot create Windows Update session: $($_.Exception.Message)"
    exit 4
}

$criteria = if ($IncludeOptional) { 'IsInstalled=0 and IsHidden=0' }
            else { 'IsInstalled=0 and IsHidden=0 and Type=''Software''' }

Write-Output "Searching ($criteria)..."
$result = $null
try {
    $result = $searcher.Search($criteria)
} catch {
    Write-Error @"
Update search failed: $($_.Exception.Message)

Common causes:
  - No network path to Windows Update / WSUS
  - The Windows Update service (wuauserv) is disabled
  - Running non-elevated in a restricted token
"@
    exit 4
}

$updates = @($result.Updates)
Write-Output ("Found {0} applicable update(s)." -f $updates.Count)

if ($updates.Count -eq 0) {
    $pend = Test-RebootPending
    $report.RebootNeeded = ($pend.Count -gt 0)
    Write-Output 'System is up to date.'
    if ($pend.Count -gt 0) { Write-Output ("Reboot still pending: {0}" -f ($pend -join ', ')) }
    New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
    $report | ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath (Join-Path $OutputPath 'patch-latest.json') -Encoding UTF8
    exit 0
}

Write-Output ''
$i = 0
foreach ($u in $updates) {
    $i++
    $kb  = ($u.KBArticleIDs | ForEach-Object { "KB$_" }) -join ','
    $sev = if ($u.MsrcSeverity) { $u.MsrcSeverity } else { 'Unspecified' }
    $mb  = [math]::Round($u.MaxDownloadSize / 1MB, 1)
    Write-Output ("  {0,3}. [{1,-11}] {2} ({3} MB)" -f $i, $sev, $u.Title, $mb)
    if ($kb) { Write-Output ("       {0}" -f $kb) }
    $report.Pending += @{
        Title = $u.Title; KB = $kb; Severity = $sev
        SizeMB = $mb; RebootRequired = $u.InstallationBehavior.RebootBehavior -ne 0
    }
}

if (-not $Install) {
    Write-Output ''
    Write-Output 'Scan only. Re-run with -Install (elevated) to apply.'
    New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
    $report | ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath (Join-Path $OutputPath 'patch-latest.json') -Encoding UTF8
    exit 1
}

# ----------------------------------------------------------- WU: install ----

if (-not $isElevated) {
    Write-Error 'Installing updates requires elevation. Use vmctl.sh run-elevated.'
    exit 3
}

$toInstall = New-Object -ComObject Microsoft.Update.UpdateColl
$count = 0
foreach ($u in $updates) {
    if ($MaxUpdates -gt 0 -and $count -ge $MaxUpdates) { break }
    if (-not $u.EulaAccepted) {
        try { $u.AcceptEula() } catch { Write-Warning "EULA accept failed: $($u.Title)" }
    }
    [void]$toInstall.Add($u)
    $count++
}

Write-Output ''
Write-Output ("Downloading {0} update(s)..." -f $toInstall.Count)
try {
    $downloader = $session.CreateUpdateDownloader()
    $downloader.Updates = $toInstall
    $dl = $downloader.Download()
    Write-Output ("Download result: {0}" -f $dl.ResultCode)   # 2 = succeeded
    if ($dl.ResultCode -notin 2,3) {
        Write-Error "Download failed with result code $($dl.ResultCode)"
        exit 4
    }
} catch {
    Write-Error "Download failed: $($_.Exception.Message)"
    exit 4
}

$ready = New-Object -ComObject Microsoft.Update.UpdateColl
foreach ($u in $toInstall) { if ($u.IsDownloaded) { [void]$ready.Add($u) } }

if ($ready.Count -eq 0) { Write-Error 'No updates downloaded successfully.'; exit 4 }

Write-Output ("Installing {0} update(s)... this can take a while." -f $ready.Count)
$installResult = $null
try {
    $installer = $session.CreateUpdateInstaller()
    $installer.Updates = $ready
    $installResult = $installer.Install()
} catch {
    Write-Error "Install failed: $($_.Exception.Message)"
    exit 4
}

# ResultCode: 0 NotStarted 1 InProgress 2 Succeeded 3 SucceededWithErrors
#             4 Failed     5 Aborted
$codeName = @{0='NotStarted';1='InProgress';2='Succeeded';3='SucceededWithErrors';4='Failed';5='Aborted'}
Write-Output ''
Write-Output ("Overall result: {0} ({1})" -f $installResult.ResultCode, $codeName[[int]$installResult.ResultCode])

for ($k = 0; $k -lt $ready.Count; $k++) {
    $u  = $ready.Item($k)
    $ur = $installResult.GetUpdateResult($k)
    $ok = $ur.ResultCode -in 2,3
    Write-Output ("  [{0}] {1}" -f $(if ($ok) {'OK  '} else {'FAIL'}), $u.Title)
    $entry = @{ Title = $u.Title; ResultCode = $ur.ResultCode; HResult = $ur.HResult }
    if ($ok) { $report.Installed += $entry } else { $report.Failed += $entry }
}

$report.RebootNeeded = [bool]$installResult.RebootRequired
$pend = Test-RebootPending
if ($pend.Count -gt 0) { $report.RebootNeeded = $true }

New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutputPath "patch-$stamp.json") -Encoding UTF8
$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutputPath 'patch-latest.json') -Encoding UTF8

Write-Output ''
Write-Output ("Installed: {0}   Failed: {1}" -f $report.Installed.Count, $report.Failed.Count)
Write-Output ("Report   : {0}" -f (Join-Path $OutputPath "patch-$stamp.json"))

if ($report.RebootNeeded) {
    Write-Output ''
    Write-Output 'REBOOT REQUIRED.'
    if ($AutoReboot) {
        Write-Output ("Rebooting in {0}s..." -f $RebootDelaySeconds)
        & shutdown.exe /r /t $RebootDelaySeconds /c 'VM hardening toolkit: post-patch reboot'
    } else {
        Write-Output 'Reboot from the host with:  vmctl.sh restart'
    }
}

if ($report.Failed.Count -gt 0) { exit 2 } else { exit 0 }
