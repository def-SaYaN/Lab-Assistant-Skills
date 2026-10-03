<#
.SYNOPSIS
    Read-only security posture audit for a Windows guest.

.DESCRIPTION
    Collects ~45 checks across identity, patching, Defender, firewall,
    BitLocker, services, network, audit policy, and attack surface.
    Writes NOTHING and changes NOTHING. Safe to run non-elevated, though
    some checks degrade to "Unknown" without admin rights.

    Each result carries: Id, Category, Title, Status, Observed, Expected,
    Severity, Elevated (whether admin was needed), and FixHint.

.PARAMETER OutputPath
    Directory for report files. Default: $env:TEMP\vmctl\audit

.PARAMETER Format
    One or more of: Console, Json, Csv, Markdown. Default: Console, Json

.PARAMETER Category
    Restrict to named categories (e.g. Identity, Defender).

.EXAMPLE
    .\Invoke-HardeningAudit.ps1
.EXAMPLE
    .\Invoke-HardeningAudit.ps1 -Format Console,Json,Markdown -OutputPath C:\audit
#>
[CmdletBinding()]
param(
    [string]   $OutputPath = (Join-Path $env:TEMP 'vmctl\audit'),
    [ValidateSet('Console','Json','Csv','Markdown')]
    [string[]] $Format     = @('Console','Json'),
    [string[]] $Category
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

# ------------------------------------------------------------------ setup ---

$script:Results = [System.Collections.Generic.List[object]]::new()

$script:IsElevated = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

function Add-Result {
    param(
        [Parameter(Mandatory)][string] $Id,
        [Parameter(Mandatory)][string] $Category,
        [Parameter(Mandatory)][string] $Title,
        [ValidateSet('Pass','Fail','Warn','Unknown','NotApplicable')]
        [string] $Status   = 'Unknown',
        $Observed          = $null,
        $Expected          = $null,
        [ValidateSet('Critical','High','Medium','Low','Info')]
        [string] $Severity = 'Medium',
        [string] $FixHint  = '',
        [bool]   $NeedsElevation = $false
    )
    $script:Results.Add([pscustomobject]@{
        Id             = $Id
        Category       = $Category
        Title          = $Title
        Status         = $Status
        Observed       = if ($null -ne $Observed) { "$Observed" } else { '' }
        Expected       = if ($null -ne $Expected) { "$Expected" } else { '' }
        Severity       = $Severity
        NeedsElevation = $NeedsElevation
        FixHint        = $FixHint
    })
}

# Safe wrapper: never let one failing check abort the run.
function Test-Safe {
    param([scriptblock] $Body, [string] $Id)
    try { & $Body }
    catch {
        Add-Result -Id $Id -Category 'Error' -Title "Check '$Id' threw" `
            -Status Unknown -Observed $_.Exception.Message -Severity Info
    }
}

function Get-RegValue {
    param([string] $Path, [string] $Name)
    try {
        $v = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $v.$Name
    } catch { return $null }
}

# ------------------------------------------------------------- 1 identity ---

Test-Safe -Id 'ID' -Body {

    $lua = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
    Add-Result -Id 'ID-001' -Category 'Identity' -Title 'UAC (EnableLUA) enabled' `
        -Status $(if ($lua -eq 1) {'Pass'} elseif ($null -eq $lua) {'Unknown'} else {'Fail'}) `
        -Observed $lua -Expected '1' -Severity 'High' `
        -FixHint 'Set EnableLUA=1 under HKLM\...\Policies\System, then reboot.'

    $cpba = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin'
    Add-Result -Id 'ID-002' -Category 'Identity' -Title 'UAC admin consent prompt' `
        -Status $(if ($cpba -in 1,2,3,4,5) {'Pass'} elseif ($cpba -eq 0) {'Fail'} else {'Unknown'}) `
        -Observed $cpba -Expected '>=1 (prompt)' -Severity 'Medium' `
        -FixHint 'ConsentPromptBehaviorAdmin=2 (prompt on secure desktop) is the hardened value.'

    $latfp = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'LocalAccountTokenFilterPolicy'
    Add-Result -Id 'ID-003' -Category 'Identity' -Title 'LocalAccountTokenFilterPolicy not enabled' `
        -Status $(if ($latfp -eq 1) {'Warn'} else {'Pass'}) `
        -Observed $(if ($null -eq $latfp) {'not set'} else {$latfp}) -Expected 'not set / 0' `
        -Severity 'High' `
        -FixHint 'Value 1 grants full-token remote admin to local accounts. Remove unless deliberately required.'

    try {
        $admins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop)
        $names  = ($admins | ForEach-Object { $_.Name }) -join ', '
        Add-Result -Id 'ID-004' -Category 'Identity' -Title 'Local Administrators membership' `
            -Status $(if ($admins.Count -le 2) {'Pass'} else {'Warn'}) `
            -Observed "$($admins.Count): $names" -Expected 'minimal set' -Severity 'Medium' `
            -FixHint 'Remove unnecessary accounts from the Administrators group.'
    } catch {
        Add-Result -Id 'ID-004' -Category 'Identity' -Title 'Local Administrators membership' `
            -Status Unknown -Observed $_.Exception.Message -Severity Medium
    }

    try {
        $g = Get-LocalUser -Name 'Guest' -ErrorAction Stop
        Add-Result -Id 'ID-005' -Category 'Identity' -Title 'Guest account disabled' `
            -Status $(if ($g.Enabled) {'Fail'} else {'Pass'}) `
            -Observed "Enabled=$($g.Enabled)" -Expected 'Enabled=False' -Severity 'High' `
            -FixHint 'Disable-LocalUser -Name Guest'
    } catch {
        Add-Result -Id 'ID-005' -Category 'Identity' -Title 'Guest account disabled' -Status Unknown -Severity High
    }

    try {
        $blank = @(Get-LocalUser -ErrorAction Stop |
                   Where-Object { $_.Enabled -and -not $_.PasswordRequired })
        Add-Result -Id 'ID-006' -Category 'Identity' -Title 'No enabled accounts without password requirement' `
            -Status $(if ($blank.Count -eq 0) {'Pass'} else {'Fail'}) `
            -Observed $(if ($blank) { ($blank.Name -join ', ') } else { 'none' }) `
            -Expected 'none' -Severity 'Critical' `
            -FixHint 'Set PasswordRequired on every enabled local account.'
    } catch {
        Add-Result -Id 'ID-006' -Category 'Identity' -Title 'Accounts without password requirement' -Status Unknown -Severity Critical
    }

    try {
        $never = @(Get-LocalUser -ErrorAction Stop |
                   Where-Object { $_.Enabled -and $_.PasswordNeverExpires })
        Add-Result -Id 'ID-007' -Category 'Identity' -Title 'No enabled accounts with non-expiring passwords' `
            -Status $(if ($never.Count -eq 0) {'Pass'} else {'Warn'}) `
            -Observed $(if ($never) { ($never.Name -join ', ') } else { 'none' }) `
            -Expected 'none' -Severity 'Low' `
            -FixHint 'Lab VMs often leave this on deliberately; tighten for production images.'
    } catch { }

    # net accounts: password/lockout policy
    try {
        $na = (net accounts) 2>&1 | Out-String
        $minLen  = [regex]::Match($na, 'Minimum password length\s*:\s*(\d+)').Groups[1].Value
        $lockout = [regex]::Match($na, 'Lockout threshold\s*:\s*(\S+)').Groups[1].Value
        $maxAge  = [regex]::Match($na, 'Maximum password age \(days\)\s*:\s*(\S+)').Groups[1].Value

        Add-Result -Id 'ID-008' -Category 'Identity' -Title 'Minimum password length >= 14' `
            -Status $(if ([int]($minLen -as [int]) -ge 14) {'Pass'} else {'Fail'}) `
            -Observed $minLen -Expected '>= 14' -Severity 'High' `
            -FixHint 'net accounts /minpwlen:14'

        Add-Result -Id 'ID-009' -Category 'Identity' -Title 'Account lockout threshold set' `
            -Status $(if ($lockout -match '^\d+$' -and [int]$lockout -gt 0 -and [int]$lockout -le 10) {'Pass'} else {'Fail'}) `
            -Observed $lockout -Expected '1-10 attempts' -Severity 'High' `
            -FixHint 'net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15'

        Add-Result -Id 'ID-010' -Category 'Identity' -Title 'Maximum password age bounded' `
            -Status $(if ($maxAge -match '^\d+$' -and [int]$maxAge -ge 1 -and [int]$maxAge -le 365) {'Pass'} else {'Warn'}) `
            -Observed $maxAge -Expected '1-365 days' -Severity 'Low'
    } catch { }
}

# ------------------------------------------------------------- 2 patching ---

Test-Safe -Id 'PATCH' -Body {

    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        Add-Result -Id 'PA-001' -Category 'Patching' -Title 'OS build' `
            -Status 'Pass' -Observed "$($os.Caption) $($os.Version) ($($os.OSArchitecture))" `
            -Expected 'supported build' -Severity 'Info'

        $install = $os.InstallDate
        Add-Result -Id 'PA-002' -Category 'Patching' -Title 'OS install date' `
            -Status 'Pass' -Observed $install -Severity 'Info'
    } catch { }

    try {
        $hf = @(Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending)
        $last = $hf | Select-Object -First 1
        $age  = if ($last.InstalledOn) { (New-TimeSpan -Start $last.InstalledOn -End (Get-Date)).Days } else { $null }
        Add-Result -Id 'PA-003' -Category 'Patching' -Title 'Most recent hotfix within 45 days' `
            -Status $(if ($null -eq $age) {'Unknown'} elseif ($age -le 45) {'Pass'} else {'Fail'}) `
            -Observed $(if ($last) { "$($last.HotFixID) on $($last.InstalledOn) ($age days ago)" } else { 'none' }) `
            -Expected '<= 45 days' -Severity 'High' `
            -FixHint 'Run Invoke-Patching.ps1 to install pending updates.'

        Add-Result -Id 'PA-004' -Category 'Patching' -Title 'Installed hotfix count' `
            -Status 'Pass' -Observed $hf.Count -Severity 'Info'
    } catch {
        Add-Result -Id 'PA-003' -Category 'Patching' -Title 'Hotfix inventory' -Status Unknown -Severity High
    }

    # Pending updates via the Windows Update COM API (read-only search).
    try {
        $session  = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $res      = $searcher.Search("IsInstalled=0 and IsHidden=0")
        $crit     = @($res.Updates | Where-Object {
                        $_.MsrcSeverity -in @('Critical','Important')
                     })
        Add-Result -Id 'PA-005' -Category 'Patching' -Title 'No pending updates' `
            -Status $(if ($res.Updates.Count -eq 0) {'Pass'} else {'Fail'}) `
            -Observed "$($res.Updates.Count) pending ($($crit.Count) critical/important)" `
            -Expected '0 pending' -Severity $(if ($crit.Count -gt 0) {'Critical'} else {'Medium'}) `
            -FixHint 'Invoke-Patching.ps1 -Install'
    } catch {
        Add-Result -Id 'PA-005' -Category 'Patching' -Title 'Pending update scan' `
            -Status Unknown -Observed $_.Exception.Message -Severity Medium `
            -FixHint 'WU COM API unavailable (often blocked without elevation or offline).' `
            -NeedsElevation $true
    }

    # Reboot-pending signals
    try {
        $rb = @()
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $rb += 'CBS' }
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $rb += 'WU' }
        if (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations') { $rb += 'PendingFileRename' }
        Add-Result -Id 'PA-006' -Category 'Patching' -Title 'No reboot pending' `
            -Status $(if ($rb.Count -eq 0) {'Pass'} else {'Warn'}) `
            -Observed $(if ($rb) { $rb -join ', ' } else { 'none' }) -Expected 'none' -Severity 'Medium' `
            -FixHint 'Reboot the guest to finish servicing operations.'
    } catch { }
}

# ------------------------------------------------------------- 3 defender ---

Test-Safe -Id 'DEF' -Body {

    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop

        Add-Result -Id 'DF-001' -Category 'Defender' -Title 'Real-time protection enabled' `
            -Status $(if ($mp.RealTimeProtectionEnabled) {'Pass'} else {'Fail'}) `
            -Observed $mp.RealTimeProtectionEnabled -Expected 'True' -Severity 'Critical' `
            -FixHint 'Set-MpPreference -DisableRealtimeMonitoring $false'

        Add-Result -Id 'DF-002' -Category 'Defender' -Title 'Antivirus service running' `
            -Status $(if ($mp.AMServiceEnabled) {'Pass'} else {'Fail'}) `
            -Observed $mp.AMServiceEnabled -Expected 'True' -Severity 'Critical'

        Add-Result -Id 'DF-003' -Category 'Defender' -Title 'Behavior monitoring enabled' `
            -Status $(if ($mp.BehaviorMonitorEnabled) {'Pass'} else {'Fail'}) `
            -Observed $mp.BehaviorMonitorEnabled -Expected 'True' -Severity 'High' `
            -FixHint 'Set-MpPreference -DisableBehaviorMonitoring $false'

        Add-Result -Id 'DF-004' -Category 'Defender' -Title 'Tamper protection enabled' `
            -Status $(if ($mp.IsTamperProtected) {'Pass'} else {'Warn'}) `
            -Observed $mp.IsTamperProtected -Expected 'True' -Severity 'High' `
            -FixHint 'Enable via Windows Security UI or Intune; not settable by script.'

        $sigAge = $mp.AntivirusSignatureAge
        Add-Result -Id 'DF-005' -Category 'Defender' -Title 'Signature age <= 7 days' `
            -Status $(if ($null -eq $sigAge) {'Unknown'} elseif ($sigAge -le 7) {'Pass'} else {'Fail'}) `
            -Observed "$sigAge days (v$($mp.AntivirusSignatureVersion))" -Expected '<= 7 days' `
            -Severity 'High' -FixHint 'Update-MpSignature'

        Add-Result -Id 'DF-006' -Category 'Defender' -Title 'Network inspection / NIS enabled' `
            -Status $(if ($mp.NISEnabled) {'Pass'} else {'Warn'}) `
            -Observed $mp.NISEnabled -Expected 'True' -Severity 'Medium'
    } catch {
        Add-Result -Id 'DF-001' -Category 'Defender' -Title 'Defender status' `
            -Status Unknown -Observed $_.Exception.Message -Severity Critical `
            -FixHint 'Get-MpComputerStatus failed; Defender may be replaced by a third-party AV.'
    }

    try {
        $pref = Get-MpPreference -ErrorAction Stop

        Add-Result -Id 'DF-007' -Category 'Defender' -Title 'PUA protection enabled' `
            -Status $(if ($pref.PUAProtection -ge 1) {'Pass'} else {'Warn'}) `
            -Observed $pref.PUAProtection -Expected '1 (block)' -Severity 'Medium' `
            -FixHint 'Set-MpPreference -PUAProtection Enabled'

        Add-Result -Id 'DF-008' -Category 'Defender' -Title 'Cloud protection (MAPS) enabled' `
            -Status $(if ($pref.MAPSReporting -ge 1) {'Pass'} else {'Warn'}) `
            -Observed $pref.MAPSReporting -Expected '>=1' -Severity 'Medium' `
            -FixHint 'Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples'

        $exCount = @($pref.ExclusionPath).Count + @($pref.ExclusionProcess).Count + @($pref.ExclusionExtension).Count
        Add-Result -Id 'DF-009' -Category 'Defender' -Title 'Defender exclusions reviewed' `
            -Status $(if ($exCount -eq 0) {'Pass'} else {'Warn'}) `
            -Observed "$exCount exclusion(s)" -Expected 'none, or justified' -Severity 'Medium' `
            -FixHint 'Each exclusion is an AV blind spot; remove unjustified entries.'

        $asr = @($pref.AttackSurfaceReductionRules_Ids).Count
        Add-Result -Id 'DF-010' -Category 'Defender' -Title 'ASR rules configured' `
            -Status $(if ($asr -gt 0) {'Pass'} else {'Warn'}) `
            -Observed "$asr rule(s)" -Expected '>0' -Severity 'Medium' `
            -FixHint 'Invoke-Hardening.ps1 -Profile Strict applies a baseline ASR set.'
    } catch { }
}

# ------------------------------------------------------------- 4 firewall ---

Test-Safe -Id 'FW' -Body {
    try {
        foreach ($p in @('Domain','Private','Public')) {
            $fp = Get-NetFirewallProfile -Profile $p -ErrorAction Stop
            Add-Result -Id "FW-00$(@{Domain=1;Private=2;Public=3}[$p])" -Category 'Firewall' `
                -Title "Firewall enabled ($p)" `
                -Status $(if ($fp.Enabled) {'Pass'} else {'Fail'}) `
                -Observed "Enabled=$($fp.Enabled); Inbound=$($fp.DefaultInboundAction)" `
                -Expected 'Enabled=True; Inbound=Block' -Severity 'Critical' `
                -FixHint "Set-NetFirewallProfile -Profile $p -Enabled True -DefaultInboundAction Block"
        }

        # 'NotConfigured' inherits the Windows default, which is Block for
        # inbound. Only an explicit 'Allow' is a real finding.
        $all     = @(Get-NetFirewallProfile -ErrorAction Stop)
        $allowIn = @($all | Where-Object { $_.DefaultInboundAction -eq 'Allow' })
        $notCfg  = @($all | Where-Object { $_.DefaultInboundAction -eq 'NotConfigured' })
        Add-Result -Id 'FW-004' -Category 'Firewall' -Title 'Default inbound action blocks on all profiles' `
            -Status $(if ($allowIn.Count -gt 0) {'Fail'} elseif ($notCfg.Count -gt 0) {'Warn'} else {'Pass'}) `
            -Observed $(
                if ($allowIn) { "Allow on: $($allowIn.Name -join ', ')" }
                elseif ($notCfg) { "NotConfigured on: $($notCfg.Name -join ', ') (inherits default Block)" }
                else { 'all explicitly Block' }) `
            -Expected 'Block (explicit preferred)' -Severity 'High' `
            -FixHint 'Set-NetFirewallProfile -All -DefaultInboundAction Block to make the policy explicit.'

        $anyRules = @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop)
        Add-Result -Id 'FW-005' -Category 'Firewall' -Title 'Inbound allow-rule count' `
            -Status $(if ($anyRules.Count -lt 60) {'Pass'} else {'Warn'}) `
            -Observed "$($anyRules.Count) enabled inbound allow rules" -Expected 'minimal' -Severity 'Low' `
            -FixHint 'Review enabled inbound rules; disable unused groups.'
    } catch {
        Add-Result -Id 'FW-001' -Category 'Firewall' -Title 'Firewall status' `
            -Status Unknown -Observed $_.Exception.Message -Severity Critical
    }
}

# ---------------------------------------------------------- 5 disk crypto ---

Test-Safe -Id 'BL' -Body {
    try {
        $vols = @(Get-BitLockerVolume -ErrorAction Stop)
        $sys  = $vols | Where-Object { $_.VolumeType -eq 'OperatingSystem' } | Select-Object -First 1
        if ($sys) {
            Add-Result -Id 'BL-001' -Category 'Encryption' -Title 'OS volume BitLocker protection on' `
                -Status $(if ($sys.ProtectionStatus -eq 'On') {'Pass'} else {'Fail'}) `
                -Observed "Protection=$($sys.ProtectionStatus); $($sys.EncryptionPercentage)% ; $($sys.EncryptionMethod)" `
                -Expected 'Protection=On' -Severity 'High' `
                -FixHint 'BitLocker needs a TPM. On Fusion, encrypt the VM first, then add a vTPM device.'
        } else {
            Add-Result -Id 'BL-001' -Category 'Encryption' -Title 'OS volume BitLocker protection on' `
                -Status Unknown -Observed 'no OS volume reported' -Severity High
        }
    } catch {
        Add-Result -Id 'BL-001' -Category 'Encryption' -Title 'BitLocker status' `
            -Status Unknown -Observed $_.Exception.Message -Severity High `
            -NeedsElevation $true `
            -FixHint 'Get-BitLockerVolume requires elevation.'
    }

    try {
        $tpm = Get-Tpm -ErrorAction Stop
        Add-Result -Id 'BL-002' -Category 'Encryption' -Title 'TPM present and ready' `
            -Status $(if ($tpm.TpmPresent -and $tpm.TpmReady) {'Pass'} else {'Fail'}) `
            -Observed "Present=$($tpm.TpmPresent); Ready=$($tpm.TpmReady)" `
            -Expected 'Present=True; Ready=True' -Severity 'High' `
            -FixHint 'Add a vTPM in the hypervisor. VMware Fusion requires VM encryption first.'
    } catch {
        Add-Result -Id 'BL-002' -Category 'Encryption' -Title 'TPM present and ready' `
            -Status Unknown -Observed $_.Exception.Message -Severity High -NeedsElevation $true
    }

    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction Stop
        Add-Result -Id 'BL-003' -Category 'Encryption' -Title 'Secure Boot enabled' `
            -Status $(if ($sb) {'Pass'} else {'Fail'}) -Observed $sb -Expected 'True' `
            -Severity 'High' -FixHint 'Enable Secure Boot in VM firmware settings.'
    } catch {
        Add-Result -Id 'BL-003' -Category 'Encryption' -Title 'Secure Boot enabled' `
            -Status Unknown -Observed $_.Exception.Message -Severity High -NeedsElevation $true
    }
}

# ------------------------------------------------- 6 services and surface ---

Test-Safe -Id 'SVC' -Body {

    # Services that are classic lateral-movement / exposure surface.
    $risky = @(
        @{ Name='RemoteRegistry'; Sev='High';   Why='Remote registry access' }
        @{ Name='TermService';    Sev='Medium'; Why='Remote Desktop host' }
        @{ Name='SSDPSRV';        Sev='Low';    Why='SSDP discovery' }
        @{ Name='upnphost';       Sev='Medium'; Why='UPnP device host' }
        @{ Name='WinRM';          Sev='Medium'; Why='Remote management' }
        @{ Name='Spooler';        Sev='High';   Why='Print Spooler (PrintNightmare class)' }
        @{ Name='SharedAccess';   Sev='Medium'; Why='Internet Connection Sharing' }
        @{ Name='RemoteAccess';   Sev='Medium'; Why='Routing and Remote Access' }
    )
    $i = 0
    foreach ($r in $risky) {
        $i++
        $svc = Get-Service -Name $r.Name -ErrorAction SilentlyContinue
        if (-not $svc) {
            Add-Result -Id ("SV-{0:D3}" -f $i) -Category 'Services' -Title "$($r.Name) not present" `
                -Status 'Pass' -Observed 'not installed' -Severity 'Info'
            continue
        }
        $startup = (Get-CimInstance Win32_Service -Filter "Name='$($r.Name)'" -ErrorAction SilentlyContinue).StartMode
        $bad = ($svc.Status -eq 'Running') -or ($startup -in @('Auto','Automatic'))
        Add-Result -Id ("SV-{0:D3}" -f $i) -Category 'Services' `
            -Title "$($r.Name) disabled or stopped - $($r.Why)" `
            -Status $(if ($bad) {'Warn'} else {'Pass'}) `
            -Observed "Status=$($svc.Status); StartMode=$startup" `
            -Expected 'Stopped / Disabled unless required' -Severity $r.Sev `
            -FixHint "Stop-Service $($r.Name); Set-Service $($r.Name) -StartupType Disabled"
    }
}

Test-Safe -Id 'SURF' -Body {

    $smb1 = $null
    try { $smb1 = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop).State } catch { }
    Add-Result -Id 'SU-001' -Category 'AttackSurface' -Title 'SMBv1 disabled' `
        -Status $(if ($smb1 -eq 'Disabled') {'Pass'} elseif ($null -eq $smb1) {'Unknown'} else {'Fail'}) `
        -Observed $smb1 -Expected 'Disabled' -Severity 'High' `
        -FixHint 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart' `
        -NeedsElevation $true

    try {
        $srv = Get-SmbServerConfiguration -ErrorAction Stop
        Add-Result -Id 'SU-002' -Category 'AttackSurface' -Title 'SMB signing required (server)' `
            -Status $(if ($srv.RequireSecuritySignature) {'Pass'} else {'Warn'}) `
            -Observed $srv.RequireSecuritySignature -Expected 'True' -Severity 'Medium' `
            -FixHint 'Set-SmbServerConfiguration -RequireSecuritySignature $true -Force'
    } catch {
        Add-Result -Id 'SU-002' -Category 'AttackSurface' -Title 'SMB signing required (server)' `
            -Status Unknown -Severity Medium -NeedsElevation $true
    }

    $llmnr = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
    Add-Result -Id 'SU-003' -Category 'AttackSurface' -Title 'LLMNR disabled' `
        -Status $(if ($llmnr -eq 0) {'Pass'} else {'Warn'}) `
        -Observed $(if ($null -eq $llmnr) {'not configured'} else {$llmnr}) -Expected '0' `
        -Severity 'Medium' `
        -FixHint 'Set EnableMulticast=0 under HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient (blocks LLMNR poisoning).'

    $nbt = $null
    try {
        $nbt = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction Stop |
                 ForEach-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).NetbiosOptions } |
                 Where-Object { $_ -ne 2 })
    } catch { }
    Add-Result -Id 'SU-004' -Category 'AttackSurface' -Title 'NetBIOS over TCP/IP disabled on all interfaces' `
        -Status $(if ($null -eq $nbt) {'Unknown'} elseif ($nbt.Count -eq 0) {'Pass'} else {'Warn'}) `
        -Observed $(if ($null -ne $nbt) { "$($nbt.Count) interface(s) not set to 2" } else { 'unknown' }) `
        -Expected 'NetbiosOptions=2 everywhere' -Severity 'Medium' `
        -FixHint 'Set NetbiosOptions=2 on each NetBT interface (blocks NBT-NS poisoning).'

    $wsh = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' 'Enabled'
    Add-Result -Id 'SU-005' -Category 'AttackSurface' -Title 'Windows Script Host disabled' `
        -Status $(if ($wsh -eq 0) {'Pass'} else {'Warn'}) `
        -Observed $(if ($null -eq $wsh) {'enabled (default)'} else {$wsh}) -Expected '0' `
        -Severity 'Low' -FixHint 'Blocks .vbs/.js double-click execution. May break legacy tooling.'

    $autorun = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
    Add-Result -Id 'SU-006' -Category 'AttackSurface' -Title 'AutoRun disabled for all drives' `
        -Status $(if ($autorun -eq 255) {'Pass'} else {'Warn'}) `
        -Observed $(if ($null -eq $autorun) {'not configured'} else {$autorun}) -Expected '255' `
        -Severity 'Medium' -FixHint 'Set NoDriveTypeAutoRun=0xFF under Policies\Explorer.'

    # PowerShell v2 engine: bypasses modern logging and AMSI.
    $ps2 = $null
    try { $ps2 = (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction Stop).State } catch { }
    Add-Result -Id 'SU-007' -Category 'AttackSurface' -Title 'PowerShell v2 engine removed' `
        -Status $(if ($ps2 -eq 'Disabled') {'Pass'} elseif ($null -eq $ps2) {'Unknown'} else {'Fail'}) `
        -Observed $ps2 -Expected 'Disabled' -Severity 'High' `
        -FixHint 'PSv2 bypasses AMSI and script-block logging. Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root' `
        -NeedsElevation $true

    # RDP posture
    $deny = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
    $nla  = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
    Add-Result -Id 'SU-008' -Category 'AttackSurface' -Title 'RDP disabled, or NLA enforced when enabled' `
        -Status $(if ($deny -eq 1) {'Pass'} elseif ($nla -eq 1) {'Warn'} else {'Fail'}) `
        -Observed "fDenyTSConnections=$deny; NLA=$nla" `
        -Expected 'RDP off, or NLA=1' -Severity 'High' `
        -FixHint 'If RDP is needed: UserAuthentication=1 (NLA) and restrict source IPs by firewall rule.'
}

# -------------------------------------------------- 7 logging + integrity ---

Test-Safe -Id 'LOG' -Body {

    $sbl = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
    Add-Result -Id 'LG-001' -Category 'Logging' -Title 'PowerShell script block logging enabled' `
        -Status $(if ($sbl -eq 1) {'Pass'} else {'Fail'}) `
        -Observed $(if ($null -eq $sbl) {'not configured'} else {$sbl}) -Expected '1' `
        -Severity 'Medium' `
        -FixHint 'Set EnableScriptBlockLogging=1 under Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging.'

    $mod = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging'
    Add-Result -Id 'LG-002' -Category 'Logging' -Title 'PowerShell module logging enabled' `
        -Status $(if ($mod -eq 1) {'Pass'} else {'Warn'}) `
        -Observed $(if ($null -eq $mod) {'not configured'} else {$mod}) -Expected '1' -Severity 'Low'

    $cmdline = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled'
    Add-Result -Id 'LG-003' -Category 'Logging' -Title 'Process creation events include command line' `
        -Status $(if ($cmdline -eq 1) {'Pass'} else {'Warn'}) `
        -Observed $(if ($null -eq $cmdline) {'not configured'} else {$cmdline}) -Expected '1' `
        -Severity 'Medium' `
        -FixHint 'Critical for IR. Pairs with audit policy "Process Creation".'

    foreach ($lg in @('Security','System','Application')) {
        try {
            $l = Get-WinEvent -ListLog $lg -ErrorAction Stop
            $mb = [math]::Round($l.MaximumSizeInBytes / 1MB)
            Add-Result -Id "LG-10$(@{Security=1;System=2;Application=3}[$lg])" -Category 'Logging' `
                -Title "$lg log size >= 128 MB" `
                -Status $(if ($mb -ge 128) {'Pass'} else {'Warn'}) `
                -Observed "$mb MB" -Expected '>= 128 MB' -Severity 'Low' `
                -FixHint "wevtutil sl $lg /ms:201326592"
        } catch { }
    }

    # Audit policy subcategories (needs elevation)
    try {
        $ap = (auditpol /get /category:* ) 2>&1 | Out-String
        if ($ap -match 'Logon/Logoff') {
            $noAudit = ([regex]::Matches($ap, 'No Auditing')).Count
            Add-Result -Id 'LG-004' -Category 'Logging' -Title 'Audit subcategories configured' `
                -Status $(if ($noAudit -lt 30) {'Pass'} else {'Warn'}) `
                -Observed "$noAudit subcategories with No Auditing" -Expected 'key subcategories enabled' `
                -Severity 'Medium' -FixHint 'auditpol /set /subcategory:"Process Creation" /success:enable'
        } else {
            Add-Result -Id 'LG-004' -Category 'Logging' -Title 'Audit policy readable' `
                -Status Unknown -Observed 'auditpol requires elevation' -Severity Medium -NeedsElevation $true
        }
    } catch {
        Add-Result -Id 'LG-004' -Category 'Logging' -Title 'Audit policy readable' `
            -Status Unknown -Severity Medium -NeedsElevation $true
    }
}

# ------------------------------------------------------------- 8 network ----

Test-Safe -Id 'NET' -Body {
    try {
        $listen = @(Get-NetTCPConnection -State Listen -ErrorAction Stop)
        $ext = @($listen | Where-Object { $_.LocalAddress -in @('0.0.0.0','::') })
        $ports = ($ext | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object) -join ', '
        Add-Result -Id 'NW-001' -Category 'Network' -Title 'Externally-bound listening ports' `
            -Status $(if ($ext.Count -le 12) {'Pass'} else {'Warn'}) `
            -Observed "$($ext.Count) sockets; ports: $ports" -Expected 'minimal' -Severity 'Medium' `
            -FixHint 'Each 0.0.0.0 listener is reachable from the network; close or firewall unused ones.'
    } catch { }

    try {
        $prof = @(Get-NetConnectionProfile -ErrorAction Stop)
        foreach ($p in $prof) {
            Add-Result -Id 'NW-002' -Category 'Network' -Title "Network category not Private/Domain on untrusted nets ($($p.InterfaceAlias))" `
                -Status $(if ($p.NetworkCategory -eq 'Public') {'Pass'} else {'Warn'}) `
                -Observed "$($p.Name): $($p.NetworkCategory)" -Expected 'Public for untrusted' -Severity 'Low' `
                -FixHint 'Public applies the most restrictive firewall profile.'
        }
    } catch { }

    try {
        $ipv6 = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' 'DisabledComponents'
        Add-Result -Id 'NW-003' -Category 'Network' -Title 'IPv6 configuration reviewed' `
            -Status 'Pass' -Observed $(if ($null -eq $ipv6) {'default (enabled)'} else {"DisabledComponents=$ipv6"}) `
            -Severity 'Info' -FixHint 'Leave IPv6 enabled unless policy requires otherwise.'
    } catch { }
}

# -------------------------------------------- 9 server roles / domain -------

Test-Safe -Id 'SRV' -Body {

    $cs = $null; $osi = $null
    try { $cs  = Get-CimInstance Win32_ComputerSystem  -ErrorAction Stop } catch { }
    try { $osi = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { }

    $isServer = $osi -and $osi.ProductType -in 2,3   # 2=DC, 3=member/standalone server
    $isDC     = $osi -and $osi.ProductType -eq 2
    $role     = if ($cs) {
        switch ($cs.DomainRole) {
            0 {'Standalone Workstation'} 1 {'Member Workstation'}
            2 {'Standalone Server'}      3 {'Member Server'}
            4 {'Backup Domain Controller'} 5 {'Primary Domain Controller'}
            default {'Unknown'}
        }
    } else { 'Unknown' }

    Add-Result -Id 'SR-001' -Category 'ServerRole' -Title 'System role identified' -Status 'Pass' `
        -Observed "$role (ProductType=$($osi.ProductType); Domain=$($cs.Domain))" -Severity 'Info'

    if ($isDC) {
        Add-Result -Id 'SR-002' -Category 'ServerRole' -Title 'Domain controller detected' -Status 'Pass' `
            -Observed 'run Invoke-ADAudit.ps1 for AD-specific checks' -Severity 'Info' `
            -FixHint 'vmctl.sh run-elevated scripts/windows/Invoke-ADAudit.ps1'
    }

    if ($isServer) {
        # Installed roles: each is attack surface.
        try {
            $feat = @(Get-WindowsFeature -ErrorAction Stop | Where-Object Installed)
            $roles = @($feat | Where-Object { $_.FeatureType -eq 'Role' })
            Add-Result -Id 'SR-003' -Category 'ServerRole' -Title 'Installed server roles minimal' `
                -Status $(if ($roles.Count -le 3) {'Pass'} else {'Warn'}) `
                -Observed "$($roles.Count): $(($roles.Name | Select-Object -First 10) -join ', ')" `
                -Expected 'only required roles' -Severity 'Medium' `
                -FixHint 'Each role adds listening services and patch burden. Uninstall-WindowsFeature <name>'

            # GUI on a server is optional attack surface
            $gui = $feat | Where-Object Name -eq 'Server-Gui-Shell'
            Add-Result -Id 'SR-004' -Category 'ServerRole' -Title 'Server Core (no desktop shell)' `
                -Status $(if (-not $gui) {'Pass'} else {'Warn'}) `
                -Observed $(if ($gui) {'Desktop Experience installed'} else {'Server Core'}) `
                -Expected 'Server Core where possible' -Severity 'Low' `
                -FixHint 'Server Core removes browser/shell surface and reduces patching.'
        } catch {
            Add-Result -Id 'SR-003' -Category 'ServerRole' -Title 'Server role enumeration' `
                -Status Unknown -Observed $_.Exception.Message -Severity Medium
        }

        # SMB v1 server role is a separate feature on Server SKUs
        try {
            $smb1 = Get-WindowsFeature -Name FS-SMB1 -ErrorAction Stop
            Add-Result -Id 'SR-005' -Category 'ServerRole' -Title 'SMB1 feature removed' `
                -Status $(if (-not $smb1.Installed) {'Pass'} else {'Fail'}) `
                -Observed "Installed=$($smb1.Installed)" -Expected 'not installed' -Severity 'High' `
                -FixHint 'Uninstall-WindowsFeature FS-SMB1 -Restart'
        } catch { }
    }

    # Domain membership specifics
    if ($cs -and $cs.PartOfDomain) {
        Add-Result -Id 'SR-006' -Category 'ServerRole' -Title 'Domain joined' -Status 'Pass' `
            -Observed $cs.Domain -Severity 'Info'

        # Secure channel health
        try {
            $sc = Test-ComputerSecureChannel -ErrorAction Stop
            Add-Result -Id 'SR-007' -Category 'ServerRole' -Title 'Secure channel to domain healthy' `
                -Status $(if ($sc) {'Pass'} else {'Fail'}) -Observed $sc -Expected 'True' `
                -Severity 'High' -FixHint 'Test-ComputerSecureChannel -Repair -Credential <domain admin>'
        } catch { }

        # Cached logons: each cached credential is offline-crackable
        $cached = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'CachedLogonsCount'
        Add-Result -Id 'SR-008' -Category 'ServerRole' -Title 'Cached logon count <= 4' `
            -Status $(if ($null -ne $cached -and [int]$cached -le 4) {'Pass'} else {'Warn'}) `
            -Observed $(if ($null -eq $cached) {'default (10)'} else {$cached}) -Expected '<= 4 (0 on servers)' `
            -Severity 'Medium' `
            -FixHint 'Cached domain credentials can be extracted and cracked offline.'

        # LDAP client signing
        $ldapc = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\ldap' 'LDAPClientIntegrity'
        Add-Result -Id 'SR-009' -Category 'ServerRole' -Title 'LDAP client signing required' `
            -Status $(if ($ldapc -eq 2) {'Pass'} else {'Warn'}) `
            -Observed $(if ($null -eq $ldapc) {'not configured'} else {$ldapc}) -Expected '2' `
            -Severity 'Medium' -FixHint 'Mitigates LDAP relay from this host.'
    } else {
        Add-Result -Id 'SR-006' -Category 'ServerRole' -Title 'Domain joined' -Status 'NotApplicable' `
            -Observed 'workgroup' -Severity 'Info'
    }
}

# ----------------------------------------------- 10 hypervisor integration --

Test-Safe -Id 'HV' -Body {
    $tools = Get-Service -Name 'VMTools' -ErrorAction SilentlyContinue
    Add-Result -Id 'HV-001' -Category 'Hypervisor' -Title 'VMware Tools service running' `
        -Status $(if ($tools -and $tools.Status -eq 'Running') {'Pass'} else {'Warn'}) `
        -Observed $(if ($tools) { $tools.Status } else { 'not installed' }) -Expected 'Running' `
        -Severity 'Low' -FixHint 'Tools provides the guest-ops channel this toolkit depends on.'

    try {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard `
              -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop
        $vbs = $dg.VirtualizationBasedSecurityStatus
        Add-Result -Id 'HV-002' -Category 'Hypervisor' -Title 'Virtualization-based security running' `
            -Status $(if ($vbs -eq 2) {'Pass'} else {'Warn'}) `
            -Observed "VBS status=$vbs (0=off,1=configured,2=running)" -Expected '2' -Severity 'Medium' `
            -FixHint 'VBS/Credential Guard needs nested virtualization + vTPM on the hypervisor.'
    } catch {
        Add-Result -Id 'HV-002' -Category 'Hypervisor' -Title 'Virtualization-based security running' `
            -Status Unknown -Severity Medium -NeedsElevation $true
    }
}

# ------------------------------------------------------------- reporting ----

if ($Category) {
    $script:Results = [System.Collections.Generic.List[object]](
        $script:Results | Where-Object { $_.Category -in $Category })
}

$summary = [ordered]@{
    Computer      = $env:COMPUTERNAME
    User          = "$env:USERDOMAIN\$env:USERNAME"
    Elevated      = $script:IsElevated
    TimestampUtc  = (Get-Date).ToUniversalTime().ToString('s') + 'Z'
    Total         = $script:Results.Count
    Pass          = @($script:Results | Where-Object Status -eq 'Pass').Count
    Fail          = @($script:Results | Where-Object Status -eq 'Fail').Count
    Warn          = @($script:Results | Where-Object Status -eq 'Warn').Count
    Unknown       = @($script:Results | Where-Object Status -eq 'Unknown').Count
}
$denom = $summary.Pass + $summary.Fail + $summary.Warn
$summary.ScorePercent = if ($denom -gt 0) { [math]::Round(100.0 * $summary.Pass / $denom, 1) } else { 0 }

New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

if ($Format -contains 'Console') {
    Write-Output ''
    Write-Output "===== VM HARDENING AUDIT ====="
    Write-Output ("Host     : {0}  (user {1}, elevated={2})" -f $summary.Computer, $summary.User, $summary.Elevated)
    Write-Output ("Time     : {0}" -f $summary.TimestampUtc)
    Write-Output ("Score    : {0}% ({1} pass / {2} fail / {3} warn / {4} unknown)" -f `
        $summary.ScorePercent, $summary.Pass, $summary.Fail, $summary.Warn, $summary.Unknown)
    if (-not $script:IsElevated) {
        Write-Output "NOTE     : running non-elevated; some checks report Unknown."
    }
    Write-Output ''

    foreach ($grp in ($script:Results | Group-Object Category | Sort-Object Name)) {
        Write-Output ("--- {0} ---" -f $grp.Name)
        foreach ($r in ($grp.Group | Sort-Object @{E={
                @{Fail=0;Warn=1;Unknown=2;Pass=3;NotApplicable=4}[$_.Status]}}, Id)) {
            $mark = @{Pass='PASS';Fail='FAIL';Warn='WARN';Unknown='????';NotApplicable='N/A '}[$r.Status]
            Write-Output ("  [{0}] {1,-10} {2}" -f $mark, $r.Id, $r.Title)
            if ($r.Status -ne 'Pass' -and $r.Observed) {
                Write-Output ("         observed: {0}" -f $r.Observed)
            }
            if ($r.Status -in @('Fail','Warn') -and $r.FixHint) {
                Write-Output ("         fix     : {0}" -f $r.FixHint)
            }
        }
        Write-Output ''
    }

    $crit = @($script:Results | Where-Object { $_.Status -eq 'Fail' -and $_.Severity -in @('Critical','High') })
    if ($crit) {
        Write-Output "===== PRIORITY FAILURES ====="
        foreach ($c in ($crit | Sort-Object Severity, Id)) {
            Write-Output ("  [{0}] {1} - {2}" -f $c.Severity, $c.Id, $c.Title)
        }
        Write-Output ''
    }
}

if ($Format -contains 'Json') {
    $p = Join-Path $OutputPath "audit-$stamp.json"
    [pscustomobject]@{ Summary = $summary; Results = $script:Results } |
        ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $p -Encoding UTF8
    Write-Output "JSON report: $p"
    # Stable copy for tooling that wants a predictable path.
    [pscustomobject]@{ Summary = $summary; Results = $script:Results } |
        ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutputPath 'audit-latest.json') -Encoding UTF8
}

if ($Format -contains 'Csv') {
    $p = Join-Path $OutputPath "audit-$stamp.csv"
    $script:Results | Export-Csv -LiteralPath $p -NoTypeInformation -Encoding UTF8
    Write-Output "CSV report: $p"
}

if ($Format -contains 'Markdown') {
    $p  = Join-Path $OutputPath "audit-$stamp.md"
    $md = [System.Text.StringBuilder]::new()
    [void]$md.AppendLine("# VM Hardening Audit")
    [void]$md.AppendLine()
    [void]$md.AppendLine("- **Host:** $($summary.Computer)")
    [void]$md.AppendLine("- **Time (UTC):** $($summary.TimestampUtc)")
    [void]$md.AppendLine("- **Elevated:** $($summary.Elevated)")
    [void]$md.AppendLine("- **Score:** $($summary.ScorePercent)% ($($summary.Pass) pass / $($summary.Fail) fail / $($summary.Warn) warn / $($summary.Unknown) unknown)")
    [void]$md.AppendLine()
    foreach ($grp in ($script:Results | Group-Object Category | Sort-Object Name)) {
        [void]$md.AppendLine("## $($grp.Name)")
        [void]$md.AppendLine()
        [void]$md.AppendLine("| Status | ID | Check | Observed | Severity |")
        [void]$md.AppendLine("|---|---|---|---|---|")
        foreach ($r in $grp.Group) {
            $o = ($r.Observed -replace '\|','\|')
            [void]$md.AppendLine("| $($r.Status) | $($r.Id) | $($r.Title) | $o | $($r.Severity) |")
        }
        [void]$md.AppendLine()
    }
    $md.ToString() | Set-Content -LiteralPath $p -Encoding UTF8
    Write-Output "Markdown report: $p"
}

# Exit code reflects posture: 0 clean, 1 warnings only, 2 failures present.
if ($summary.Fail -gt 0) { exit 2 } elseif ($summary.Warn -gt 0) { exit 1 } else { exit 0 }
