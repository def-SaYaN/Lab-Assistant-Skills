<#
.SYNOPSIS
    Remediate Active Directory security findings, with dry-run and rollback.

.DESCRIPTION
    Companion to Invoke-ADAudit.ps1. Applies domain and DC-level hardening.

    AD changes are FOREST-WIDE and far harder to undo than local policy.
    ALWAYS run -WhatIf first, and always on a DC you can snapshot.

    REQUIRES: Domain Admin (most controls) and elevation.

.PARAMETER Profile
    Baseline - low-risk, widely applicable
    Strict   - + privileged-group cleanup, delegation removal, LSASS PPL,
               RC4 disablement, LDAP channel binding enforced (Always)
    Paranoid - + deny all NTLM in the domain
    AD CS findings (ESC1-ESC4) are reported by Invoke-ADAudit.ps1 but never
    auto-remediated: the fix depends on who legitimately enrols.

.PARAMETER Only / -Skip
    Filter by control ID.

.PARAMETER WhatIf
    Preview without changing anything. RUN THIS FIRST.

.PARAMETER RollbackFile
    Revert a previous run's journal.

.EXAMPLE
    .\Invoke-ADHardening.ps1 -Profile Baseline -WhatIf
.EXAMPLE
    .\Invoke-ADHardening.ps1 -Profile Baseline
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
param(
    [ValidateSet('Baseline','Strict','Paranoid')][string]$Profile='Baseline',
    [string[]]$Only,
    [string[]]$Skip,
    [string]  $RollbackFile,
    [string]  $JournalPath = (Join-Path $env:TEMP 'vmctl\rollback')
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

$isElevated = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isElevated) { Write-Error 'Requires elevation.'; exit 3 }

try { Import-Module ActiveDirectory -ErrorAction Stop }
catch { Write-Error 'ActiveDirectory module required. Install RSAT-AD-PowerShell.'; exit 4 }

$script:Journal = [System.Collections.Generic.List[object]]::new()
$script:JournalFile = $null
$script:Applied=0; $script:Failed=0; $script:Skipped=0

function Test-Selected {
    param([string]$Id,[string[]]$Profiles)
    if ($Profile -notin $Profiles) { return $false }
    if ($Only -and $Id -notin $Only) { return $false }
    if ($Skip -and $Id -in $Skip) { return $false }
    return $true
}

function Add-Journal {
    param([string]$Id,[string]$Type,[hashtable]$Before,[hashtable]$After)
    $script:Journal.Add([pscustomobject]@{
        Id=$Id;Type=$Type;Before=$Before;After=$After
        TimestampUtc=(Get-Date).ToUniversalTime().ToString('s')+'Z'})
    Save-Journal
}

# Flush after every change so a crash or host timeout keeps a usable journal.
function Save-Journal {
    if (-not $script:JournalFile) {
        New-Item -ItemType Directory -Force -Path $JournalPath | Out-Null
        $script:JournalFile = Join-Path $JournalPath ("ad-rollback-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    }
    ConvertTo-Json -InputObject @($script:Journal) -Depth 8 |
        Set-Content -LiteralPath $script:JournalFile -Encoding UTF8
}

function Backup-AuditPolicy {
    New-Item -ItemType Directory -Force -Path $JournalPath | Out-Null
    $f = Join-Path $JournalPath ("ad-auditpol-{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    & auditpol /backup /file:"$f" | Out-Null
    if (Test-Path -LiteralPath $f) { return @{ AuditPolBackup = $f } }
    return @{}
}

function Invoke-ADControl {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][scriptblock]$Test,
        [Parameter(Mandatory)][scriptblock]$Apply,
        [scriptblock]$CaptureState={@{}},
        [string[]]$Profiles=@('Baseline','Strict','Paranoid')
    )
    if (-not (Test-Selected -Id $Id -Profiles $Profiles)) { $script:Skipped++; return }
    $ok=$false
    try { $ok=[bool](& $Test) } catch { $ok=$false }
    if ($ok) { Write-Output "  [ok]    $Id  already compliant"; return }
    if (-not $PSCmdlet.ShouldProcess("$Id : $Description",'apply')) {
        Write-Output "  [would] $Id  $Description"; return
    }
    $before=@{}; try { $before = & $CaptureState } catch { }
    try {
        & $Apply
        Add-Journal -Id $Id -Type 'AD' -Before $before -After @{Description=$Description}
        Write-Output "  [set]   $Id  $Description"; $script:Applied++
    } catch {
        Write-Output "  [FAIL]  $Id  $Description -- $($_.Exception.Message)"; $script:Failed++
    }
}

function Set-ADHardeningReg {
    param(
        [Parameter(Mandatory)][string]$Id,[Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,[Parameter(Mandatory)]$Value,
        [string]$Type='DWord',[Parameter(Mandatory)][string]$Description,
        [string[]]$Profiles=@('Baseline','Strict','Paranoid')
    )
    if (-not (Test-Selected -Id $Id -Profiles $Profiles)) { $script:Skipped++; return }
    $existed = Test-Path $Path
    $cur = if ($existed) { try { (Get-ItemProperty $Path -Name $Name -ErrorAction Stop).$Name } catch { $null } } else { $null }
    if ($cur -eq $Value) { Write-Output "  [ok]    $Id  already compliant ($Name=$Value)"; return }
    if (-not $PSCmdlet.ShouldProcess("$Id : $Description","set $Path\$Name=$Value")) {
        Write-Output "  [would] $Id  $Description"
        Write-Output "          $Path\$Name : $(if($null -eq $cur){'<unset>'}else{$cur}) -> $Value"
        return
    }
    try {
        if (-not $existed) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
        Add-Journal -Id $Id -Type 'Registry' `
            -Before @{Path=$Path;Name=$Name;Value=$cur;Existed=$existed} `
            -After  @{Path=$Path;Name=$Name;Value=$Value;Type=$Type}
        Write-Output "  [set]   $Id  $Description"; $script:Applied++
    } catch {
        Write-Output "  [FAIL]  $Id  $Description -- $($_.Exception.Message)"; $script:Failed++
    }
}

# ------------------------------------------------------------- rollback ----

if ($RollbackFile) {
    if (-not (Test-Path $RollbackFile)) { Write-Error "Not found: $RollbackFile"; exit 2 }
    $entries = @(Get-Content -LiteralPath $RollbackFile -Raw | ConvertFrom-Json)
    for ($i=$entries.Count-1; $i -ge 0; $i--) {
        $e=$entries[$i]
        if ($e.Type -ne 'Registry') {
            $b = $e.Before
            try {
                if ($b -and $null -ne $b.Quota) {
                    $d = Get-ADDomain
                    Set-ADObject -Identity $d.DistinguishedName -Replace @{'ms-DS-MachineAccountQuota'=[int]$b.Quota} -ErrorAction Stop
                    Write-Output "  [rev]   $($e.Id) : ms-DS-MachineAccountQuota=$($b.Quota)"
                } elseif ($b -and $b.Service -and $b.StartMode) {
                    $st = @{ Auto='Automatic'; Manual='Manual'; Disabled='Disabled' }["$($b.StartMode)"]
                    if (-not $st) { throw "unmapped StartMode '$($b.StartMode)'" }
                    Set-Service -Name $b.Service -StartupType $st -ErrorAction Stop
                    if ("$($b.Status)" -eq 'Running') { Start-Service -Name $b.Service -ErrorAction Stop }
                    Write-Output "  [rev]   $($e.Id) : $($b.Service) -> $st"
                } elseif ($b -and $b.AuditPolBackup -and (Test-Path -LiteralPath $b.AuditPolBackup)) {
                    & auditpol /restore /file:"$($b.AuditPolBackup)" | Out-Null
                    Write-Output "  [rev]   $($e.Id) : audit policy restored from $($b.AuditPolBackup)"
                } else {
                    Write-Output "  [skip]  $($e.Id) : revert '$($e.Type)' manually. Prior state:"
                    Write-Output ("          " + (ConvertTo-Json -InputObject $b -Depth 4 -Compress))
                }
            } catch { Write-Output "  [FAIL]  $($e.Id) : $($_.Exception.Message)" }
            continue
        }
        try {
            if ($null -eq $e.Before.Value) {
                Remove-ItemProperty -Path $e.Before.Path -Name $e.Before.Name -Force -ErrorAction SilentlyContinue
                Write-Output "  [rev]   $($e.Id) : removed $($e.Before.Name)"
            } else {
                New-ItemProperty -Path $e.Before.Path -Name $e.Before.Name -Value $e.Before.Value `
                    -PropertyType $e.After.Type -Force | Out-Null
                Write-Output "  [rev]   $($e.Id) : restored $($e.Before.Name)=$($e.Before.Value)"
            }
        } catch { Write-Output "  [FAIL]  $($e.Id) : $($_.Exception.Message)" }
    }
    Write-Output 'Rollback complete. Reboot DCs to settle policy.'
    exit 0
}

# ---------------------------------------------------------------- start ----

$osi  = Get-CimInstance Win32_OperatingSystem
$IsDC = $osi.ProductType -eq 2

Write-Output ''
Write-Output "===== AD HARDENING : profile=$Profile ====="
Write-Output ("Host: {0}  IsDC={1}" -f $env:COMPUTERNAME,$IsDC)
if ($WhatIfPreference) { Write-Output 'DRY RUN - no changes.' }
Write-Output ''

# ================================================= 1. DOMAIN-WIDE ==========

Write-Output '--- Domain-wide settings ---'

Invoke-ADControl -Id 'ADH-001' `
    -Description 'Set ms-DS-MachineAccountQuota to 0 (blocks RBCD escalation)' `
    -Test {
        $d=Get-ADDomain
        (Get-ADObject -Identity $d.DistinguishedName -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota' -eq 0
    } `
    -CaptureState {
        $d=Get-ADDomain
        @{Quota=(Get-ADObject -Identity $d.DistinguishedName -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'}
    } `
    -Apply {
        $d=Get-ADDomain
        Set-ADObject -Identity $d.DistinguishedName -Replace @{'ms-DS-MachineAccountQuota'=0} -ErrorAction Stop
    }

Invoke-ADControl -Id 'ADH-002' `
    -Description 'Enable AD Recycle Bin (irreversible once enabled)' `
    -Test { [bool]((Get-ADForest).EnabledFeatures | Where-Object { $_ -match 'Recycle Bin' }) } `
    -Apply {
        $f=Get-ADForest
        Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet `
            -Target $f.Name -Confirm:$false -ErrorAction Stop
    } `
    -Profiles @('Baseline','Strict','Paranoid')

Invoke-ADControl -Id 'ADH-003' `
    -Description 'Password policy: min length 14, history 24, lockout 5/15min' `
    -Test {
        $p=Get-ADDefaultDomainPasswordPolicy
        $p.MinPasswordLength -ge 14 -and $p.PasswordHistoryCount -ge 24 -and
        $p.LockoutThreshold -gt 0 -and $p.LockoutThreshold -le 10 -and $p.ComplexityEnabled
    } `
    -CaptureState {
        $p=Get-ADDefaultDomainPasswordPolicy
        @{MinLength=$p.MinPasswordLength;History=$p.PasswordHistoryCount
          Lockout=$p.LockoutThreshold;Complexity=$p.ComplexityEnabled}
    } `
    -Apply {
        Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DNSRoot `
            -MinPasswordLength 14 -PasswordHistoryCount 24 -ComplexityEnabled $true `
            -LockoutThreshold 5 -LockoutDuration (New-TimeSpan -Minutes 15) `
            -LockoutObservationWindow (New-TimeSpan -Minutes 15) `
            -ReversibleEncryptionEnabled $false -ErrorAction Stop
    }

# ============================================ 2. PRIVILEGED ACCOUNTS =======

Write-Output ''
Write-Output '--- Privileged accounts ---'

Invoke-ADControl -Id 'ADH-010' `
    -Description 'Flag all Domain Admins as sensitive / cannot be delegated' `
    -Test {
        $m=@(Get-ADGroupMember 'Domain Admins' -Recursive | Where-Object objectClass -eq 'user')
        $bad=@($m | ForEach-Object { Get-ADUser $_ -Properties AccountNotDelegated } |
               Where-Object { -not $_.AccountNotDelegated })
        $bad.Count -eq 0
    } `
    -CaptureState {
        @{Members=(@(Get-ADGroupMember 'Domain Admins' -Recursive |
            Where-Object objectClass -eq 'user' |
            ForEach-Object { Get-ADUser $_ -Properties AccountNotDelegated } |
            Select-Object SamAccountName,AccountNotDelegated))}
    } `
    -Apply {
        Get-ADGroupMember 'Domain Admins' -Recursive |
            Where-Object objectClass -eq 'user' |
            ForEach-Object { Set-ADUser -Identity $_.SamAccountName -AccountNotDelegated $true -ErrorAction Stop }
    }

Invoke-ADControl -Id 'ADH-011' `
    -Description 'Empty Account Operators, Server Operators, Print Operators' `
    -Test {
        $n=0
        foreach ($g in @('Account Operators','Server Operators','Print Operators')) {
            $n += @(Get-ADGroupMember $g -ErrorAction SilentlyContinue).Count
        }
        $n -eq 0
    } `
    -CaptureState {
        $h=@{}
        foreach ($g in @('Account Operators','Server Operators','Print Operators')) {
            $h[$g] = @(Get-ADGroupMember $g -ErrorAction SilentlyContinue | Select-Object -Expand SamAccountName)
        }
        $h
    } `
    -Apply {
        foreach ($g in @('Account Operators','Server Operators','Print Operators')) {
            Get-ADGroupMember $g -ErrorAction SilentlyContinue | ForEach-Object {
                Remove-ADGroupMember -Identity $g -Members $_ -Confirm:$false -ErrorAction Stop
            }
        }
    } `
    -Profiles @('Strict','Paranoid')

Invoke-ADControl -Id 'ADH-012' `
    -Description 'Enable Kerberos pre-authentication on all accounts (stops AS-REP roasting)' `
    -Test { @(Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true -and Enabled -eq $true}).Count -eq 0 } `
    -CaptureState {
        @{Accounts=@(Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Select-Object -Expand SamAccountName)}
    } `
    -Apply {
        Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true -and Enabled -eq $true} |
            ForEach-Object { Set-ADAccountControl -Identity $_ -DoesNotRequirePreAuth $false -ErrorAction Stop }
    }

Invoke-ADControl -Id 'ADH-013' `
    -Description 'Disable reversible password encryption on all accounts' `
    -Test { @(Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq $true}).Count -eq 0 } `
    -Apply {
        Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq $true} |
            ForEach-Object { Set-ADUser -Identity $_ -AllowReversiblePasswordEncryption $false -ErrorAction Stop }
    }

Invoke-ADControl -Id 'ADH-014' `
    -Description 'Remove unconstrained delegation from non-DC computers' `
    -Test {
        $dcNames = @(Get-ADDomainController -Filter * | ForEach-Object { $_.Name })
        $unc = @(Get-ADComputer -Filter {TrustedForDelegation -eq $true} |
                 Where-Object { $_.Name -notin $dcNames })
        $unc.Count -eq 0
    } `
    -CaptureState {
        @{Computers=@(Get-ADComputer -Filter {TrustedForDelegation -eq $true} | Select-Object -Expand Name)}
    } `
    -Apply {
        $dcNames = @(Get-ADDomainController -Filter * | ForEach-Object { $_.Name })
        Get-ADComputer -Filter {TrustedForDelegation -eq $true} |
            Where-Object { $_.Name -notin $dcNames } |
            ForEach-Object { Set-ADAccountControl -Identity $_ -TrustedForDelegation $false -ErrorAction Stop }
    } `
    -Profiles @('Strict','Paranoid')

# ================================================ 3. DC-LOCAL SETTINGS =====

if ($IsDC) {
    Write-Output ''
    Write-Output '--- Domain controller hardening ---'

    Set-ADHardeningReg -Id 'ADH-020' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
        -Name 'LDAPServerIntegrity' -Value 2 `
        -Description 'Require LDAP signing (blocks LDAP relay)'

    # Channel binding: 1 (when supported) is the safe first step; 2 (always)
    # rejects LDAPS clients that cannot send CBT, so it is Strict+ only.
    Set-ADHardeningReg -Id 'ADH-021' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
        -Name 'LdapEnforceChannelBinding' -Value 1 `
        -Description 'LDAP channel binding when supported (blocks LDAPS relay for capable clients)' `
        -Profiles @('Baseline')

    Set-ADHardeningReg -Id 'ADH-028' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
        -Name 'LdapEnforceChannelBinding' -Value 2 `
        -Description 'Enforce LDAP channel binding always (blocks LDAPS relay)' `
        -Profiles @('Strict','Paranoid')

    Invoke-ADControl -Id 'ADH-022' `
        -Description 'Disable Print Spooler on DC (blocks PrinterBug coercion)' `
        -Test {
            $s=Get-Service Spooler -ErrorAction SilentlyContinue
            (-not $s) -or ($s.Status -ne 'Running' -and
             (Get-CimInstance Win32_Service -Filter "Name='Spooler'").StartMode -eq 'Disabled')
        } `
        -CaptureState {
            $s=Get-Service Spooler -ErrorAction SilentlyContinue
            @{Service='Spooler'; Status=if($s){"$($s.Status)"}; StartMode=(Get-CimInstance Win32_Service -Filter "Name='Spooler'" -ErrorAction SilentlyContinue).StartMode}
        } `
        -Apply {
            Stop-Service Spooler -Force -ErrorAction SilentlyContinue
            Set-Service Spooler -StartupType Disabled -ErrorAction Stop
        }

    Set-ADHardeningReg -Id 'ADH-023' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' `
        -Name 'AuditReceivingNTLMTraffic' -Value 2 `
        -Description 'Audit all inbound NTLM traffic (observe before restricting)'

    Set-ADHardeningReg -Id 'ADH-024' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' `
        -Name 'RestrictNTLMInDomain' -Value 7 `
        -Description 'Deny all NTLM in domain (AUDIT FIRST - breaks legacy apps)' `
        -Profiles @('Paranoid')

    Set-ADHardeningReg -Id 'ADH-025' `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
        -Name 'RunAsPPL' -Value 1 `
        -Description 'Run LSASS as protected process (blocks credential dumping)' `
        -Profiles @('Strict','Paranoid')

    Invoke-ADControl -Id 'ADH-026' `
        -Description 'Require SMB signing on DC' `
        -Test { (Get-SmbServerConfiguration).RequireSecuritySignature } `
        -Apply { Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -ErrorAction Stop }

    # Kerberos: AES only (RC4 tickets crack far faster)
    Set-ADHardeningReg -Id 'ADH-027' `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' `
        -Name 'SupportedEncryptionTypes' -Value 24 `
        -Description 'Kerberos AES128+AES256 only (disable RC4/DES; rotate krbtgt and old service passwords first)' `
        -Profiles @('Strict','Paranoid')
}

# ====================================================== 4. AUDIT POLICY ====

Write-Output ''
Write-Output '--- Audit policy (AD-relevant) ---'

Invoke-ADControl -Id 'ADH-030' `
    -Description 'Enable AD-focused audit subcategories' `
    -Test { $false } `
    -CaptureState { Backup-AuditPolicy } `
    -Apply {
        $subs=@(
            @{N='Directory Service Access';     S='enable'; F='enable'}
            @{N='Directory Service Changes';    S='enable'; F='enable'}
            @{N='Kerberos Authentication Service'; S='enable'; F='enable'}
            @{N='Kerberos Service Ticket Operations'; S='enable'; F='enable'}
            @{N='Credential Validation';        S='enable'; F='enable'}
            @{N='Security Group Management';    S='enable'; F='enable'}
            @{N='User Account Management';      S='enable'; F='enable'}
            @{N='Computer Account Management';  S='enable'; F='enable'}
            @{N='Process Creation';             S='enable'; F='disable'}
            @{N='Logon';                        S='enable'; F='enable'}
            @{N='Account Lockout';              S='enable'; F='enable'}
        )
        foreach ($s in $subs) {
            & auditpol /set /subcategory:"$($s.N)" /success:$($s.S) /failure:$($s.F) | Out-Null
        }
    }

Invoke-ADControl -Id 'ADH-031' `
    -Description 'Increase Security log to 1 GB on a DC' `
    -Test { (Get-WinEvent -ListLog Security).MaximumSizeInBytes -ge 1GB } `
    -Apply { & wevtutil sl Security /ms:1073741824 | Out-Null }

# ========================================================== SUMMARY ========

Write-Output ''
Write-Output '===== SUMMARY ====='
if ($WhatIfPreference) {
    Write-Output 'Dry run complete. Nothing changed.'
    Write-Output 'Re-run without -WhatIf to apply.'
    exit 0
}
Write-Output ("Applied : {0}" -f $script:Applied)
Write-Output ("Failed  : {0}" -f $script:Failed)
Write-Output ("Skipped : {0}" -f $script:Skipped)

if ($script:Journal.Count -gt 0) {
    Save-Journal
    $jf = $script:JournalFile
    Write-Output ''
    Write-Output "Rollback journal: $jf"
    Write-Output "NOTE: registry, Spooler, MachineAccountQuota and audit policy auto-revert;"
    Write-Output "      other AD object changes are printed with their prior state for manual undo."
}

Write-Output ''
Write-Output 'REBOOT DCs for LSASS PPL, LDAP signing, and Kerberos encryption changes.'
Write-Output 'Allow AD replication to converge before auditing again (repadmin /replsummary).'
if ($script:Failed -gt 0) { exit 2 } else { exit 0 }
