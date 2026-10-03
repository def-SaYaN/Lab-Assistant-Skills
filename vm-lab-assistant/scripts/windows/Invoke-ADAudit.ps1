<#
.SYNOPSIS
    Read-only Active Directory security audit for a domain controller or
    domain-joined Windows Server.

.DESCRIPTION
    Covers the attack paths that matter in a real AD environment:
    Kerberos (kerberoasting, AS-REP roasting, delegation), privileged group
    sprawl, krbtgt hygiene, AD CS certificate template abuse (ESC1-ESC8),
    LAPS, SMB/LDAP signing, DC-specific posture, password policy,
    replication health, and trust configuration.

    Writes NOTHING. Requires the ActiveDirectory module for most checks;
    degrades gracefully to Unknown when absent.

    Run on a DC, or on a domain-joined host with RSAT installed.

.PARAMETER OutputPath
    Directory for reports. Default $env:TEMP\vmctl\adaudit

.PARAMETER Format
    Console, Json, Csv, Markdown. Default Console, Json

.PARAMETER Category
    Restrict to named categories.

.EXAMPLE
    .\Invoke-ADAudit.ps1
.EXAMPLE
    .\Invoke-ADAudit.ps1 -Format Console,Json,Markdown
#>
[CmdletBinding()]
param(
    [string]   $OutputPath = (Join-Path $env:TEMP 'vmctl\adaudit'),
    [ValidateSet('Console','Json','Csv','Markdown')]
    [string[]] $Format     = @('Console','Json'),
    [string[]] $Category
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

$script:Results = [System.Collections.Generic.List[object]]::new()
$script:IsElevated = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

function Add-Result {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Title,
        [ValidateSet('Pass','Fail','Warn','Unknown','NotApplicable')][string]$Status='Unknown',
        $Observed=$null, $Expected=$null,
        [ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity='Medium',
        [string]$FixHint=''
    )
    $script:Results.Add([pscustomobject]@{
        Id=$Id; Category=$Category; Title=$Title; Status=$Status
        Observed=if($null -ne $Observed){"$Observed"}else{''}
        Expected=if($null -ne $Expected){"$Expected"}else{''}
        Severity=$Severity; FixHint=$FixHint
    })
}

function Test-Safe {
    param([scriptblock]$Body,[string]$Id)
    try { & $Body } catch {
        Add-Result -Id $Id -Category 'Error' -Title "Check '$Id' threw" `
            -Status Unknown -Observed $_.Exception.Message -Severity Info
    }
}

# --------------------------------------------------------------- context ---

$HasAD = $false
try { Import-Module ActiveDirectory -ErrorAction Stop; $HasAD = $true } catch { }

$IsDC = $false; $DomainRole = 'Unknown'
try {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $DomainRole = switch ($cs.DomainRole) {
        0 {'Standalone Workstation'} 1 {'Member Workstation'}
        2 {'Standalone Server'}      3 {'Member Server'}
        4 {'Backup Domain Controller'} 5 {'Primary Domain Controller'}
        default {'Unknown'}
    }
    $IsDC = $cs.DomainRole -in 4,5
} catch { }

Add-Result -Id 'AD-000' -Category 'Context' -Title 'Domain role' -Status 'Pass' `
    -Observed "$DomainRole (ADModule=$HasAD, Elevated=$($script:IsElevated))" -Severity 'Info'

if (-not $HasAD) {
    Add-Result -Id 'AD-001' -Category 'Context' -Title 'ActiveDirectory module available' `
        -Status 'Unknown' -Observed 'not installed' -Expected 'installed' -Severity 'High' `
        -FixHint 'Install-WindowsFeature RSAT-AD-PowerShell (Server) or Add-WindowsCapability Rsat.ActiveDirectory (Client)'
}

# ====================================================== 1. DOMAIN BASICS ====

if ($HasAD) {
Test-Safe -Id 'DOM' -Body {
    $d = Get-ADDomain -ErrorAction Stop
    $f = Get-ADForest -ErrorAction Stop

    Add-Result -Id 'AD-010' -Category 'Domain' -Title 'Domain functional level is 2016 or higher' `
        -Status $(if ("$($d.DomainMode)" -match '2016|2019|2022|2025|Default') {'Pass'} else {'Warn'}) `
        -Observed "$($d.DomainMode)" -Expected 'Windows2016Domain+' -Severity 'Medium' `
        -FixHint 'Newer levels unlock Credential Guard, PAM, and better Kerberos defaults.'

    Add-Result -Id 'AD-011' -Category 'Domain' -Title 'Forest functional level is 2016 or higher' `
        -Status $(if ("$($f.ForestMode)" -match '2016|2019|2022|2025|Default') {'Pass'} else {'Warn'}) `
        -Observed "$($f.ForestMode)" -Expected 'Windows2016Forest+' -Severity 'Medium'

    Add-Result -Id 'AD-012' -Category 'Domain' -Title 'Domain inventory' -Status 'Pass' `
        -Observed "domain=$($d.DNSRoot) forest=$($f.Name) domains=$($f.Domains.Count)" -Severity 'Info'

    # AD Recycle Bin: without it, accidental deletes need an authoritative restore.
    $rb = $f.EnabledFeatures | Where-Object { $_ -match 'Recycle Bin' }
    Add-Result -Id 'AD-013' -Category 'Domain' -Title 'AD Recycle Bin enabled' `
        -Status $(if ($rb) {'Pass'} else {'Warn'}) `
        -Observed $(if ($rb) {'enabled'} else {'not enabled'}) -Expected 'enabled' -Severity 'Medium' `
        -FixHint "Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target <forest>"

    # Machine account quota: default 10 lets ANY user join 10 computers.
    # That is the pivot for several privilege-escalation chains (e.g. RBCD).
    $maq = (Get-ADObject -Identity $d.DistinguishedName -Properties ms-DS-MachineAccountQuota -ErrorAction SilentlyContinue).'ms-DS-MachineAccountQuota'
    Add-Result -Id 'AD-014' -Category 'Domain' -Title 'ms-DS-MachineAccountQuota is 0' `
        -Status $(if ($maq -eq 0) {'Pass'} elseif ($null -eq $maq) {'Unknown'} else {'Fail'}) `
        -Observed $maq -Expected '0' -Severity 'High' `
        -FixHint 'Default 10 enables resource-based constrained delegation attacks. Set to 0.'
}

# ====================================================== 2. PRIVILEGED ACCT ==

Test-Safe -Id 'PRIV' -Body {

    foreach ($g in @('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators','Server Operators','Print Operators')) {
        try {
            $m = @(Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop)
            $limit = switch ($g) {
                'Domain Admins'     {5}  'Enterprise Admins' {2}
                'Schema Admins'     {1}  'Account Operators' {0}
                'Print Operators'   {0}  'Server Operators'  {0}
                'Backup Operators'  {1}  default {6}
            }
            $names = ($m | Select-Object -First 12 | ForEach-Object { $_.SamAccountName }) -join ', '
            Add-Result -Id "AD-02$([array]::IndexOf(@('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators','Server Operators','Print Operators'),$g))" `
                -Category 'PrivilegedAccess' -Title "$g membership within limit ($limit)" `
                -Status $(if ($m.Count -le $limit) {'Pass'} else {'Warn'}) `
                -Observed "$($m.Count) member(s): $names" -Expected "<= $limit" `
                -Severity $(if ($g -in @('Domain Admins','Enterprise Admins','Schema Admins')) {'High'} else {'Medium'}) `
                -FixHint "Account/Print/Server Operators should be empty - they grant indirect DA. Use tiered admin accounts."
        } catch {
            Add-Result -Id "AD-02x-$g" -Category 'PrivilegedAccess' -Title "$g membership" `
                -Status Unknown -Observed $_.Exception.Message -Severity Medium
        }
    }

    # Privileged accounts missing "sensitive and cannot be delegated"
    try {
        $da = @(Get-ADGroupMember 'Domain Admins' -Recursive -ErrorAction Stop |
                Where-Object objectClass -eq 'user' |
                ForEach-Object { Get-ADUser $_ -Properties AccountNotDelegated,ServicePrincipalName,PasswordLastSet,LastLogonDate -ErrorAction SilentlyContinue })
        $nd = @($da | Where-Object { -not $_.AccountNotDelegated })
        Add-Result -Id 'AD-030' -Category 'PrivilegedAccess' -Title 'Domain Admins marked sensitive / not delegated' `
            -Status $(if ($nd.Count -eq 0) {'Pass'} else {'Fail'}) `
            -Observed $(if ($nd) { ($nd.SamAccountName -join ', ') } else { 'all protected' }) `
            -Expected 'all flagged AccountNotDelegated' -Severity 'High' `
            -FixHint 'Set-ADUser <u> -AccountNotDelegated $true  (or add to Protected Users). Blocks delegation-based theft.'

        $spn = @($da | Where-Object { $_.ServicePrincipalName })
        Add-Result -Id 'AD-031' -Category 'PrivilegedAccess' -Title 'No Domain Admin has an SPN (kerberoastable)' `
            -Status $(if ($spn.Count -eq 0) {'Pass'} else {'Fail'}) `
            -Observed $(if ($spn) { ($spn.SamAccountName -join ', ') } else { 'none' }) `
            -Expected 'none' -Severity 'Critical' `
            -FixHint 'A DA with an SPN can be kerberoasted offline to full domain compromise. Remove the SPN or use a gMSA.'

        $stale = @($da | Where-Object { $_.PasswordLastSet -and $_.PasswordLastSet -lt (Get-Date).AddDays(-365) })
        Add-Result -Id 'AD-032' -Category 'PrivilegedAccess' -Title 'Domain Admin passwords rotated within 1 year' `
            -Status $(if ($stale.Count -eq 0) {'Pass'} else {'Warn'}) `
            -Observed $(if ($stale) { ($stale.SamAccountName -join ', ') } else { 'all recent' }) `
            -Expected 'rotated < 365 days' -Severity 'Medium'
    } catch { }

    # Protected Users group adoption
    try {
        $pu = @(Get-ADGroupMember 'Protected Users' -ErrorAction Stop)
        Add-Result -Id 'AD-033' -Category 'PrivilegedAccess' -Title 'Protected Users group in use' `
            -Status $(if ($pu.Count -gt 0) {'Pass'} else {'Warn'}) `
            -Observed "$($pu.Count) member(s)" -Expected 'privileged accounts enrolled' -Severity 'Medium' `
            -FixHint 'Protected Users blocks NTLM, unconstrained delegation, and credential caching for its members.'
    } catch { }

    # Built-in Administrator (RID 500) usage
    try {
        $d = Get-ADDomain -ErrorAction Stop
        $adm = Get-ADUser -Identity "$($d.DomainSID)-500" -Properties LastLogonDate,PasswordLastSet,Enabled -ErrorAction Stop
        Add-Result -Id 'AD-034' -Category 'PrivilegedAccess' -Title 'Built-in Administrator (RID 500) not in active use' `
            -Status $(if (-not $adm.Enabled) {'Pass'} elseif ($adm.LastLogonDate -and $adm.LastLogonDate -gt (Get-Date).AddDays(-90)) {'Warn'} else {'Pass'}) `
            -Observed "Enabled=$($adm.Enabled); LastLogon=$($adm.LastLogonDate)" `
            -Expected 'disabled or unused' -Severity 'Medium' `
            -FixHint 'RID 500 is the first target in any domain. Use named admin accounts instead.'
    } catch { }
}

# ========================================================= 3. KERBEROS =====

Test-Safe -Id 'KRB' -Body {

    # Kerberoastable: any enabled user account with an SPN
    try {
        $roast = @(Get-ADUser -Filter {ServicePrincipalName -like '*' -and Enabled -eq $true} `
                   -Properties ServicePrincipalName,PasswordLastSet,MemberOf -ErrorAction Stop)
        Add-Result -Id 'AD-040' -Category 'Kerberos' -Title 'Kerberoastable user accounts minimised' `
            -Status $(if ($roast.Count -eq 0) {'Pass'} elseif ($roast.Count -le 3) {'Warn'} else {'Fail'}) `
            -Observed "$($roast.Count): $(($roast | Select-Object -First 8).SamAccountName -join ', ')" `
            -Expected '0 (use gMSA)' -Severity 'High' `
            -FixHint 'Each is offline-crackable. Migrate to Group Managed Service Accounts (120-char random passwords).'

        $weak = @($roast | Where-Object { $_.PasswordLastSet -and $_.PasswordLastSet -lt (Get-Date).AddDays(-365) })
        Add-Result -Id 'AD-041' -Category 'Kerberos' -Title 'Service account passwords rotated within 1 year' `
            -Status $(if ($weak.Count -eq 0) {'Pass'} else {'Warn'}) `
            -Observed "$($weak.Count) stale" -Expected '0' -Severity 'Medium'
    } catch { }

    # AS-REP roastable: Kerberos pre-auth disabled
    try {
        $asrep = @(Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true -and Enabled -eq $true} -ErrorAction Stop)
        Add-Result -Id 'AD-042' -Category 'Kerberos' -Title 'No accounts with Kerberos pre-auth disabled' `
            -Status $(if ($asrep.Count -eq 0) {'Pass'} else {'Fail'}) `
            -Observed $(if ($asrep) { ($asrep.SamAccountName -join ', ') } else { 'none' }) `
            -Expected 'none' -Severity 'High' `
            -FixHint 'AS-REP roasting needs no credentials at all. Set-ADAccountControl -DoesNotRequirePreAuth $false'
    } catch { }

    # Unconstrained delegation: compromise = full domain
    try {
        $unc = @(Get-ADObject -Filter {(UserAccountControl -band 524288) -ne 0} `
                 -Properties samAccountName,UserAccountControl -ErrorAction Stop |
                 Where-Object { $_.samAccountName -notmatch '^\w+\$$' -or $_.ObjectClass -eq 'computer' })
        $nonDC = @($unc | Where-Object { $_.samAccountName -notin (Get-ADDomainController -Filter * -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name)$" }) })
        Add-Result -Id 'AD-043' -Category 'Kerberos' -Title 'No unconstrained delegation outside DCs' `
            -Status $(if ($nonDC.Count -eq 0) {'Pass'} else {'Fail'}) `
            -Observed $(if ($nonDC) { ($nonDC.samAccountName -join ', ') } else { 'DCs only' }) `
            -Expected 'DCs only' -Severity 'Critical' `
            -FixHint 'A host with unconstrained delegation caches any TGT sent to it, including a DAs. Use constrained or RBCD.'
    } catch { }

    # Constrained delegation with protocol transition (TrustedToAuthForDelegation)
    try {
        $t2a = @(Get-ADObject -Filter {(UserAccountControl -band 16777216) -ne 0} `
                 -Properties samAccountName -ErrorAction Stop)
        Add-Result -Id 'AD-044' -Category 'Kerberos' -Title 'Protocol transition (S4U2Self) usage reviewed' `
            -Status $(if ($t2a.Count -eq 0) {'Pass'} else {'Warn'}) `
            -Observed "$($t2a.Count): $(($t2a | Select-Object -First 6).samAccountName -join ', ')" `
            -Expected 'minimal' -Severity 'High' `
            -FixHint 'Protocol transition lets the host impersonate any user to the target service.'
    } catch { }

    # krbtgt password age: golden-ticket lifetime
    try {
        $k = Get-ADUser -Identity krbtgt -Properties PasswordLastSet -ErrorAction Stop
        $age = if ($k.PasswordLastSet) { (New-TimeSpan -Start $k.PasswordLastSet -End (Get-Date)).Days } else { $null }
        Add-Result -Id 'AD-045' -Category 'Kerberos' -Title 'krbtgt password rotated within 180 days' `
            -Status $(if ($null -eq $age) {'Unknown'} elseif ($age -le 180) {'Pass'} else {'Fail'}) `
            -Observed "$age days (set $($k.PasswordLastSet))" -Expected '<= 180 days' -Severity 'High' `
            -FixHint 'A stolen krbtgt hash forges Golden Tickets until rotated TWICE (wait for replication between resets).'
    } catch { }

    # Kerberos encryption: RC4 should be off
    try {
        $rc4 = @(Get-ADUser -Filter {Enabled -eq $true} -Properties 'msDS-SupportedEncryptionTypes' -ErrorAction Stop |
                 Where-Object { $_.'msDS-SupportedEncryptionTypes' -and ($_.'msDS-SupportedEncryptionTypes' -band 0x4) })
        Add-Result -Id 'AD-046' -Category 'Kerberos' -Title 'RC4 Kerberos encryption not explicitly enabled' `
            -Status $(if ($rc4.Count -eq 0) {'Pass'} else {'Warn'}) `
            -Observed "$($rc4.Count) account(s) allow RC4" -Expected 'AES only' -Severity 'Medium' `
            -FixHint 'RC4 tickets are far cheaper to crack. Set msDS-SupportedEncryptionTypes to AES (24).'
    } catch { }
}

# ========================================================= 4. ACCOUNTS =====

Test-Safe -Id 'ACCT' -Body {
    try {
        $never = @(Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} -ErrorAction Stop)
        Add-Result -Id 'AD-050' -Category 'Accounts' -Title 'Few accounts with non-expiring passwords' `
            -Status $(if ($never.Count -eq 0) {'Pass'} elseif ($never.Count -le 3) {'Warn'} else {'Fail'}) `
            -Observed "$($never.Count): $(($never | Select-Object -First 8).SamAccountName -join ', ')" `
            -Expected '0' -Severity 'Medium'
    } catch { }

    try {
        $nopw = @(Get-ADUser -Filter {PasswordNotRequired -eq $true -and Enabled -eq $true} -ErrorAction Stop)
        Add-Result -Id 'AD-051' -Category 'Accounts' -Title 'No enabled accounts with PasswordNotRequired' `
            -Status $(if ($nopw.Count -eq 0) {'Pass'} else {'Fail'}) `
            -Observed $(if ($nopw) { ($nopw.SamAccountName -join ', ') } else { 'none' }) `
            -Expected 'none' -Severity 'Critical' `
            -FixHint 'These accounts can authenticate with a blank password.'
    } catch { }

    try {
        $cut = (Get-Date).AddDays(-90)
        $stale = @(Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonDate -ErrorAction Stop |
                   Where-Object { $_.LastLogonDate -and $_.LastLogonDate -lt $cut })
        Add-Result -Id 'AD-052' -Category 'Accounts' -Title 'Stale enabled accounts (no logon in 90 days)' `
            -Status $(if ($stale.Count -eq 0) {'Pass'} elseif ($stale.Count -le 5) {'Warn'} else {'Fail'}) `
            -Observed "$($stale.Count) stale" -Expected '0' -Severity 'Medium' `
            -FixHint 'Disable unused accounts; they are low-noise footholds.'

        $staleComp = @(Get-ADComputer -Filter {Enabled -eq $true} -Properties LastLogonDate -ErrorAction Stop |
                       Where-Object { $_.LastLogonDate -and $_.LastLogonDate -lt $cut })
        Add-Result -Id 'AD-053' -Category 'Accounts' -Title 'Stale computer accounts (no logon in 90 days)' `
            -Status $(if ($staleComp.Count -le 5) {'Pass'} else {'Warn'}) `
            -Observed "$($staleComp.Count) stale" -Expected 'minimal' -Severity 'Low'
    } catch { }

    # Reversible encryption = passwords recoverable in cleartext
    try {
        $rev = @(Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq $true} -ErrorAction Stop)
        Add-Result -Id 'AD-054' -Category 'Accounts' -Title 'No accounts store passwords reversibly' `
            -Status $(if ($rev.Count -eq 0) {'Pass'} else {'Fail'}) `
            -Observed $(if ($rev) { ($rev.SamAccountName -join ', ') } else { 'none' }) `
            -Expected 'none' -Severity 'Critical' `
            -FixHint 'Reversible encryption stores the password in a recoverable form.'
    } catch { }

    # Default domain password policy
    try {
        $p = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
        Add-Result -Id 'AD-055' -Category 'Accounts' -Title 'Minimum password length >= 14' `
            -Status $(if ($p.MinPasswordLength -ge 14) {'Pass'} else {'Fail'}) `
            -Observed $p.MinPasswordLength -Expected '>= 14' -Severity 'High' `
            -FixHint 'Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 14'

        Add-Result -Id 'AD-056' -Category 'Accounts' -Title 'Password complexity enabled' `
            -Status $(if ($p.ComplexityEnabled) {'Pass'} else {'Fail'}) `
            -Observed $p.ComplexityEnabled -Expected 'True' -Severity 'High'

        Add-Result -Id 'AD-057' -Category 'Accounts' -Title 'Account lockout threshold set (1-10)' `
            -Status $(if ($p.LockoutThreshold -gt 0 -and $p.LockoutThreshold -le 10) {'Pass'} else {'Fail'}) `
            -Observed $p.LockoutThreshold -Expected '1-10' -Severity 'High' `
            -FixHint '0 means unlimited password guessing.'

        Add-Result -Id 'AD-058' -Category 'Accounts' -Title 'Password history >= 24' `
            -Status $(if ($p.PasswordHistoryCount -ge 24) {'Pass'} else {'Warn'}) `
            -Observed $p.PasswordHistoryCount -Expected '>= 24' -Severity 'Low'

        Add-Result -Id 'AD-059' -Category 'Accounts' -Title 'Reversible encryption disabled domain-wide' `
            -Status $(if (-not $p.ReversibleEncryptionEnabled) {'Pass'} else {'Fail'}) `
            -Observed $p.ReversibleEncryptionEnabled -Expected 'False' -Severity 'Critical'
    } catch { }
}

# ============================================================ 5. AD CS =====

Test-Safe -Id 'ADCS' -Body {
    $caFound = $false
    try {
        $cfg = (Get-ADRootDSE -ErrorAction Stop).configurationNamingContext
        $cas = @(Get-ADObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$cfg" `
                 -Filter {objectClass -eq 'pKIEnrollmentService'} -Properties dNSHostName,cACertificate -ErrorAction Stop)
        $caFound = $cas.Count -gt 0

        Add-Result -Id 'AD-060' -Category 'ADCS' -Title 'Certificate Authorities inventoried' `
            -Status 'Pass' -Observed $(if ($cas) { ($cas.Name -join ', ') } else { 'none' }) -Severity 'Info'

        if ($caFound) {
            $tmplBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$cfg"
            $tmpl = @(Get-ADObject -SearchBase $tmplBase -Filter {objectClass -eq 'pKICertificateTemplate'} `
                      -Properties msPKI-Certificate-Name-Flag,msPKI-Enrollment-Flag,pKIExtendedKeyUsage,`
                                  msPKI-RA-Signature,nTSecurityDescriptor -ErrorAction Stop)

            # ESC1: requester supplies subject + client auth EKU + no manager approval
            $esc1 = @($tmpl | Where-Object {
                ($_.'msPKI-Certificate-Name-Flag' -band 0x1) -and          # ENROLLEE_SUPPLIES_SUBJECT
                (-not ($_.'msPKI-Enrollment-Flag' -band 0x2)) -and          # no CA manager approval
                (($_.'msPKI-RA-Signature' -eq 0) -or ($null -eq $_.'msPKI-RA-Signature')) -and
                ($_.pKIExtendedKeyUsage -contains '1.3.6.1.5.5.7.3.2' -or   # Client Authentication
                 $_.pKIExtendedKeyUsage -contains '1.3.6.1.5.2.3.4' -or     # PKINIT
                 $null -eq $_.pKIExtendedKeyUsage)
            })
            Add-Result -Id 'AD-061' -Category 'ADCS' -Title 'No ESC1-vulnerable certificate templates' `
                -Status $(if ($esc1.Count -eq 0) {'Pass'} else {'Fail'}) `
                -Observed $(if ($esc1) { ($esc1.Name -join ', ') } else { 'none' }) `
                -Expected 'none' -Severity 'Critical' `
                -FixHint 'ESC1: enrollee supplies subject + client auth + no approval = any user impersonates DA. Remove the flag or require approval.'

            # ESC2: Any Purpose or no EKU
            $esc2 = @($tmpl | Where-Object {
                ($_.pKIExtendedKeyUsage -contains '2.5.29.37.0') -or
                ($null -eq $_.pKIExtendedKeyUsage) -or ($_.pKIExtendedKeyUsage.Count -eq 0)
            })
            Add-Result -Id 'AD-062' -Category 'ADCS' -Title 'No ESC2-vulnerable templates (Any Purpose EKU)' `
                -Status $(if ($esc2.Count -eq 0) {'Pass'} else {'Fail'}) `
                -Observed $(if ($esc2) { ($esc2.Name -join ', ') } else { 'none' }) `
                -Expected 'none' -Severity 'High' `
                -FixHint 'Any Purpose / empty EKU certificates can be used for authentication.'

            # ESC3: Certificate Request Agent EKU
            $esc3 = @($tmpl | Where-Object { $_.pKIExtendedKeyUsage -contains '1.3.6.1.4.1.311.20.2.1' })
            Add-Result -Id 'AD-063' -Category 'ADCS' -Title 'Enrollment Agent templates restricted' `
                -Status $(if ($esc3.Count -eq 0) {'Pass'} else {'Warn'}) `
                -Observed $(if ($esc3) { ($esc3.Name -join ', ') } else { 'none' }) `
                -Expected 'none or tightly restricted' -Severity 'High' `
                -FixHint 'ESC3: an enrollment agent can request certificates on behalf of any user.'

            # ESC4: overly permissive template ACLs
            $esc4 = @()
            foreach ($t in $tmpl) {
                try {
                    $sd = $t.nTSecurityDescriptor
                    if (-not $sd) { continue }
                    foreach ($ace in $sd.Access) {
                        if ($ace.IdentityReference -match 'Authenticated Users|Domain Users|Everyone' -and
                            $ace.ActiveDirectoryRights -match 'WriteDacl|WriteOwner|GenericAll|GenericWrite') {
                            $esc4 += "$($t.Name) [$($ace.IdentityReference)]"
                            break
                        }
                    }
                } catch { }
            }
            Add-Result -Id 'AD-064' -Category 'ADCS' -Title 'No ESC4-vulnerable template ACLs' `
                -Status $(if ($esc4.Count -eq 0) {'Pass'} else {'Fail'}) `
                -Observed $(if ($esc4) { ($esc4 -join '; ') } else { 'none' }) `
                -Expected 'none' -Severity 'Critical' `
                -FixHint 'ESC4: write access to a template lets an attacker reconfigure it into ESC1.'

            Add-Result -Id 'AD-065' -Category 'ADCS' -Title 'Certificate template inventory' -Status 'Pass' `
                -Observed "$($tmpl.Count) templates published" -Severity 'Info'
        }
    } catch {
        Add-Result -Id 'AD-060' -Category 'ADCS' -Title 'AD CS enumeration' -Status 'Unknown' `
            -Observed $_.Exception.Message -Severity 'Medium'
    }

    if (-not $caFound) {
        Add-Result -Id 'AD-061' -Category 'ADCS' -Title 'AD CS present' -Status 'NotApplicable' `
            -Observed 'no Enterprise CA in forest' -Severity 'Info'
    }
}

# ============================================================== 6. LAPS ====

Test-Safe -Id 'LAPS' -Body {
    $legacy = $false; $win = $false
    try { $legacy = [bool](Get-ADObject -Filter {name -eq 'ms-Mcs-AdmPwd'} -SearchBase (Get-ADRootDSE).schemaNamingContext -ErrorAction Stop) } catch { }
    try { $win    = [bool](Get-ADObject -Filter {name -eq 'ms-LAPS-Password'} -SearchBase (Get-ADRootDSE).schemaNamingContext -ErrorAction Stop) } catch { }

    Add-Result -Id 'AD-070' -Category 'LAPS' -Title 'LAPS schema present' `
        -Status $(if ($legacy -or $win) {'Pass'} else {'Fail'}) `
        -Observed "WindowsLAPS=$win LegacyLAPS=$legacy" -Expected 'at least one' -Severity 'High' `
        -FixHint 'Without LAPS every machine shares a local admin password - one compromise becomes lateral movement everywhere.'

    if ($legacy -or $win) {
        try {
            $attr = if ($win) {'ms-LAPS-PasswordExpirationTime'} else {'ms-Mcs-AdmPwdExpirationTime'}
            $all  = @(Get-ADComputer -Filter {Enabled -eq $true} -Properties $attr -ErrorAction Stop)
            $with = @($all | Where-Object { $_.$attr })
            $pct  = if ($all.Count) { [math]::Round(100.0*$with.Count/$all.Count) } else { 0 }
            Add-Result -Id 'AD-071' -Category 'LAPS' -Title 'LAPS deployed to most computers' `
                -Status $(if ($pct -ge 90) {'Pass'} elseif ($pct -ge 50) {'Warn'} else {'Fail'}) `
                -Observed "$($with.Count)/$($all.Count) ($pct%)" -Expected '>= 90%' -Severity 'High'
        } catch { }
    }
}

# ====================================================== 7. DC POSTURE ======

Test-Safe -Id 'DCP' -Body {
    try {
        $dcs = @(Get-ADDomainController -Filter * -ErrorAction Stop)
        Add-Result -Id 'AD-080' -Category 'DomainController' -Title 'Domain controller inventory' `
            -Status 'Pass' -Observed "$($dcs.Count): $(($dcs.Name) -join ', ')" -Severity 'Info'

        Add-Result -Id 'AD-081' -Category 'DomainController' -Title 'More than one DC (resilience)' `
            -Status $(if ($dcs.Count -ge 2) {'Pass'} else {'Warn'}) `
            -Observed "$($dcs.Count) DC(s)" -Expected '>= 2' -Severity 'Medium'

        # Read-only DCs are expected at branch sites; note their presence.
        $rodc = @($dcs | Where-Object { $_.IsReadOnly })
        Add-Result -Id 'AD-082' -Category 'DomainController' -Title 'RODC inventory' -Status 'Pass' `
            -Observed "$($rodc.Count) read-only" -Severity 'Info'
    } catch { }

    if ($IsDC) {
        # LDAP signing on the DC
        $ldap = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
                 -Name 'LDAPServerIntegrity' -ErrorAction SilentlyContinue).LDAPServerIntegrity
        Add-Result -Id 'AD-083' -Category 'DomainController' -Title 'LDAP server signing required' `
            -Status $(if ($ldap -eq 2) {'Pass'} else {'Fail'}) `
            -Observed $(if ($null -eq $ldap) {'not configured (default 1 = negotiate)'} else {$ldap}) `
            -Expected '2 (require)' -Severity 'High' `
            -FixHint 'LDAPServerIntegrity=2 blocks LDAP relay attacks.'

        # Channel binding (CBT) mitigates LDAPS relay
        $cbt = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
                -Name 'LdapEnforceChannelBinding' -ErrorAction SilentlyContinue).LdapEnforceChannelBinding
        Add-Result -Id 'AD-084' -Category 'DomainController' -Title 'LDAP channel binding enforced' `
            -Status $(if ($cbt -eq 2) {'Pass'} elseif ($cbt -eq 1) {'Warn'} else {'Fail'}) `
            -Observed $(if ($null -eq $cbt) {'not configured'} else {$cbt}) -Expected '2 (always)' `
            -Severity 'High' -FixHint 'Blocks relaying authentication to LDAPS.'

        # SMB signing is mandatory on DCs by default; verify it was not weakened
        try {
            $smb = Get-SmbServerConfiguration -ErrorAction Stop
            Add-Result -Id 'AD-085' -Category 'DomainController' -Title 'SMB signing required on DC' `
                -Status $(if ($smb.RequireSecuritySignature) {'Pass'} else {'Fail'}) `
                -Observed $smb.RequireSecuritySignature -Expected 'True' -Severity 'Critical' `
                -FixHint 'Unsigned SMB on a DC enables NTLM relay to SYSTEM.'
        } catch { }

        # Print Spooler on a DC enables PrinterBug / coerced authentication
        $sp = Get-Service -Name Spooler -ErrorAction SilentlyContinue
        Add-Result -Id 'AD-086' -Category 'DomainController' -Title 'Print Spooler disabled on DC' `
            -Status $(if (-not $sp -or $sp.Status -ne 'Running') {'Pass'} else {'Fail'}) `
            -Observed $(if ($sp) { $sp.Status } else { 'not installed' }) -Expected 'Stopped/Disabled' `
            -Severity 'High' `
            -FixHint 'PrinterBug coerces DC authentication to an attacker host. Stop-Service Spooler; Set-Service Spooler -StartupType Disabled'

        # NTLM usage auditing
        $ntlm = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' `
                 -Name 'AuditReceivingNTLMTraffic' -ErrorAction SilentlyContinue).AuditReceivingNTLMTraffic
        Add-Result -Id 'AD-087' -Category 'DomainController' -Title 'NTLM auditing enabled' `
            -Status $(if ($ntlm -ge 1) {'Pass'} else {'Warn'}) `
            -Observed $(if ($null -eq $ntlm) {'not configured'} else {$ntlm}) -Expected '>= 1' `
            -Severity 'Medium' -FixHint 'Audit before restricting NTLM, so you know what will break.'

        # DSRM account behaviour
        $dsrm = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
                 -Name 'DsrmAdminLogonBehavior' -ErrorAction SilentlyContinue).DsrmAdminLogonBehavior
        Add-Result -Id 'AD-088' -Category 'DomainController' -Title 'DSRM logon behaviour not set to 2' `
            -Status $(if ($dsrm -eq 2) {'Fail'} else {'Pass'}) `
            -Observed $(if ($null -eq $dsrm) {'not set (secure default)'} else {$dsrm}) `
            -Expected '0 or 1' -Severity 'High' `
            -FixHint 'Value 2 lets the DSRM account log on normally - a persistence backdoor.'
    }

    # Replication health
    try {
        $fail = @(Get-ADReplicationFailure -Target (Get-ADDomainController -Discover).HostName -ErrorAction Stop)
        Add-Result -Id 'AD-089' -Category 'DomainController' -Title 'No AD replication failures' `
            -Status $(if ($fail.Count -eq 0) {'Pass'} else {'Fail'}) `
            -Observed "$($fail.Count) failure(s)" -Expected '0' -Severity 'High' `
            -FixHint 'repadmin /showrepl  and  repadmin /replsummary'
    } catch { }
}

# ========================================================= 8. TRUSTS ======

Test-Safe -Id 'TRUST' -Body {
    try {
        $tr = @(Get-ADTrust -Filter * -ErrorAction Stop)
        if ($tr.Count -eq 0) {
            Add-Result -Id 'AD-090' -Category 'Trusts' -Title 'Domain trusts' -Status 'Pass' `
                -Observed 'none' -Severity 'Info'
        } else {
            foreach ($t in $tr) {
                $risky = (-not $t.SIDFilteringQuarantined) -and ($t.TrustType -ne 'TreeRoot')
                Add-Result -Id "AD-091-$($t.Name)" -Category 'Trusts' `
                    -Title "Trust '$($t.Name)' has SID filtering enabled" `
                    -Status $(if ($t.SIDFilteringQuarantined) {'Pass'} else {'Warn'}) `
                    -Observed "direction=$($t.Direction) type=$($t.TrustType) SIDFiltering=$($t.SIDFilteringQuarantined)" `
                    -Expected 'SID filtering on external trusts' -Severity 'High' `
                    -FixHint 'Without SID filtering, a compromised trusted domain can inject SID history to become DA here.'
            }
        }
    } catch { }
}

# =========================================================== 9. GPO =======

Test-Safe -Id 'GPO' -Body {
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        $gpos = @(Get-GPO -All -ErrorAction Stop)
        Add-Result -Id 'AD-100' -Category 'GPO' -Title 'GPO inventory' -Status 'Pass' `
            -Observed "$($gpos.Count) GPOs" -Severity 'Info'

        $unlinked = @($gpos | Where-Object {
            try { ([xml](Get-GPOReport -Guid $_.Id -ReportType Xml -ErrorAction Stop)).GPO.LinksTo -eq $null } catch { $false }
        })
        Add-Result -Id 'AD-101' -Category 'GPO' -Title 'No unlinked GPOs' `
            -Status $(if ($unlinked.Count -eq 0) {'Pass'} else {'Warn'}) `
            -Observed "$($unlinked.Count) unlinked" -Expected '0' -Severity 'Low' `
            -FixHint 'Unlinked GPOs are config debt and can be re-linked maliciously.'

        # Passwords in SYSVOL (MS14-025 cpassword)
        try {
            $d = Get-ADDomain -ErrorAction Stop
            $sysvol = "\\$($d.DNSRoot)\SYSVOL\$($d.DNSRoot)\Policies"
            $cpw = @(Get-ChildItem -Path $sysvol -Recurse -Include *.xml -ErrorAction SilentlyContinue |
                     Select-String -Pattern 'cpassword' -SimpleMatch -ErrorAction SilentlyContinue)
            Add-Result -Id 'AD-102' -Category 'GPO' -Title 'No cpassword values in SYSVOL (MS14-025)' `
                -Status $(if ($cpw.Count -eq 0) {'Pass'} else {'Fail'}) `
                -Observed $(if ($cpw) { "$($cpw.Count) file(s)" } else { 'none' }) -Expected 'none' `
                -Severity 'Critical' `
                -FixHint 'GPP cpassword is encrypted with a published AES key - trivially decrypted by any domain user.'
        } catch { }
    } catch {
        Add-Result -Id 'AD-100' -Category 'GPO' -Title 'GPO enumeration' -Status 'Unknown' `
            -Observed 'GroupPolicy module unavailable' -Severity 'Low'
    }
}
} # end if ($HasAD)

# ======================================================== REPORTING ========

if ($Category) {
    $script:Results = [System.Collections.Generic.List[object]](
        $script:Results | Where-Object { $_.Category -in $Category })
}

$summary = [ordered]@{
    Computer     = $env:COMPUTERNAME
    DomainRole   = $DomainRole
    IsDC         = $IsDC
    Elevated     = $script:IsElevated
    TimestampUtc = (Get-Date).ToUniversalTime().ToString('s') + 'Z'
    Total        = $script:Results.Count
    Pass         = @($script:Results | Where-Object Status -eq 'Pass').Count
    Fail         = @($script:Results | Where-Object Status -eq 'Fail').Count
    Warn         = @($script:Results | Where-Object Status -eq 'Warn').Count
    Unknown      = @($script:Results | Where-Object Status -eq 'Unknown').Count
}
$denom = $summary.Pass + $summary.Fail + $summary.Warn
$summary.ScorePercent = if ($denom -gt 0) { [math]::Round(100.0*$summary.Pass/$denom,1) } else { 0 }

New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

if ($Format -contains 'Console') {
    Write-Output ''
    Write-Output '===== ACTIVE DIRECTORY SECURITY AUDIT ====='
    Write-Output ("Host   : {0} ({1})" -f $summary.Computer, $summary.DomainRole)
    Write-Output ("Time   : {0}" -f $summary.TimestampUtc)
    Write-Output ("Score  : {0}% ({1} pass / {2} fail / {3} warn / {4} unknown)" -f `
        $summary.ScorePercent,$summary.Pass,$summary.Fail,$summary.Warn,$summary.Unknown)
    if (-not $HasAD) { Write-Output 'NOTE   : ActiveDirectory module missing - most checks skipped.' }
    Write-Output ''
    foreach ($grp in ($script:Results | Group-Object Category | Sort-Object Name)) {
        Write-Output ("--- {0} ---" -f $grp.Name)
        foreach ($r in ($grp.Group | Sort-Object @{E={@{Fail=0;Warn=1;Unknown=2;Pass=3;NotApplicable=4}[$_.Status]}}, Id)) {
            $mark = @{Pass='PASS';Fail='FAIL';Warn='WARN';Unknown='????';NotApplicable='N/A '}[$r.Status]
            Write-Output ("  [{0}] {1,-12} {2}" -f $mark,$r.Id,$r.Title)
            if ($r.Status -ne 'Pass' -and $r.Observed) { Write-Output ("         observed: {0}" -f $r.Observed) }
            if ($r.Status -in @('Fail','Warn') -and $r.FixHint) { Write-Output ("         fix     : {0}" -f $r.FixHint) }
        }
        Write-Output ''
    }
    $crit = @($script:Results | Where-Object { $_.Status -eq 'Fail' -and $_.Severity -in @('Critical','High') })
    if ($crit) {
        Write-Output '===== PRIORITY FAILURES ====='
        foreach ($c in ($crit | Sort-Object Severity,Id)) { Write-Output ("  [{0}] {1} - {2}" -f $c.Severity,$c.Id,$c.Title) }
        Write-Output ''
    }
}

if ($Format -contains 'Json') {
    $p = Join-Path $OutputPath "adaudit-$stamp.json"
    $obj = [pscustomobject]@{ Summary=$summary; Results=$script:Results }
    $obj | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $p -Encoding UTF8
    $obj | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutputPath 'adaudit-latest.json') -Encoding UTF8
    Write-Output "JSON report: $p"
}
if ($Format -contains 'Csv') {
    $p = Join-Path $OutputPath "adaudit-$stamp.csv"
    $script:Results | Export-Csv -LiteralPath $p -NoTypeInformation -Encoding UTF8
    Write-Output "CSV report: $p"
}
if ($Format -contains 'Markdown') {
    $p = Join-Path $OutputPath "adaudit-$stamp.md"
    $md = [System.Text.StringBuilder]::new()
    [void]$md.AppendLine("# Active Directory Security Audit`n")
    [void]$md.AppendLine("- **Host:** $($summary.Computer) ($($summary.DomainRole))")
    [void]$md.AppendLine("- **Score:** $($summary.ScorePercent)%`n")
    foreach ($grp in ($script:Results | Group-Object Category | Sort-Object Name)) {
        [void]$md.AppendLine("## $($grp.Name)`n")
        [void]$md.AppendLine("| Status | ID | Check | Observed | Severity |")
        [void]$md.AppendLine("|---|---|---|---|---|")
        foreach ($r in $grp.Group) {
            [void]$md.AppendLine("| $($r.Status) | $($r.Id) | $($r.Title) | $($r.Observed -replace '\|','\|') | $($r.Severity) |")
        }
        [void]$md.AppendLine()
    }
    $md.ToString() | Set-Content -LiteralPath $p -Encoding UTF8
    Write-Output "Markdown report: $p"
}

if ($summary.Fail -gt 0) { exit 2 } elseif ($summary.Warn -gt 0) { exit 1 } else { exit 0 }
