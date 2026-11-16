#requires -Version 5.1

<#
.SYNOPSIS
    Sentinel 1.0.1 - read-only Windows security posture audit.

.DESCRIPTION
    Read-only Windows security and storage posture assessment.
    https://github.com/halonyx-io/sentinel

    The script intentionally separates:

        Physical disks
            -> Storage pools / virtual disks
                -> Mounted volumes
                    -> BitLocker

    This prevents pooled, spanned, JBOD-style, Storage Spaces, or otherwise
    unusual storage layouts from being mistaken for individual BitLocker
    volumes.

    Checks include:

      SYSTEM
        - Windows edition/version/build
        - Hardware/model
        - CPU and RAM
        - BIOS/UEFI version
        - Pending reboot

      BOOT / PLATFORM SECURITY
        - Firmware boot mode
        - Secure Boot
        - TPM presence/readiness/version/lockout

      STORAGE
        - Physical disk health
        - Storage pools
        - Storage Spaces virtual disks
        - Resiliency/layout
        - Physical disks backing virtual disks
        - Mounted volume health
        - Mapping virtual disks to mounted volumes

      BITLOCKER
        - Queries BitLocker-capable volumes directly
        - OS and data volume encryption state
        - Protection status
        - Encryption percentage/method
        - Key protectors
        - Recovery protector presence
        - Auto-unlock
        - Handles pooled/spanned storage without assuming one disk per letter

      WINDOWS SECURITY
        - Virtualization Based Security
        - Memory Integrity / HVCI
        - Credential Guard
        - Secure Launch
        - Kernel-mode hardware-enforced stack protection
        - LSA protection (the running LSASS protection level, falling
          back to WinInit event 12 and then the RunAsPPL setting)

      ANTIVIRUS
        - Registered Windows Security antivirus products
        - Microsoft Defender running mode
        - Real-time protection
        - Behaviour monitoring
        - downloaded-file scanning
        - signatures
        - Tamper Protection

      NETWORK
        - Windows Firewall profiles
        - SMBv1
        - SMBv2/3
        - SMB client/server signing
        - insecure SMB guest logons
        - RDP
        - RDP Network Level Authentication

      PRIVILEGE SECURITY
        - UAC
        - Admin elevation policy
        - Secure Desktop prompting

      DIAGNOSTICS (not scored)
        - Uptime and last boot
        - System drive free space
        - Most recent installed update

    SCORING

    The 0-100 integrity score is NOT an average of pass/fail counts. Each
    genuine security control carries a weight, and critical controls carry a
    cap: the highest score the machine may earn while that control is failing.
    Informational checks (disk/volume health, inventory) carry no weight, so
    healthy hardware can never inflate a security score.

        outcome:  PASS 1.0   WARN 0.5   FAIL 0.0   UNKNOWN excluded
        base   = 100 * sum(weight*outcome) / sum(weight of known controls)
        score  = min(base, caps of failing or unknown critical controls,
                     74 if incomplete)

    An unencrypted OS drive alone caps the machine at 35; an unencrypted fixed
    data drive caps it at 65. Caps stack by taking the minimum.

    Any REQUIRED control that produces no result at all is reported as
    NOT EVALUATED - counted against coverage and, if critical, capped exactly
    as a failure. Absence of evidence is never treated as evidence of safety.
    Runs that cannot read every critical control are marked INCOMPLETE and
    clamped to 74, so a partially-inspected machine can never look hardened.

    OUTPUT
        - Console report (banner, colour-coded findings, score gauge)
        - Self-contained HTML dashboard
        - JSON report
        - Human-readable TXT report
        - Checks CSV
        - Physical disk CSV
        - Storage pool CSV
        - Virtual disk CSV
        - Volume CSV
        - BitLocker CSV
        - Antivirus product CSV

    Nothing is modified.

.PARAMETER OutputDirectory
    Directory used for exported reports.

    Defaults to:
        <script directory>\WindowsSecurityAudit

.PARAMETER NoExport
    Do not create report files.

.PARAMETER NoHtml
    Skip the HTML dashboard. JSON, TXT and CSV exports are still written.

.PARAMETER OpenReport
    Open the HTML dashboard in the default browser when the scan finishes.

.PARAMETER Quiet
    Suppress normal console report.

.PARAMETER PassThru
    Return the structured report object to the pipeline.

.EXAMPLE
    .\WindowsSecurityAudit.ps1

.EXAMPLE
    .\WindowsSecurityAudit.ps1 -OpenReport

.EXAMPLE
    $audit = .\WindowsSecurityAudit.ps1 -NoExport -Quiet -PassThru
    $audit.Checks | Where-Object Status -eq 'FAIL'

.EXAMPLE
    # Everything the score held against this machine
    $audit = .\WindowsSecurityAudit.ps1 -Quiet -PassThru
    $audit.HardFails
    $audit.NotEvaluated

.NOTES
    Designed for Windows PowerShell 5.1 and PowerShell 7+ on Windows.

    RUN AS ADMINISTRATOR. Without elevation, BitLocker and some Defender/TPM
    detail cannot be read at all; the run is marked INCOMPLETE and the score
    is clamped, because an unreadable machine must never score as a safe one.

    Read-only. No remediation actions are performed. Every file written goes
    to the output directory you specify.

    Reports describe a real machine's security posture - treat them as
    sensitive.
#>


[CmdletBinding()]
param(
    [string]$OutputDirectory,

    [switch]$NoExport,

    [switch]$Quiet,

    [switch]$PassThru,

    [switch]$NoHtml,

    [switch]$OpenReport
)


Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:SentinelVersion = '1.0.1'


# ============================================================================
# OUTPUT LOCATION
# ============================================================================

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {

    $BaseDirectory = if ($PSScriptRoot) {
        $PSScriptRoot
    }
    else {
        (Get-Location).Path
    }

    $OutputDirectory =
        Join-Path $BaseDirectory 'WindowsSecurityAudit'
}


# ============================================================================
# COLLECTION OBJECTS
# ============================================================================

$script:Checks =
    [System.Collections.Generic.List[object]]::new()

$script:PhysicalDisks =
    [System.Collections.Generic.List[object]]::new()

$script:StoragePools =
    [System.Collections.Generic.List[object]]::new()

$script:VirtualDisks =
    [System.Collections.Generic.List[object]]::new()

$script:Volumes =
    [System.Collections.Generic.List[object]]::new()

$script:BitLockerVolumes =
    [System.Collections.Generic.List[object]]::new()

$script:AntivirusProducts =
    [System.Collections.Generic.List[object]]::new()


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Test-IsAdministrator {

    try {

        $Identity =
            [Security.Principal.WindowsIdentity]::GetCurrent()

        $Principal =
            New-Object Security.Principal.WindowsPrincipal($Identity)

        return $Principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        )
    }
    catch {
        return $false
    }
}


function Test-CommandExists {

    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    return [bool](
        Get-Command $Name -ErrorAction SilentlyContinue
    )
}


function Test-ObjectProperty {

    param(
        [object]$Object,

        [Parameter(Mandatory)]
        [string]$Property
    )

    if ($null -eq $Object) {
        return $false
    }

    return (
        $null -ne $Object.PSObject.Properties[$Property]
    )
}


function Get-PropertyValue {

    param(
        [object]$Object,

        [Parameter(Mandatory)]
        [string]$Property,

        [object]$Default = $null
    )

    if ($null -eq $Object) {
        return $Default
    }

    $PropertyObject =
        $Object.PSObject.Properties[$Property]

    if ($null -eq $PropertyObject) {
        return $Default
    }

    return $PropertyObject.Value
}


function Get-RegistryValue {

    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Name
    )

    try {

        $Item =
            Get-ItemProperty `
                -Path $Path `
                -Name $Name `
                -ErrorAction Stop

        return $Item.$Name
    }
    catch {
        return $null
    }
}


function ConvertTo-JoinedString {

    param(
        [object]$Value,

        [string]$Separator = ', '
    )

    if ($null -eq $Value) {
        return ''
    }

    $Values = @(
        $Value |
        ForEach-Object {
            [string]$_
        } |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace($_)
        }
    )

    if ($Values.Count -eq 0) {
        return ''
    }

    return ($Values -join $Separator)
}


function ConvertTo-SizeString {

    param(
        [Nullable[UInt64]]$Bytes
    )

    if ($null -eq $Bytes) {
        return 'Unknown'
    }

    if ($Bytes -ge 1TB) {
        return ('{0:N2} TB' -f ($Bytes / 1TB))
    }

    if ($Bytes -ge 1GB) {
        return ('{0:N2} GB' -f ($Bytes / 1GB))
    }

    if ($Bytes -ge 1MB) {
        return ('{0:N2} MB' -f ($Bytes / 1MB))
    }

    return ('{0:N0} bytes' -f $Bytes)
}


function Add-Check {

    param(
        [Parameter(Mandatory)]
        [string]$Category,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet(
            'PASS',
            'WARN',
            'FAIL',
            'INFO',
            'UNKNOWN'
        )]
        [string]$Status,

        [object]$Value,

        [string]$Expected = '',

        [string]$Details = ''
    )

    if ($null -eq $Value) {
        $Value = 'Unknown'
    }

    $Object = [PSCustomObject]@{
        Category = $Category
        Check    = $Name
        Status   = $Status
        Value    = [string]$Value
        Expected = $Expected
        Details  = $Details
    }

    $script:Checks.Add($Object)
}


function Get-StatusColour {

    param(
        [string]$Status
    )

    switch ($Status) {

        'PASS' {
            return 'Green'
        }

        'WARN' {
            return 'Yellow'
        }

        'FAIL' {
            return 'Red'
        }

        'UNKNOWN' {
            return 'DarkYellow'
        }

        'INFO' {
            return 'Gray'
        }

        default {
            return 'White'
        }
    }
}


function Get-LsaProtectionState {

    # Returns Protected = $true / $false when the running state is
    # established, or $null when it cannot be read.
    $Result = [PSCustomObject]@{ Protected = $null; Source = $null; Detail = $null }
    $Reasons = [System.Collections.Generic.List[string]]::new()

    try {
        if (-not ('SecurityAuditLsaNative' -as [type])) {
            Add-Type @'
using System;
using System.Runtime.InteropServices;

public static class SecurityAuditLsaNative
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr handle);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationProcess(
        IntPtr handle, int infoClass, out byte info, int length, out int returned);

    // Returns the PS_PROTECTION byte, or -1 with the Win32/NTSTATUS code.
    public static int GetProtection(int pid, out int error)
    {
        error = 0;
        IntPtr h = OpenProcess(0x1000, false, pid);  // QUERY_LIMITED_INFORMATION
        if (h == IntPtr.Zero) { error = Marshal.GetLastWin32Error(); return -1; }
        try
        {
            byte level; int returned;
            int status = NtQueryInformationProcess(h, 61, out level, 1, out returned);
            if (status != 0) { error = status; return -1; }
            return level;
        }
        finally { CloseHandle(h); }
    }
}
'@
        }

        $Lsass = @(Get-Process -Name lsass -ErrorAction Stop)
        if ($Lsass.Count -ne 1) { throw "found $($Lsass.Count) lsass processes" }
        $Err = 0
        $Level = [SecurityAuditLsaNative]::GetProtection($Lsass[0].Id, [ref]$Err)
        if ($Level -lt 0) { throw ('protection query failed with code 0x{0:X}' -f $Err) }

        # PS_PROTECTION: type in bits 0-2 (1 = PPL, 2 = PP), signer in bits 4-7.
        $Type = $Level -band 7
        $Signer = $Level -shr 4
        $Result.Protected = $Type -ne 0
        $Result.Source = 'LSASS process protection level'
        $Result.Detail = 'Protection 0x{0:X2} (type {1}, signer {2}).' -f $Level, $Type, $Signer
        return $Result
    }
    catch {
        $Reasons.Add("process query: $($_.Exception.Message)")
    }

    try {
        $Boot = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime
        $Started = Get-WinEvent -MaxEvents 1 -ErrorAction Stop -FilterHashtable @{
            LogName = 'System'; ProviderName = 'Microsoft-Windows-Wininit'; Id = 12; StartTime = $Boot
        }
        $Result.Protected = $true
        $Result.Source = 'WinInit event 12 since last boot'
        $Result.Detail = [string]$Started.Message
        return $Result
    }
    catch {
        # No event is not proof of an unprotected LSASS (the log may have
        # rolled over), so the state stays unknown.
        $Reasons.Add("event log: $($_.Exception.Message)")
    }

    $Result.Detail = $Reasons -join '; '
    return $Result
}


function Get-FirmwareMode {

    try {

        if (-not ('SecurityAuditFirmwareNative' -as [type])) {

            Add-Type @'
using System;
using System.Runtime.InteropServices;

public static class SecurityAuditFirmwareNative
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetFirmwareType(
        out UInt32 FirmwareType
    );
}
'@
        }

        [UInt32]$FirmwareType = 0

        $Success =
            [SecurityAuditFirmwareNative]::GetFirmwareType(
                [ref]$FirmwareType
            )

        if (-not $Success) {
            return 'Unknown'
        }

        switch ($FirmwareType) {

            1 {
                return 'BIOS'
            }

            2 {
                return 'UEFI'
            }

            default {
                return 'Unknown'
            }
        }
    }
    catch {
        return 'Unknown'
    }
}


function Get-PartitionMetadata {

    param(
        [string]$DriveLetter
    )

    if ([string]::IsNullOrWhiteSpace($DriveLetter)) {
        return $null
    }

    if (-not (Test-CommandExists 'Get-Partition')) {
        return $null
    }

    try {

        return (
            Get-Partition `
                -DriveLetter $DriveLetter `
                -ErrorAction Stop |
            Select-Object -First 1
        )
    }
    catch {
        return $null
    }
}


function Get-DeviceGuardServiceNames {

    param(
        [object[]]$Values
    )

    $Map = @{
        1 = 'Credential Guard'
        2 = 'Memory Integrity / HVCI'
        3 = 'System Guard Secure Launch'
        4 = 'SMM Firmware Measurement'
        5 = 'Kernel hardware-enforced stack protection'
        6 = 'Kernel stack protection - Audit mode'
        7 = 'Hypervisor-Enforced Paging Translation'
    }

    $Results = @()

    foreach ($Value in @($Values)) {

        try {
            $Number = [int]$Value
        }
        catch {
            continue
        }

        if ($Number -eq 0) {
            continue
        }

        if ($Map.ContainsKey($Number)) {
            $Results += $Map[$Number]
        }
        else {
            $Results += "Unknown service ($Number)"
        }
    }

    if ($Results.Count -eq 0) {
        return 'None'
    }

    return ($Results -join ', ')
}


function Add-DeviceGuardServiceCheck {

    param(
        [Parameter(Mandatory)]
        [int]$ServiceId,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [int[]]$Configured,

        [Parameter(Mandatory)]
        [int[]]$Running,

        [ValidateSet('WARN', 'INFO')]
        [string]$NotConfiguredStatus = 'INFO'
    )

    if ($Running -contains $ServiceId) {

        Add-Check `
            -Category 'Virtualisation Security' `
            -Name $Name `
            -Status 'PASS' `
            -Value 'Running'
    }
    elseif ($Configured -contains $ServiceId) {

        Add-Check `
            -Category 'Virtualisation Security' `
            -Name $Name `
            -Status 'WARN' `
            -Value 'Configured but not running'
    }
    else {

        Add-Check `
            -Category 'Virtualisation Security' `
            -Name $Name `
            -Status $NotConfiguredStatus `
            -Value 'Not configured'
    }
}


function Test-PendingReboot {

    $Reasons = @()

    if (
        Test-Path `
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    ) {
        $Reasons += 'Component Based Servicing'
    }

    if (
        Test-Path `
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    ) {
        $Reasons += 'Windows Update'
    }

    try {

        $PendingFileRename =
            Get-RegistryValue `
                -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
                -Name 'PendingFileRenameOperations'

        if ($PendingFileRename) {
            $Reasons += 'Pending file rename operations'
        }
    }
    catch {}

    return [PSCustomObject]@{
        Pending = ($Reasons.Count -gt 0)
        Reasons = ($Reasons -join ', ')
    }
}


# ============================================================================
# ENCRYPTION DISCOVERY HELPERS
#
# A machine without the BitLocker cmdlets is NOT an unencrypted machine.
# Windows Home ships "Device Encryption" (same underlying WMI provider), and
# any edition may be encrypted by a third-party full-disk-encryption product.
# These helpers exist so Sentinel looks harder before it ever says "unknown",
# and so it never reports "not encrypted" on the basis of a missing cmdlet.
# ============================================================================

function Get-EncryptableVolumeInfo {

    # Win32_EncryptableVolume is the provider behind BOTH BitLocker and
    # Windows Device Encryption, and it exists on Windows Home.
    param(
        [string]$DriveLetter
    )

    try {

        $Volumes =
            @(
                Get-CimInstance `
                    -Namespace 'Root\CIMv2\Security\MicrosoftVolumeEncryption' `
                    -ClassName Win32_EncryptableVolume `
                    -ErrorAction Stop
            )
    }
    catch {
        return $null
    }

    if ($DriveLetter) {

        $Wanted = $DriveLetter.TrimEnd('\')

        $Volumes =
            @(
                $Volumes |
                Where-Object {
                    ([string](
                        Get-PropertyValue -Object $_ -Property 'DriveLetter'
                    )).TrimEnd('\') -ieq $Wanted
                }
            )
    }

    if ($Volumes.Count -eq 0) {
        return $null
    }

    $ConversionMap = @{
        0 = 'FullyDecrypted'
        1 = 'FullyEncrypted'
        2 = 'EncryptionInProgress'
        3 = 'DecryptionInProgress'
        4 = 'EncryptionPaused'
        5 = 'DecryptionPaused'
    }

    $MethodMap = @{
        0 = 'None'
        1 = 'AES-128 with diffuser'
        2 = 'AES-256 with diffuser'
        3 = 'AES-CBC-128'
        4 = 'AES-CBC-256'
        5 = 'Hardware encryption'
        6 = 'XTS-AES-128'
        7 = 'XTS-AES-256'
    }

    $Results = @()

    foreach ($V in $Volumes) {

        $Prot = Get-PropertyValue -Object $V -Property 'ProtectionStatus'
        $Conv = Get-PropertyValue -Object $V -Property 'ConversionStatus'
        $Meth = Get-PropertyValue -Object $V -Property 'EncryptionMethod'

        $ProtText =
            if ($null -eq $Prot) { 'Unknown' }
            elseif ([int]$Prot -eq 1) { 'On' }
            elseif ([int]$Prot -eq 0) { 'Off' }
            else { 'Unknown' }

        $ConvText =
            if ($null -ne $Conv -and $ConversionMap.ContainsKey([int]$Conv)) {
                $ConversionMap[[int]$Conv]
            }
            else { 'Unknown' }

        $MethText =
            if ($null -ne $Meth -and $MethodMap.ContainsKey([int]$Meth)) {
                $MethodMap[[int]$Meth]
            }
            else { 'Unknown' }

        $Results += [PSCustomObject]@{
            DriveLetter      = [string](Get-PropertyValue -Object $V -Property 'DriveLetter')
            ProtectionText   = $ProtText
            ConversionText   = $ConvText
            EncryptionMethod = $MethText
        }
    }

    return $Results
}


function Get-ThirdPartyEncryptionProducts {

    # Presence detection only. Sentinel cannot read the state of a third-party
    # FDE product, so finding one means "cannot verify", never "encrypted".
    $Patterns = @(
        'VeraCrypt', 'TrueCrypt', 'DiskCryptor', 'BestCrypt', 'Jetico',
        'Cryptomator', 'SafeGuard', 'Sophos.*Encryption', 'ESET.*Encryption',
        'DESlock', 'McAfee.*Encryption', 'Trellix.*Encryption',
        'Endpoint Encryption', 'Symantec.*Encryption', 'PGP.*(Desktop|Disk)',
        'Check ?Point.*Encryption', 'Dell.*(Data Protection|Encryption)',
        'Credant', 'WinMagic', 'SecureDoc', 'Full Disk Encryption'
    )

    $Found = [System.Collections.Generic.List[string]]::new()

    foreach ($Root in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )) {

        try {

            foreach ($Item in @(
                Get-ItemProperty -Path $Root -ErrorAction SilentlyContinue
            )) {

                $Name = [string](
                    Get-PropertyValue -Object $Item -Property 'DisplayName'
                )
                if (-not $Name) { continue }

                foreach ($P in $Patterns) {
                    if ($Name -match $P) {
                        if (-not $Found.Contains($Name)) { $Found.Add($Name) }
                        break
                    }
                }
            }
        }
        catch {}
    }

    try {

        foreach ($Svc in @(
            Get-CimInstance -ClassName Win32_Service -ErrorAction Stop
        )) {

            $Disp = [string](Get-PropertyValue -Object $Svc -Property 'DisplayName')
            $Nm   = [string](Get-PropertyValue -Object $Svc -Property 'Name')
            $Hay  = "$Disp $Nm"

            foreach ($P in $Patterns) {
                if ($Hay -match $P) {
                    $Label = if ($Disp) { $Disp } else { $Nm }
                    if ($Label -and -not $Found.Contains($Label)) {
                        $Found.Add($Label)
                    }
                    break
                }
            }
        }
    }
    catch {}

    return $Found.ToArray()
}


function Test-IsPortableChassis {

    # Laptops/tablets carry far more theft risk, so unencrypted storage on a
    # portable chassis is called out explicitly.
    try {

        $Enclosure =
            Get-CimInstance `
                -ClassName Win32_SystemEnclosure `
                -ErrorAction Stop |
            Select-Object -First 1

        $Types = @(
            Get-PropertyValue -Object $Enclosure -Property 'ChassisTypes'
        )

        $Portable = @(8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32)

        foreach ($T in $Types) {
            if ($null -ne $T -and $Portable -contains [int]$T) {
                return $true
            }
        }

        return $false
    }
    catch {
        return $null
    }
}


# ============================================================================
# PRESENTATION HELPERS (console banner + HTML dashboard)
# ============================================================================

function Get-PostureBand {

    param(
        [int]$Score
    )

    if ($Score -ge 90) {
        return [PSCustomObject]@{
            Name    = 'HARDENED'
            Colour  = 'Green'
            Verdict = 'Posture is strong. Remaining items are refinements, not exposures.'
        }
    }
    elseif ($Score -ge 75) {
        return [PSCustomObject]@{
            Name    = 'FORTIFIED'
            Colour  = 'Cyan'
            Verdict = 'Solid baseline with a few gaps worth closing.'
        }
    }
    elseif ($Score -ge 60) {
        return [PSCustomObject]@{
            Name    = 'GUARDED'
            Colour  = 'Yellow'
            Verdict = 'Adequate, but core protections need attention.'
        }
    }
    elseif ($Score -ge 40) {
        return [PSCustomObject]@{
            Name    = 'EXPOSED'
            Colour  = 'Red'
            Verdict = 'Multiple core protections are missing. Prioritise the FAIL items.'
        }
    }
    elseif ($Score -ge 20) {
        return [PSCustomObject]@{
            Name    = 'AT RISK'
            Colour  = 'Red'
            Verdict = 'Critical protections are off. This host is a soft target.'
        }
    }
    else {
        return [PSCustomObject]@{
            Name    = 'CRITICAL'
            Colour  = 'DarkRed'
            Verdict = 'Fundamental protections absent. Treat this host as compromised-if-lost.'
        }
    }
}


# ----------------------------------------------------------------------------
# RISK-WEIGHTED POSTURE SCORING
#
# The score is NOT an average of pass/fail counts. Each genuine security
# control carries a WEIGHT (its share of the score) and, if it is critical, a
# CAP (the highest score the whole machine may earn while that control is
# FAILING). Informational checks (disk/volume health, system inventory, AV
# product lists, ...) are NOT in the table and never touch the score, so
# adding healthy disks can no longer inflate posture.
#
#   outcome:  PASS -> 1.0   WARN -> 0.5   FAIL -> 0.0   UNKNOWN -> excluded
#   base  = 100 * (Sum weight*outcome) / (Sum weight over known controls)
#   score = min(base, min(Cap of every FAILING critical control))
#
# Emphasis: device-theft + malware resilience (encryption, Secure Boot, TPM,
# Defender, firewall dominate the weights). Tune weights/caps in $Map below.
# ----------------------------------------------------------------------------
function Get-PostureAssessment {

    param(
        [Parameter(Mandatory)]
        [object]$Checks,

        [bool]$IsAdmin = $true
    )

    # Cat  = exact Category; Pat = regex on the check name.
    # W    = weight; Cap = score ceiling if this control FAILs; Crit = critical.
    # Req  = this control MUST be assessed on every machine. If no check matches
    #        it, that is a BLIND SPOT, not a pass: its weight counts against
    #        coverage, it is listed as NOT EVALUATED, and a critical one applies
    #        its cap exactly as if it had failed. Absence of evidence is never
    #        treated as evidence of safety.
    # Name = human label used in the NOT EVALUATED report.
    $Map = @(
        @{ Cat = 'Boot Security';           Pat = '^Secure Boot$';                   W = 12; Cap = 55;  Crit = $true;  Req = $true;  Name = 'Secure Boot' }
        @{ Cat = 'Boot Security';           Pat = '^Firmware boot mode$';            W = 2;  Cap = 100; Crit = $false; Req = $true; Name = 'Firmware boot mode' }

        @{ Cat = 'TPM';                     Pat = '^TPM present$';                   W = 6;  Cap = 70;  Crit = $true;  Req = $true;  Name = 'TPM present' }
        @{ Cat = 'TPM';                     Pat = '^TPM specification$';             W = 2;  Cap = 100; Crit = $false; Req = $true; Name = 'TPM specification' }
        @{ Cat = 'TPM';                     Pat = '^TPM ready$';                     W = 2;  Cap = 100; Crit = $false; Req = $false; Name = 'TPM ready' }

        @{ Cat = 'Encryption';              Pat = '^OS volume';                      W = 20; Cap = 35;  Crit = $true;  Req = $true;  Name = 'OS drive encryption' }
        @{ Cat = 'Encryption';              Pat = '^Data volume';                    W = 8;  Cap = 65;  Crit = $true;  Req = $false; Name = 'Data drive encryption' }
        @{ Cat = 'Encryption';              Pat = 'encryption strength';             W = 3;  Cap = 100; Crit = $false; Req = $false; Name = 'Encryption strength' }
        @{ Cat = 'Encryption';              Pat = 'key protector';                   W = 3;  Cap = 100; Crit = $false; Req = $false; Name = 'Key protector quality' }

        @{ Cat = 'Antivirus';               Pat = '^Real-time antivirus protection$'; W = 8; Cap = 50;  Crit = $true;  Req = $true;  Name = 'Real-time antivirus' }

        @{ Cat = 'Virtualisation Security'; Pat = '^Virtualization Based Security$'; W = 4;  Cap = 100; Crit = $false; Req = $true; Name = 'VBS' }
        @{ Cat = 'Virtualisation Security'; Pat = '^Memory Integrity';               W = 5;  Cap = 100; Crit = $false; Req = $true; Name = 'Memory Integrity / HVCI' }
        @{ Cat = 'Virtualisation Security'; Pat = '^Credential Guard$';              W = 4;  Cap = 100; Crit = $false; Req = $true; Name = 'Credential Guard' }

        @{ Cat = 'Credential Protection';   Pat = '^LSA';                            W = 5;  Cap = 100; Crit = $false; Req = $true; Name = 'LSA protection' }

        @{ Cat = 'Defender';                Pat = '^Real-time protection$';          W = 3;  Cap = 100; Crit = $false; Req = $false; Name = 'Defender real-time' }
        @{ Cat = 'Defender';                Pat = '^Behaviour monitoring$';          W = 2;  Cap = 100; Crit = $false; Req = $false; Name = 'Behaviour monitoring' }
        @{ Cat = 'Defender';                Pat = '^Tamper Protection$';             W = 5;  Cap = 100; Crit = $false; Req = $false; Name = 'Tamper Protection' }
        @{ Cat = 'Defender';                Pat = '^Downloaded file scanning$';      W = 1;  Cap = 100; Crit = $false; Req = $false; Name = 'Downloaded file scanning' }
        @{ Cat = 'Defender';                Pat = '^Network Inspection System$';     W = 1;  Cap = 100; Crit = $false; Req = $false; Name = 'Network Inspection System' }
        @{ Cat = 'Defender';                Pat = '^Signature age$';                 W = 2;  Cap = 100; Crit = $false; Req = $false; Name = 'Signature age' }

        @{ Cat = 'Firewall';                Pat = '^Domain profile$';                        W = 1;  Cap = 55;  Crit = $true;  Req = $true;  Name = 'Domain firewall profile' }
        @{ Cat = 'Firewall';                Pat = '^Private profile$';                        W = 1;  Cap = 55;  Crit = $true;  Req = $true;  Name = 'Private firewall profile' }
        @{ Cat = 'Firewall';                Pat = '^Public profile$';                        W = 1;  Cap = 55;  Crit = $true;  Req = $true;  Name = 'Public firewall profile' }

        @{ Cat = 'SMB Security';            Pat = '^SMBv1';                          W = 5;  Cap = 60;  Crit = $true;  Req = $true;  Name = 'SMBv1 disabled' }
        @{ Cat = 'SMB Security';            Pat = 'signing required$';               W = 2;  Cap = 100; Crit = $false; Req = $false; Name = 'SMB signing' }
        @{ Cat = 'SMB Security';            Pat = 'guest logons$';                   W = 2;  Cap = 100; Crit = $false; Req = $false; Name = 'SMB guest logons' }

        @{ Cat = 'Privilege Protection';    Pat = '^User Account Control$';          W = 4;  Cap = 60;  Crit = $true; Req = $true;  Name = 'UAC' }
        @{ Cat = 'Privilege Protection';    Pat = '^Admin elevation';               W = 2;  Cap = 100; Crit = $false; Req = $false; Name = 'Admin elevation policy' }
        @{ Cat = 'Privilege Protection';    Pat = 'Secure Desktop$';                 W = 2;  Cap = 100; Crit = $false; Req = $false; Name = 'Secure Desktop' }

        @{ Cat = 'Remote Access';           Pat = 'Network Level Authentication$';   W = 4;  Cap = 60;  Crit = $true; Req = $false; Name = 'RDP NLA' }

        @{ Cat = 'System';                  Pat = '^Pending reboot$';                W = 1;  Cap = 100; Crit = $false; Req = $false; Name = 'Pending reboot' }
    )

    $Outcome = @{ 'PASS' = 1.0; 'WARN' = 0.5; 'FAIL' = 0.0 }

    $Earned = 0.0
    $Avail = 0.0
    $WeightTotal = 0.0
    $WeightKnown = 0.0
    $RequiredOrCriticalUnknown = $false

    # Use ::new() rather than New-Object: on PowerShell 7.6 a generic List built
    # via New-Object breaks the @() array operator ("Argument types do not match").
    $Caps = [System.Collections.Generic.List[int]]::new()
    $HardFails = [System.Collections.Generic.List[object]]::new()

    $NotEvaluated = [System.Collections.Generic.List[object]]::new()

    foreach ($Entry in $Map) {
        $Observed = @($Checks | Where-Object {
            $_.Category -eq $Entry.Cat -and $_.Check -match $Entry.Pat -and
                ($_.Status -eq 'UNKNOWN' -or $Outcome.ContainsKey($_.Status))
        })

        if ($Observed.Count -eq 0) {
            if (-not $Entry.Req) { continue }
            $NotEvaluated.Add([PSCustomObject]@{
                Control  = $Entry.Name
                Category = $Entry.Cat
                Weight   = $Entry.W
                Critical = $Entry.Crit
                Cap      = $Entry.Cap
            })
        }

        $W = [double]$Entry.W
        $WeightTotal += $W
        $Known = @($Observed | Where-Object { $Outcome.ContainsKey($_.Status) })
        $HasGap = $Observed.Count -eq 0 -or $Known.Count -lt $Observed.Count
        if ($HasGap) {
            if ($Entry.Req -or $Entry.Crit) { $RequiredOrCriticalUnknown = $true }
            if ($Entry.Crit) { $Caps.Add([int]$Entry.Cap) }
        }
        else {
            $WeightKnown += $W
        }

        # Score each control once using its weakest observed result.
        # Per-volume and per-component observations remain in the report.
        if ($Known.Count -gt 0) {
            $Worst = ($Known | ForEach-Object { $Outcome[$_.Status] } | Measure-Object -Minimum).Minimum
            $Avail += $W
            $Earned += $W * $Worst
        }

        if ($Entry.Crit) {
            foreach ($Check in $Known | Where-Object Status -eq 'FAIL') {
                $Caps.Add([int]$Entry.Cap)
                $HardFails.Add([PSCustomObject]@{
                    Category = $Check.Category
                    Check    = $Check.Check
                    Cap      = $Entry.Cap
                    Critical = $true
                })
            }
        }
    }

    $Base = if ($Avail -gt 0) { 100.0 * $Earned / $Avail } else { 0.0 }
    $Score = [int][math]::Round($Base)

    foreach ($C in $Caps) {
        if ($C -lt $Score) { $Score = $C }
    }
    if ($Score -lt 0) { $Score = 0 }
    if ($Score -gt 100) { $Score = 100 }

    $Coverage = if ($WeightTotal -gt 0) {
        [int][math]::Round(100.0 * $WeightKnown / $WeightTotal)
    }
    else {
        0
    }

    $Incomplete = (
        (-not $IsAdmin) -or
        $RequiredOrCriticalUnknown -or
        ($Coverage -lt 80)
    )

    # Never award a green band - or a green-looking number - on incomplete
    # evidence. An un-assessed machine is capped at GUARDED until it is
    # actually assessed.
    if ($Incomplete -and $Score -gt 74) {
        $Score = 74
    }

    $Band = Get-PostureBand -Score $Score

    # Sort hard fails: critical first, then by lowest cap.
    $HardFailsSorted = @(
        $HardFails |
        Sort-Object -Property @{ Expression = 'Critical'; Descending = $true }, @{ Expression = 'Cap'; Descending = $false }
    )

    return [PSCustomObject]@{
        Score        = $Score
        Band         = $Band.Name
        Colour       = $Band.Colour
        Verdict      = $Band.Verdict
        Coverage     = $Coverage
        Incomplete   = [bool]$Incomplete
        HardFails    = $HardFailsSorted
        NotEvaluated = @($NotEvaluated)
    }
}


function Write-SentinelBanner {

    param(
        [string]$Computer,
        [string]$User,
        [bool]$Admin
    )

    try {
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    }
    catch {}

    $Art = @(
        ' ____  _____ _   _ _____ ___ _   _ _____ _     ',
        '/ ___|| ____| \ | |_   _|_ _| \ | | ____| |    ',
        '\___ \|  _| |  \| | | |  | ||  \| |  _| | |    ',
        ' ___) | |___| |\  | | |  | || |\  | |___| |___ ',
        '|____/|_____|_| \_| |_| |___|_| \_|_____|_____|'
    )

    Write-Host ''
    foreach ($Line in $Art) {
        Write-Host $Line -ForegroundColor Cyan
    }
    Write-Host "     W I N D O W S   S E C U R I T Y   P O S T U R E   / /   v$script:SentinelVersion" -ForegroundColor DarkCyan
    Write-Host ''

    $AdminText = if ($Admin) { 'ELEVATED' } else { 'STANDARD  (results may be partial)' }
    $AdminCol  = if ($Admin) { 'Green' } else { 'Yellow' }

    Write-Host ('  HOST      : ' + $Computer)
    Write-Host ('  OPERATOR  : ' + $User)
    Write-Host  '  ELEVATION : ' -NoNewline
    Write-Host  $AdminText -ForegroundColor $AdminCol
    Write-Host ('  SCAN TIME : ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
    Write-Host ''
}


function Write-PostureGauge {

    param(
        [int]$Score,
        [string]$Band,
        [string]$Colour,
        [string]$Verdict,
        [int]$Coverage = 100,
        [bool]$Incomplete = $false,
        [object[]]$HardFails = @(),
        [object[]]$NotEvaluated = @(),
        $Summary
    )

    $Width  = 42
    $Filled = [int][math]::Round(($Width * $Score) / 100.0)
    if ($Filled -lt 0)      { $Filled = 0 }
    if ($Filled -gt $Width) { $Filled = $Width }
    $Bar = ('#' * $Filled) + ('-' * ($Width - $Filled))

    $BandText = if ($Incomplete) { "$Band  (INCOMPLETE)" } else { $Band }

    Write-Host ''
    Write-Host ('  ' + ('=' * 62)) -ForegroundColor DarkGray
    Write-Host '  SYSTEM INTEGRITY  ' -NoNewline
    Write-Host '[' -NoNewline -ForegroundColor DarkGray
    Write-Host $Bar -NoNewline -ForegroundColor $Colour
    Write-Host ']' -NoNewline -ForegroundColor DarkGray
    Write-Host ('  ' + $Score + '/100  ') -NoNewline
    Write-Host $BandText -ForegroundColor $Colour
    Write-Host ('  ' + $Verdict) -ForegroundColor DarkGray

    if ($Incomplete) {
        Write-Host (
            '  Coverage ' + $Coverage +
            '% - some controls could not be read. Re-run as Administrator for a full score.'
        ) -ForegroundColor DarkYellow
    }

    if ($HardFails.Count -gt 0) {
        Write-Host ''
        Write-Host '  HARD FAILS (each caps the score):' -ForegroundColor Red
        foreach ($HF in $HardFails) {
            Write-Host (
                '    x ' + $HF.Category + ' / ' + $HF.Check +
                '  -> score capped at ' + $HF.Cap
            ) -ForegroundColor Red
        }
    }

    if ($NotEvaluated.Count -gt 0) {
        Write-Host ''
        Write-Host '  NOT EVALUATED (blind spots - treated as unsafe, not as passes):' -ForegroundColor Magenta
        foreach ($NE in $NotEvaluated) {
            $Suffix =
                if ($NE.Critical) { '  -> critical; score capped at ' + $NE.Cap }
                else { '' }
            Write-Host (
                '    ? ' + $NE.Category + ' / ' + $NE.Control + $Suffix
            ) -ForegroundColor Magenta
        }
    }

    Write-Host ''
    Write-Host '  PASS '     -NoNewline -ForegroundColor Green
    Write-Host $Summary.Pass -NoNewline -ForegroundColor Green
    Write-Host '    WARN '   -NoNewline -ForegroundColor Yellow
    Write-Host $Summary.Warn -NoNewline -ForegroundColor Yellow
    Write-Host '    FAIL '   -NoNewline -ForegroundColor Red
    Write-Host $Summary.Fail -NoNewline -ForegroundColor Red
    Write-Host '    UNKNOWN ' -NoNewline -ForegroundColor DarkYellow
    Write-Host $Summary.Unknown -NoNewline -ForegroundColor DarkYellow
    Write-Host '    INFO '   -NoNewline -ForegroundColor Gray
    Write-Host $Summary.Info -ForegroundColor Gray
    Write-Host ('  ' + ('=' * 62)) -ForegroundColor DarkGray
}


function New-HtmlReport {

    param(
        [Parameter(Mandatory)]
        [object]$Report
    )

    $Json = ($Report | ConvertTo-Json -Depth 12)
    # JSON escaping alone is not safe inside <script>: '</script' ends the
    # element and '<!--' changes how the tokenizer reads it. These characters
    # can only occur inside JSON strings, so their \u escapes are equivalent.
    $Json = $Json.Replace('<', '\u003c').Replace('>', '\u003e').Replace('&', '\u0026')
    $Json = $Json.Replace([string][char]0x2028, '\u2028').Replace([string][char]0x2029, '\u2029')

    $Template = @'
<title>Sentinel Security Readout</title>
<style>
  :root{
    --bg:#08080f; --bg2:#0a0b16;
    --panel:#0e1020; --panel2:#12142a;
    --line:rgba(96,164,224,.16);
    --line-hot:rgba(61,240,255,.38);
    --text:#cdd8ef; --dim:#7182a6; --faint:#485774;
    --cyan:#3df0ff; --magenta:#ff2e88;
    --pass:#2fe38f; --warn:#ffc24d; --fail:#ff4368; --unknown:#b98cff; --info:#5fd0e6;
    --glow-cyan:0 0 12px rgba(61,240,255,.55);
    --glow-mag:0 0 12px rgba(255,46,136,.5);
    color-scheme:dark;
  }
  *{box-sizing:border-box}
  body{
    margin:0; background:var(--bg); color:var(--text);
    font-family:"JetBrains Mono",ui-monospace,monospace;
    -webkit-font-smoothing:antialiased;
    line-height:1.5;
    min-height:100vh;
  }
  /* ambient background layers */
  .void{position:fixed;inset:0;z-index:-3;background:
    radial-gradient(1200px 700px at 78% -10%, rgba(255,46,136,.10), transparent 60%),
    radial-gradient(1100px 800px at 12% 110%, rgba(61,240,255,.10), transparent 60%),
    var(--bg);}
  .grid-bg{position:fixed;inset:0;z-index:-2;pointer-events:none;opacity:.5;
    background-image:
      linear-gradient(rgba(96,164,224,.06) 1px, transparent 1px),
      linear-gradient(90deg, rgba(96,164,224,.06) 1px, transparent 1px);
    background-size:44px 44px;
    -webkit-mask-image:radial-gradient(ellipse 80% 60% at 50% 30%, #000 40%, transparent 100%);
            mask-image:radial-gradient(ellipse 80% 60% at 50% 30%, #000 40%, transparent 100%);}
  .scan{position:fixed;inset:0;z-index:100;pointer-events:none;
    background:repeating-linear-gradient(0deg, rgba(0,0,0,0) 0 2px, rgba(0,0,0,.16) 2px 3px);
    mix-blend-mode:multiply;opacity:.55;}
  .vign{position:fixed;inset:0;z-index:99;pointer-events:none;
    box-shadow:inset 0 0 220px rgba(0,0,0,.9), inset 0 0 60px rgba(0,0,0,.5);}

  .wrap{max-width:1180px;margin:0 auto;padding:26px 22px 80px;}

  /* ---- device banner ---- */
  .banner{
    border:1px solid var(--line);border-radius:4px;
    background:linear-gradient(180deg,var(--panel2),var(--panel));
    padding:14px 18px;display:flex;flex-wrap:wrap;align-items:center;gap:18px 26px;
    position:relative;overflow:hidden;
  }
  .banner::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;
    background:linear-gradient(180deg,var(--cyan),var(--magenta));box-shadow:var(--glow-cyan);}
  .brand{display:flex;align-items:baseline;gap:12px;font-family:"Chakra Petch",sans-serif;}
  .brand .mark{font-weight:700;font-size:26px;letter-spacing:.14em;color:#fff;
    text-shadow:0 0 8px rgba(61,240,255,.6);}
  .brand .mark b{color:var(--cyan)}
  .brand .ver{font-size:11px;color:var(--magenta);letter-spacing:.28em;border:1px solid rgba(255,46,136,.4);
    padding:2px 7px;border-radius:3px;}
  .banner .meta{display:flex;flex-wrap:wrap;gap:8px 22px;margin-left:auto;font-size:12px;}
  .banner .meta div{display:flex;flex-direction:column;gap:2px}
  .banner .meta span{color:var(--faint);letter-spacing:.16em;font-size:10px;text-transform:uppercase}
  .banner .meta b{color:var(--text);font-weight:500}
  .live{color:var(--pass)!important}
  .dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--pass);
    box-shadow:0 0 8px var(--pass);margin-right:6px;animation:pulse 2s infinite}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}

  /* ---- hero ---- */
  .hero{display:grid;grid-template-columns:300px 1fr;gap:16px;margin-top:16px}
  @media(max-width:760px){.hero{grid-template-columns:1fr}}
  .panel{border:1px solid var(--line);border-radius:4px;background:var(--panel);position:relative}
  .panel::after{content:"";position:absolute;inset:0;border-radius:4px;pointer-events:none;
    box-shadow:inset 0 0 40px rgba(61,240,255,.03)}
  .corner{position:absolute;width:10px;height:10px;border:1px solid var(--line-hot);opacity:.6}
  .corner.tl{top:-1px;left:-1px;border-right:0;border-bottom:0}
  .corner.tr{top:-1px;right:-1px;border-left:0;border-bottom:0}
  .corner.bl{bottom:-1px;left:-1px;border-right:0;border-top:0}
  .corner.br{bottom:-1px;right:-1px;border-left:0;border-top:0}

  .gauge{padding:18px 16px 20px;text-align:center;display:flex;flex-direction:column;align-items:center}
  .gauge h2{margin:0 0 6px;font-family:"Chakra Petch",sans-serif;font-weight:500;font-size:11px;
    letter-spacing:.28em;color:var(--dim);text-transform:uppercase}
  .ring{position:relative;width:220px;height:220px}
  .ring svg{transform:rotate(135deg)}
  .ring .val{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
  .ring .score{font-family:"Chakra Petch",sans-serif;font-weight:700;font-size:60px;line-height:1;color:#fff;
    text-shadow:0 0 18px rgba(61,240,255,.5)}
  .ring .score small{font-size:20px;color:var(--dim);font-weight:400}
  .ring .band{font-family:"Chakra Petch",sans-serif;letter-spacing:.2em;font-size:13px;margin-top:8px;font-weight:600;
    max-width:190px;margin-left:auto;margin-right:auto;line-height:1.35;text-align:center}
  .ring .band .inc{display:block;width:max-content;margin:5px auto 0;font-size:9px;letter-spacing:.18em;
    font-weight:700;color:var(--warn);border:1px solid rgba(255,194,77,.55);border-radius:2px;padding:1px 6px;
    text-shadow:none}
  .gauge .sub{font-size:11px;color:var(--faint);margin-top:14px;letter-spacing:.06em;max-width:230px}

  /* ---- stat tiles + distribution ---- */
  .right{display:flex;flex-direction:column;gap:16px}
  .tiles{display:grid;grid-template-columns:repeat(5,1fr);gap:10px}
  @media(max-width:560px){.tiles{grid-template-columns:repeat(2,1fr)}}
  .tile{border:1px solid var(--line);border-radius:4px;background:var(--panel);padding:12px 12px 11px;
    position:relative;overflow:hidden;cursor:pointer;transition:.18s;user-select:none}
  .tile:hover{border-color:var(--line-hot);transform:translateY(-2px)}
  .tile[aria-pressed="true"]{border-color:currentColor;box-shadow:inset 0 0 0 1px currentColor}
  .tile .n{font-family:"Chakra Petch",sans-serif;font-size:32px;font-weight:700;line-height:1;color:currentColor}
  .tile .l{font-size:10px;letter-spacing:.18em;text-transform:uppercase;color:var(--dim);margin-top:6px}
  .tile .bar{position:absolute;left:0;bottom:0;height:3px;width:100%;background:currentColor;opacity:.9}
  .t-pass{color:var(--pass)} .t-warn{color:var(--warn)} .t-fail{color:var(--fail)}
  .t-unknown{color:var(--unknown)} .t-info{color:var(--info)}

  .dist{border:1px solid var(--line);border-radius:4px;background:var(--panel);padding:14px 16px}
  .dist h3{margin:0 0 10px;font-family:"Chakra Petch",sans-serif;font-weight:500;font-size:10px;
    letter-spacing:.24em;text-transform:uppercase;color:var(--dim)}
  .segbar{height:14px;border-radius:3px;overflow:hidden;display:flex;background:#05060c;border:1px solid var(--line)}
  .segbar i{display:block;height:100%;transition:width .9s cubic-bezier(.2,.8,.2,1)}
  .legend{display:flex;flex-wrap:wrap;gap:6px 16px;margin-top:11px;font-size:11px;color:var(--dim)}
  .legend b{color:var(--text);font-weight:500}
  .legend .sw{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:6px;vertical-align:middle}

  /* ---- hard fails callout ---- */
  .hardfails{margin-top:22px;border:1px solid rgba(255,67,104,.4);border-radius:4px;
    background:linear-gradient(180deg,rgba(255,67,104,.10),rgba(255,67,104,.03));padding:14px 16px}
  .hardfails h3{margin:0 0 10px;font-family:"Chakra Petch",sans-serif;font-weight:600;font-size:12px;
    letter-spacing:.16em;text-transform:uppercase;color:var(--fail)}
  .hf-row{display:flex;align-items:center;gap:12px;padding:5px 0;font-size:13px;color:var(--text)}
  .hf-row+.hf-row{border-top:1px solid rgba(255,67,104,.14)}
  .hf-cap{flex:none;min-width:44px;text-align:center;font-family:"Chakra Petch",sans-serif;font-weight:700;
    color:var(--fail);border:1px solid rgba(255,67,104,.4);border-radius:2px;padding:2px 6px;font-size:12px}

  /* ---- not-evaluated callout ---- */
  .noteval{margin-top:16px;border:1px solid rgba(185,140,255,.42);border-radius:4px;
    background:linear-gradient(180deg,rgba(185,140,255,.10),rgba(185,140,255,.03));padding:14px 16px}
  .noteval h3{margin:0 0 10px;font-family:"Chakra Petch",sans-serif;font-weight:600;font-size:12px;
    letter-spacing:.16em;text-transform:uppercase;color:var(--unknown)}
  .ne-cap{flex:none;min-width:44px;text-align:center;font-family:"Chakra Petch",sans-serif;font-weight:700;
    color:var(--unknown);border:1px solid rgba(185,140,255,.42);border-radius:2px;padding:2px 6px;font-size:12px}
  .ne-foot{margin:10px 0 0;font-size:11px;line-height:1.6;color:var(--dim)}

  /* ---- filter bar ---- */
  .toolbar{display:flex;flex-wrap:wrap;align-items:center;gap:10px;margin:26px 0 14px}
  .toolbar .lbl{font-family:"Chakra Petch",sans-serif;font-size:11px;letter-spacing:.24em;color:var(--faint);text-transform:uppercase}
  .chip{font-family:"JetBrains Mono",monospace;font-size:11px;letter-spacing:.1em;color:var(--dim);
    background:var(--panel);border:1px solid var(--line);border-radius:3px;padding:6px 12px;cursor:pointer;transition:.15s}
  .chip:hover{color:var(--text);border-color:var(--line-hot)}
  .chip.on{color:var(--bg);background:var(--cyan);border-color:var(--cyan);font-weight:700;box-shadow:var(--glow-cyan)}

  /* ---- category panels ---- */
  .cat{margin-top:14px}
  .cat-head{display:flex;align-items:center;gap:14px;padding:11px 16px;cursor:pointer;
    border:1px solid var(--line);border-radius:4px;background:linear-gradient(180deg,var(--panel2),var(--panel));user-select:none}
  .cat-head:hover{border-color:var(--line-hot)}
  .cat-head .caret{color:var(--cyan);font-size:11px;transition:transform .2s;width:12px}
  .cat.collapsed .caret{transform:rotate(-90deg)}
  .cat-head h3{margin:0;font-family:"Chakra Petch",sans-serif;font-weight:600;font-size:14px;
    letter-spacing:.12em;text-transform:uppercase;color:var(--text)}
  .cat-head .idx{font-size:11px;color:var(--faint);font-family:"Chakra Petch",sans-serif;letter-spacing:.1em}
  .cat-head .mini{margin-left:auto;display:flex;gap:6px;font-size:10px}
  .cat-head .mini span{padding:2px 7px;border-radius:2px;letter-spacing:.08em;border:1px solid transparent}
  .m-pass{color:var(--pass);border-color:rgba(47,227,143,.3)!important;background:rgba(47,227,143,.08)}
  .m-warn{color:var(--warn);border-color:rgba(255,194,77,.3)!important;background:rgba(255,194,77,.08)}
  .m-fail{color:var(--fail);border-color:rgba(255,67,104,.3)!important;background:rgba(255,67,104,.08)}
  .rows{border:1px solid var(--line);border-top:0;border-radius:0 0 4px 4px;overflow:hidden}
  .cat.collapsed .rows{display:none}

  .row{display:grid;grid-template-columns:4px 78px 1fr auto;align-items:center;gap:14px;
    padding:9px 16px 9px 0;border-top:1px solid rgba(96,164,224,.07);background:var(--panel);position:relative}
  .rows .row:first-child{border-top:0}
  .row:hover{background:var(--panel2)}
  .row .stripe{align-self:stretch;width:4px}
  .row .st{font-size:10px;font-weight:700;letter-spacing:.12em;text-align:center;padding:3px 0;border-radius:2px}
  .row .name{color:var(--text);font-size:13px}
  .row .name em{color:var(--faint);font-style:normal;font-size:11px;display:block;margin-top:2px}
  .row .val{color:var(--dim);font-size:12px;text-align:right;padding-right:16px;white-space:nowrap;
    font-variant-numeric:tabular-nums}
  .row.has-detail{cursor:pointer}
  .row .val .exp{color:var(--faint);margin-left:8px;font-size:10px}
  .detail{grid-column:1/-1;padding:0 16px 0 96px;max-height:0;overflow:hidden;transition:max-height .25s ease;
    background:#080910}
  .detail.open{max-height:200px;padding-top:2px;padding-bottom:12px}
  .detail p{margin:8px 0 0;font-size:12px;color:var(--dim);border-left:2px solid var(--line-hot);padding-left:12px}
  .detail .kv{color:var(--faint)}
  .detail .kv b{color:var(--warn)}

  .s-PASS{color:var(--pass)} .bg-PASS{background:rgba(47,227,143,.12)} .stripe-PASS{background:var(--pass)}
  .s-WARN{color:var(--warn)} .bg-WARN{background:rgba(255,194,77,.13)} .stripe-WARN{background:var(--warn)}
  .s-FAIL{color:var(--fail)} .bg-FAIL{background:rgba(255,67,104,.14)} .stripe-FAIL{background:var(--fail)}
  .s-INFO{color:var(--info)} .bg-INFO{background:rgba(95,208,230,.10)} .stripe-INFO{background:rgba(95,208,230,.5)}
  .s-UNKNOWN{color:var(--unknown)} .bg-UNKNOWN{background:rgba(185,140,255,.12)} .stripe-UNKNOWN{background:var(--unknown)}

  .foot{margin-top:34px;text-align:center;color:var(--faint);font-size:11px;letter-spacing:.1em}
  .foot b{color:var(--dim)}
  .hidden{display:none!important}
  .sr-only{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0)}
  @media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style>

<div class="void"></div>
<div class="grid-bg"></div>
<div class="scan"></div>
<div class="vign"></div>

<h1 class="sr-only">Sentinel Windows security posture readout dashboard</h1>

<div class="wrap">

  <div class="banner">
    <span class="corner tl"></span><span class="corner tr"></span>
    <span class="corner bl"></span><span class="corner br"></span>
    <div class="brand">
      <div class="mark">SENTI<b>NEL</b></div>
      <div class="ver">POSTURE // v3</div>
    </div>
    <div class="meta">
      <div><span>Host</span><b id="m-host">—</b></div>
      <div><span>Operator</span><b id="m-user">—</b></div>
      <div><span>Elevation</span><b id="m-admin">—</b></div>
      <div><span>Scan time</span><b id="m-time">—</b></div>
      <div><span>Link</span><b class="live"><span class="dot"></span>SECURE</b></div>
    </div>
  </div>

  <div class="hero">
    <div class="panel gauge">
      <span class="corner tl"></span><span class="corner tr"></span>
      <span class="corner bl"></span><span class="corner br"></span>
      <h2>System Integrity</h2>
      <div class="ring">
        <svg width="220" height="220" viewBox="0 0 220 220" aria-hidden="true">
          <defs>
            <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0" stop-color="#3df0ff"/><stop offset="1" stop-color="#ff2e88"/>
            </linearGradient>
          </defs>
          <circle cx="110" cy="110" r="92" fill="none" stroke="#141830" stroke-width="12"
                  stroke-dasharray="433.5 578" stroke-linecap="round"/>
          <circle id="arc" cx="110" cy="110" r="92" fill="none" stroke="url(#g)" stroke-width="12"
                  stroke-linecap="round" stroke-dasharray="0 578"
                  style="filter:drop-shadow(0 0 6px rgba(61,240,255,.6))"/>
        </svg>
        <div class="val">
          <div class="score"><span id="score">0</span><small>/100</small></div>
          <div class="band" id="band">—</div>
        </div>
      </div>
      <div class="sub" id="verdict">Awaiting telemetry…</div>
    </div>

    <div class="right">
      <div class="tiles" id="tiles"></div>
      <div class="dist">
        <h3>Result Distribution</h3>
        <div class="segbar" id="segbar"></div>
        <div class="legend" id="legend"></div>
      </div>
    </div>
  </div>

  <div class="toolbar">
    <span class="lbl">Filter</span>
    <button class="chip on" data-f="ALL">ALL</button>
    <button class="chip" data-f="FAIL">FAIL</button>
    <button class="chip" data-f="WARN">WARN</button>
    <button class="chip" data-f="PASS">PASS</button>
    <button class="chip" data-f="INFO">INFO</button>
    <button class="chip" data-f="UNKNOWN">UNKNOWN</button>
  </div>

  <div id="cats"></div>

  <div class="foot">
    SENTINEL // READ-ONLY POSTURE ENGINE &nbsp;·&nbsp; nothing on this host was modified &nbsp;·&nbsp;
    generated <b id="f-time">—</b>
  </div>
</div>

<script>
/* ============================================================
   REPORT PAYLOAD
   In the real script this single object is emitted by:
     $Report | ConvertTo-Json -Depth 10
   and injected here. Everything below renders from it.
   Injected at export time by New-HtmlReport (from $Report | ConvertTo-Json).
   ============================================================ */
const REPORT = @@REPORT_JSON@@;

/* ---------- ordering + helpers ---------- */
const CAT_ORDER=["System","Boot Security","TPM","Encryption","Storage Health",
  "Virtualisation Security","Credential Protection","Antivirus","Defender","Firewall",
  "SMB Security","Remote Access","Privilege Protection","Collection"];
const SEV=["FAIL","WARN","UNKNOWN","INFO","PASS"];
const esc=s=>String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

const checks=REPORT.Checks;
const counts={PASS:0,WARN:0,FAIL:0,UNKNOWN:0,INFO:0};
checks.forEach(c=>counts[c.Status]!=null&&counts[c.Status]++);

/* Score, band, coverage and hard fails come straight from the PowerShell
   engine (REPORT.*) so the dashboard and the console can never disagree. */
const BANDCOL={HARDENED:"var(--pass)",FORTIFIED:"var(--cyan)",GUARDED:"var(--warn)",
  EXPOSED:"var(--fail)","AT RISK":"var(--fail)",CRITICAL:"var(--fail)"};
const score=REPORT.Score!=null?REPORT.Score:0;
const bandName=REPORT.Posture||"UNKNOWN";
const bandCol=BANDCOL[bandName]||"var(--dim)";
const incomplete=!!REPORT.Incomplete;
const coverage=REPORT.Coverage!=null?REPORT.Coverage:100;
const verdict=REPORT.Verdict||"";
const hardFails=REPORT.HardFails||[];
const notEvaluated=REPORT.NotEvaluated||[];

/* ---------- banner ---------- */
const $=id=>document.getElementById(id);
$("m-host").textContent=REPORT.ComputerName;
$("m-user").textContent=REPORT.UserName;
const adminEl=$("m-admin");
adminEl.textContent=REPORT.Administrator?"Administrator":"Standard";
adminEl.style.color=REPORT.Administrator?"var(--pass)":"var(--warn)";
const ts=new Date(REPORT.GeneratedAt);
const tstr=ts.toLocaleString(undefined,{year:"numeric",month:"short",day:"2-digit",hour:"2-digit",minute:"2-digit"});
$("m-time").textContent=tstr; $("f-time").textContent=tstr;

/* ---------- gauge ---------- */
const bandEl=$("band");
bandEl.innerHTML=esc(bandName)+(incomplete?'<span class="inc">INCOMPLETE</span>':"");
bandEl.style.color=bandCol;
bandEl.style.textShadow="0 0 12px "+bandCol;
$("verdict").innerHTML=esc(verdict)+(incomplete
  ?`<br><span style="color:var(--warn)">Coverage ${coverage}% — run as Administrator for a full score.</span>`:"");
const arc=document.getElementById("arc"), C=578, full=433.5; // 270deg of 2πr
arc.setAttribute("stroke",bandCol);
arc.style.filter="drop-shadow(0 0 6px "+bandCol+")";
const target=full*(score/100);
const scoreEl=document.getElementById("score");
const reduce=matchMedia("(prefers-reduced-motion:reduce)").matches;
if(reduce){arc.setAttribute("stroke-dasharray",target+" "+C);scoreEl.textContent=score;}
else{
  let t0=null;const dur=1400;
  const step=ts2=>{if(!t0)t0=ts2;const p=Math.min(1,(ts2-t0)/dur);const e=1-Math.pow(1-p,3);
    arc.setAttribute("stroke-dasharray",(full*(score/100)*e)+" "+C);
    scoreEl.textContent=Math.round(score*e);
    if(p<1)requestAnimationFrame(step);};
  requestAnimationFrame(step);
}

/* ---------- hard fails callout ---------- */
if(hardFails.length){
  const hf=document.createElement("div");
  hf.className="hardfails";
  hf.innerHTML=`<h3>&#9888; HARD FAILS — each caps the score</h3>`+hardFails.map(h=>
    `<div class="hf-row"><span class="hf-cap">&#8804;${h.Cap}</span>`+
    `<span class="hf-name">${esc(h.Category)} / ${esc(h.Check)}</span></div>`).join("");
  const tb=document.querySelector(".toolbar");
  tb.parentNode.insertBefore(hf,tb);
}

/* ---------- blind spots (controls never assessed) ---------- */
if(notEvaluated.length){
  const ne=document.createElement("div");
  ne.className="noteval";
  ne.innerHTML=`<h3>&#9633; NOT EVALUATED — blind spots, treated as unsafe</h3>`+notEvaluated.map(n=>
    `<div class="hf-row"><span class="ne-cap">${n.Critical?"&#8804;"+n.Cap:"—"}</span>`+
    `<span class="hf-name">${esc(n.Category)} / ${esc(n.Control)}</span></div>`).join("")+
    `<p class="ne-foot">These controls produced no result, so Sentinel could not confirm them. `+
    `They are never counted as passes — critical ones cap the score exactly as a failure would.</p>`;
  const tb2=document.querySelector(".toolbar");
  tb2.parentNode.insertBefore(ne,tb2);
}

/* ---------- stat tiles ---------- */
const TILE=[["PASS","t-pass"],["WARN","t-warn"],["FAIL","t-fail"],["UNKNOWN","t-unknown"],["INFO","t-info"]];
document.getElementById("tiles").innerHTML=TILE.map(([k,c])=>
  `<div class="tile ${c}" data-f="${k}" role="button" tabindex="0" aria-pressed="false">
     <div class="n">${counts[k]}</div><div class="l">${k}</div><div class="bar"></div></div>`).join("");

/* ---------- distribution bar ---------- */
const total=checks.length;
const SEG=[["PASS","var(--pass)"],["WARN","var(--warn)"],["FAIL","var(--fail)"],["UNKNOWN","var(--unknown)"],["INFO","var(--info)"]];
document.getElementById("segbar").innerHTML=SEG.map(([k,col])=>
  counts[k]?`<i style="width:${100*counts[k]/total}%;background:${col};box-shadow:0 0 10px ${col}"></i>`:"").join("");
document.getElementById("legend").innerHTML=SEG.map(([k,col])=>
  `<span><span class="sw" style="background:${col}"></span>${k} <b>${counts[k]}</b></span>`).join("");

/* ---------- category panels ---------- */
const cats={};
checks.forEach(c=>{(cats[c.Category]=cats[c.Category]||[]).push(c);});
const order=[...CAT_ORDER.filter(c=>cats[c]),...Object.keys(cats).filter(c=>!CAT_ORDER.includes(c))];
const host=document.getElementById("cats");
order.forEach((cat,i)=>{
  const rows=cats[cat];
  const cc={PASS:0,WARN:0,FAIL:0};
  rows.forEach(r=>cc[r.Status]!=null&&cc[r.Status]++);
  const mini=[cc.FAIL?`<span class="m-fail">${cc.FAIL} FAIL</span>`:"",
              cc.WARN?`<span class="m-warn">${cc.WARN} WARN</span>`:"",
              cc.PASS?`<span class="m-pass">${cc.PASS} PASS</span>`:""].join("");
  const rowsHtml=rows.map(r=>{
    const d=r.Details?`<div class="detail"><p>${r.Expected?`<span class="kv">Expected: <b>${esc(r.Expected)}</b></span><br>`:""}${esc(r.Details)}</p></div>`:"";
    const st=SEV.includes(r.Status)?r.Status:"UNKNOWN";
    return `<div class="row ${r.Details?"has-detail":""}" data-status="${st}">
        <div class="stripe stripe-${st}"></div>
        <div class="st s-${st} bg-${st}">${st}</div>
        <div class="name">${esc(r.Check)}</div>
        <div class="val">${esc(r.Value)}${r.Details?'<span class="exp">▸</span>':""}</div>
        ${d}</div>`;
  }).join("");
  const idx=String(i+1).padStart(2,"0");
  host.insertAdjacentHTML("beforeend",
    `<div class="cat" data-cat="${esc(cat)}">
      <div class="cat-head"><span class="caret">▼</span>
        <span class="idx">${idx}</span><h3>${esc(cat)}</h3>
        <div class="mini">${mini}</div></div>
      <div class="rows">${rowsHtml}</div></div>`);
});

/* ---------- interactions ---------- */
host.addEventListener("click",e=>{
  const head=e.target.closest(".cat-head");
  if(head){head.parentElement.classList.toggle("collapsed");return;}
  const row=e.target.closest(".row.has-detail");
  if(row){const d=row.querySelector(".detail");if(d)d.classList.toggle("open");}
});

let filter="ALL";
function applyFilter(f){
  filter=f;
  document.querySelectorAll(".chip").forEach(c=>c.classList.toggle("on",c.dataset.f===f));
  document.querySelectorAll(".tile").forEach(t=>t.setAttribute("aria-pressed",t.dataset.f===f));
  document.querySelectorAll(".cat").forEach(cat=>{
    let shown=0;
    cat.querySelectorAll(".row").forEach(r=>{
      const vis=(f==="ALL"||r.dataset.status===f);
      r.classList.toggle("hidden",!vis); if(vis)shown++;
    });
    cat.classList.toggle("hidden",shown===0);
  });
}
document.querySelectorAll(".chip").forEach(c=>c.addEventListener("click",()=>applyFilter(c.dataset.f)));
document.getElementById("tiles").addEventListener("click",e=>{
  const t=e.target.closest(".tile"); if(t)applyFilter(filter===t.dataset.f?"ALL":t.dataset.f);
});
document.getElementById("tiles").addEventListener("keydown",e=>{
  if(e.key==="Enter"||e.key===" "){e.preventDefault();const t=e.target.closest(".tile");if(t)applyFilter(filter===t.dataset.f?"ALL":t.dataset.f);}
});
</script>

'@

    return $Template.Replace('@@REPORT_JSON@@', $Json)
}


# ============================================================================
# EXECUTION CONTEXT
# ============================================================================

$IsAdmin =
    Test-IsAdministrator


if ($IsAdmin) {

    Add-Check `
        -Category 'Collection' `
        -Name 'Administrator context' `
        -Status 'INFO' `
        -Value 'Elevated' `
        -Details 'Full collection should be available.'
}
else {

    Add-Check `
        -Category 'Collection' `
        -Name 'Administrator context' `
        -Status 'WARN' `
        -Value 'Not elevated' `
        -Expected 'Run as Administrator' `
        -Details (
            'Some firmware, BitLocker, Defender and security ' +
            'queries may return incomplete results.'
        )
}


Add-Check `
    -Category 'Collection' `
    -Name 'PowerShell' `
    -Status 'INFO' `
    -Value (
        "$($PSVersionTable.PSEdition) " +
        "$($PSVersionTable.PSVersion)"
    )


# ============================================================================
# SYSTEM INFORMATION
# ============================================================================

$OperatingSystem = $null
$ComputerSystem = $null
$BIOS = $null
$Processor = $null


try {

    $OperatingSystem =
        Get-CimInstance `
            -ClassName Win32_OperatingSystem `
            -ErrorAction Stop

    $ComputerSystem =
        Get-CimInstance `
            -ClassName Win32_ComputerSystem `
            -ErrorAction Stop

    $BIOS =
        Get-CimInstance `
            -ClassName Win32_BIOS `
            -ErrorAction Stop

    $Processor =
        Get-CimInstance `
            -ClassName Win32_Processor `
            -ErrorAction Stop |
        Select-Object -First 1


    $CurrentVersionPath =
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'


    $DisplayVersion =
        Get-RegistryValue `
            -Path $CurrentVersionPath `
            -Name 'DisplayVersion'


    if (-not $DisplayVersion) {

        $DisplayVersion =
            Get-RegistryValue `
                -Path $CurrentVersionPath `
                -Name 'ReleaseId'
    }


    $UBR =
        Get-RegistryValue `
            -Path $CurrentVersionPath `
            -Name 'UBR'


    $BuildString =
        [string]$OperatingSystem.BuildNumber


    if ($null -ne $UBR) {
        $BuildString += ".$UBR"
    }


    $OSString =
        [string]$OperatingSystem.Caption


    if ($DisplayVersion) {
        $OSString += " $DisplayVersion"
    }


    $OSString += " (Build $BuildString)"


    Add-Check `
        -Category 'System' `
        -Name 'Operating system' `
        -Status 'INFO' `
        -Value $OSString


    Add-Check `
        -Category 'System' `
        -Name 'Hardware' `
        -Status 'INFO' `
        -Value (
            "$($ComputerSystem.Manufacturer) " +
            "$($ComputerSystem.Model)"
        )


    if ($Processor) {

        Add-Check `
            -Category 'System' `
            -Name 'Processor' `
            -Status 'INFO' `
            -Value (
                ([string]$Processor.Name).Trim()
            )
    }


    if ($ComputerSystem.TotalPhysicalMemory) {

        $RAMGB =
            [math]::Round(
                (
                    [double]$ComputerSystem.TotalPhysicalMemory /
                    1GB
                ),
                1
            )

        Add-Check `
            -Category 'System' `
            -Name 'Installed memory' `
            -Status 'INFO' `
            -Value "$RAMGB GB"
    }


    $BIOSDate = 'Unknown'

    if ($BIOS.ReleaseDate) {

        try {

            $BIOSDate =
                ([datetime]$BIOS.ReleaseDate).ToString(
                    'yyyy-MM-dd'
                )
        }
        catch {}
    }


    Add-Check `
        -Category 'System' `
        -Name 'BIOS / firmware' `
        -Status 'INFO' `
        -Value (
            "$($BIOS.SMBIOSBIOSVersion) " +
            "($BIOSDate)"
        )
}
catch {

    Add-Check `
        -Category 'System' `
        -Name 'System information' `
        -Status 'UNKNOWN' `
        -Value 'Collection failed' `
        -Details $_.Exception.Message
}


# ============================================================================
# SUPPORT DIAGNOSTICS
# ============================================================================

try {
    if ($null -eq $OperatingSystem) { throw 'Windows operating system data is unavailable.' }
    $boot = [datetime]$OperatingSystem.LastBootUpTime
    $uptime = (Get-Date) - $boot
    Add-Check -Category 'Diagnostics' -Name 'System uptime' -Status 'INFO' `
        -Value ('{0:N1} days' -f $uptime.TotalDays) -Details ('Last boot: ' + $boot.ToString('o'))
}
catch {
    Add-Check -Category 'Diagnostics' -Name 'System uptime' -Status 'UNKNOWN' `
        -Value 'Collection failed' -Details $_.Exception.Message
}

try {
    $systemDisk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'" -ErrorAction Stop
    if ($null -eq $systemDisk -or $null -eq $systemDisk.FreeSpace -or $systemDisk.Size -le 0) {
        throw 'System volume size or free space is unavailable.'
    }
    $free = [double]$systemDisk.FreeSpace
    $percent = 100 * $free / $systemDisk.Size
    $status = if ($free -lt 5GB) { 'WARN' } else { 'INFO' }
    Add-Check -Category 'Diagnostics' -Name 'System drive free space' -Status $status `
        -Value ('{0}: {1:N1} GiB free ({2:N1}%)' -f $systemDisk.DeviceID, ($free / 1GB), $percent) `
        -Details 'Sentinel flags less than 5 GiB for maintenance. This check does not affect the security score.'
}
catch {
    Add-Check -Category 'Diagnostics' -Name 'System drive free space' -Status 'UNKNOWN' `
        -Value 'Collection failed' -Details $_.Exception.Message
}

try {
    $latestFix = Get-HotFix -ErrorAction Stop |
        Where-Object { $_.InstalledOn -is [datetime] -and $_.InstalledOn -gt [datetime]::MinValue } |
        Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($null -eq $latestFix) { throw 'The hotfix inventory returned no dated entries.' }
    Add-Check -Category 'Diagnostics' -Name 'Latest dated Windows hotfix' -Status 'INFO' `
        -Value ('{0} ({1:yyyy-MM-dd})' -f $latestFix.HotFixID, $latestFix.InstalledOn) `
        -Details 'Get-HotFix inventory is partial. Use your update management service to assess patch compliance.'
}
catch {
    Add-Check -Category 'Diagnostics' -Name 'Latest dated Windows hotfix' -Status 'UNKNOWN' `
        -Value 'Date unavailable' -Details $_.Exception.Message
}


# ============================================================================
# PENDING REBOOT
# ============================================================================

try {

    $PendingReboot =
        Test-PendingReboot

    if ($PendingReboot.Pending) {

        Add-Check `
            -Category 'System' `
            -Name 'Pending reboot' `
            -Status 'WARN' `
            -Value 'Yes' `
            -Expected 'No' `
            -Details $PendingReboot.Reasons
    }
    else {

        Add-Check `
            -Category 'System' `
            -Name 'Pending reboot' `
            -Status 'PASS' `
            -Value 'No'
    }
}
catch {

    Add-Check `
        -Category 'System' `
        -Name 'Pending reboot' `
        -Status 'UNKNOWN' `
        -Value 'Unable to determine' `
        -Details $_.Exception.Message
}


# ============================================================================
# FIRMWARE MODE
# ============================================================================

$FirmwareMode =
    Get-FirmwareMode


switch ($FirmwareMode) {

    'UEFI' {

        Add-Check `
            -Category 'Boot Security' `
            -Name 'Firmware boot mode' `
            -Status 'PASS' `
            -Value 'UEFI' `
            -Expected 'UEFI'
    }

    'BIOS' {

        Add-Check `
            -Category 'Boot Security' `
            -Name 'Firmware boot mode' `
            -Status 'WARN' `
            -Value 'Legacy BIOS' `
            -Expected 'UEFI'
    }

    default {

        Add-Check `
            -Category 'Boot Security' `
            -Name 'Firmware boot mode' `
            -Status 'UNKNOWN' `
            -Value 'Unable to determine'
    }
}


# ============================================================================
# SECURE BOOT
# ============================================================================

$SecureBootKnown = $false
$SecureBootEnabled = $false
$SecureBootSource = ''


if (
    $FirmwareMode -eq 'UEFI' -and
    (Test-CommandExists 'Confirm-SecureBootUEFI')
) {

    try {

        $SecureBootEnabled =
            [bool](
                Confirm-SecureBootUEFI `
                    -ErrorAction Stop
            )

        $SecureBootKnown = $true
        $SecureBootSource =
            'Confirm-SecureBootUEFI'
    }
    catch {

        $SecureBootSource =
            $_.Exception.Message
    }
}


if (-not $SecureBootKnown) {

    $RegistrySecureBoot =
        Get-RegistryValue `
            -Path (
                'HKLM:\SYSTEM\CurrentControlSet\' +
                'Control\SecureBoot\State'
            ) `
            -Name 'UEFISecureBootEnabled'


    if ($null -ne $RegistrySecureBoot) {

        $SecureBootEnabled =
            ([int]$RegistrySecureBoot -eq 1)

        $SecureBootKnown = $true

        $SecureBootSource =
            'Registry fallback'
    }
}


if ($SecureBootKnown) {

    if ($SecureBootEnabled) {

        Add-Check `
            -Category 'Boot Security' `
            -Name 'Secure Boot' `
            -Status 'PASS' `
            -Value 'Enabled' `
            -Expected 'Enabled' `
            -Details $SecureBootSource
    }
    else {

        Add-Check `
            -Category 'Boot Security' `
            -Name 'Secure Boot' `
            -Status 'FAIL' `
            -Value 'Disabled' `
            -Expected 'Enabled' `
            -Details $SecureBootSource
    }
}
elseif ($FirmwareMode -eq 'BIOS') {

    Add-Check `
        -Category 'Boot Security' `
        -Name 'Secure Boot' `
        -Status 'WARN' `
        -Value 'Unavailable under legacy BIOS' `
        -Expected 'UEFI with Secure Boot'
}
else {

    Add-Check `
        -Category 'Boot Security' `
        -Name 'Secure Boot' `
        -Status 'UNKNOWN' `
        -Value 'Unable to determine' `
        -Details $SecureBootSource
}


# ============================================================================
# TPM
# ============================================================================

# TPM interfaces are gathered from three sources. Get-Tpm and the Win32_Tpm
# CIM class both require elevation (they throw Access Denied otherwise), so
# Get-PnpDevice -Class SecurityDevices - which works WITHOUT elevation - is
# the presence/version fallback. A TPM is only reported ABSENT on positive
# evidence (a successful device query that found none); if every interface is
# inaccessible the result is UNKNOWN, never a false FAIL.

$TPMNative = $null
$TPMCim    = $null
$TPMPnp    = $null
$TPMPnpQueried = $false


if (Test-CommandExists 'Get-Tpm') {

    try {
        $TPMNative =
            Get-Tpm `
                -ErrorAction Stop
    }
    catch {}
}


# Get-Tpm is unreliable without elevation: instead of throwing it can return
# an object reporting TpmPresent=$false. Ignore it unless elevated so a false
# reading can never override the unprivileged PnP evidence below.
if (-not $IsAdmin) {
    $TPMNative = $null
}


try {
    $TPMCim =
        Get-CimInstance `
            -Namespace 'Root\CIMv2\Security\MicrosoftTpm' `
            -ClassName Win32_Tpm `
            -ErrorAction Stop
}
catch {}


if (Test-CommandExists 'Get-PnpDevice') {

    try {

        $SecurityDevices =
            @(
                Get-PnpDevice `
                    -Class SecurityDevices `
                    -ErrorAction Stop
            )

        $TPMPnpQueried = $true

        $TPMPnp =
            $SecurityDevices |
            Where-Object {
                $_.FriendlyName -match 'Trusted Platform|TPM'
            } |
            Select-Object -First 1
    }
    catch {}
}


# ---- presence ----
# Positive evidence from any source wins. Only conclude "absent" when the
# unprivileged security-device query ran and found no TPM (and nothing else
# affirmed one), or when elevated Get-Tpm explicitly reports none.

$NativePresent = $null
if ($TPMNative -and (Test-ObjectProperty $TPMNative 'TpmPresent')) {
    $NativePresent = [bool]$TPMNative.TpmPresent
}

$TPMPresent = $null

if (($NativePresent -eq $true) -or $TPMCim -or $TPMPnp) {
    $TPMPresent = $true
}
elseif ($TPMPnpQueried) {
    # Security-device enumeration succeeded and found no TPM -> genuinely absent.
    $TPMPresent = $false
}
elseif ($NativePresent -eq $false) {
    $TPMPresent = $false
}


# ---- version ----

$TPMVersion = $null

if ($TPMCim -and (Test-ObjectProperty $TPMCim 'SpecVersion') -and $TPMCim.SpecVersion) {

    $SpecVersion = [string]$TPMCim.SpecVersion

    if ($SpecVersion -match '2\.0')      { $TPMVersion = '2.0' }
    elseif ($SpecVersion -match '1\.2')  { $TPMVersion = '1.2' }
}

if (
    -not $TPMVersion -and
    $TPMPnp -and
    (Test-ObjectProperty $TPMPnp 'FriendlyName') -and
    $TPMPnp.FriendlyName
) {
    if ($TPMPnp.FriendlyName -match '2\.0')     { $TPMVersion = '2.0' }
    elseif ($TPMPnp.FriendlyName -match '1\.2') { $TPMVersion = '1.2' }
}


# ---- present check ----

if ($null -eq $TPMPresent) {

    Add-Check `
        -Category 'TPM' `
        -Name 'TPM present' `
        -Status 'UNKNOWN' `
        -Value 'Unable to determine' `
        -Expected 'TPM 2.0' `
        -Details 'All TPM interfaces were inaccessible. Re-run as Administrator.'
}
elseif ($TPMPresent) {

    $TPMSource =
        if ($TPMNative)  { 'Get-Tpm' }
        elseif ($TPMCim) { 'Win32_Tpm' }
        else             { 'PnP security device' }

    $TPMPresentValue =
        if ($TPMVersion) { "Yes (TPM $TPMVersion)" } else { 'Yes' }

    Add-Check `
        -Category 'TPM' `
        -Name 'TPM present' `
        -Status 'PASS' `
        -Value $TPMPresentValue `
        -Expected 'Yes' `
        -Details "Detected via $TPMSource."
}
else {

    Add-Check `
        -Category 'TPM' `
        -Name 'TPM present' `
        -Status 'FAIL' `
        -Value 'No' `
        -Expected 'TPM 2.0' `
        -Details 'No TPM security device found. BitLocker cannot bind keys to hardware.'
}


# ---- specification / version ----

if ($TPMVersion) {

    $TPMSpecStatus =
        if ($TPMVersion -eq '2.0') { 'PASS' } else { 'WARN' }

    $TPMSpecDetails =
        if ($TPMVersion -eq '1.2') {
            'TPM 1.2 is deprecated; Windows 11 and modern attestation expect 2.0.'
        }
        else { '' }

    Add-Check `
        -Category 'TPM' `
        -Name 'TPM specification' `
        -Status $TPMSpecStatus `
        -Value "TPM $TPMVersion" `
        -Expected 'TPM 2.0' `
        -Details $TPMSpecDetails
}
elseif ($TPMPresent) {

    Add-Check `
        -Category 'TPM' `
        -Name 'TPM specification' `
        -Status 'UNKNOWN' `
        -Value 'Version not readable' `
        -Expected 'TPM 2.0'
}


# ---- enabled / activated (only when the privileged data is available) ----

$TPMEnabled = $null
$TPMActivated = $null

if ($TPMNative) {
    if (Test-ObjectProperty $TPMNative 'TpmEnabled')   { $TPMEnabled   = [bool]$TPMNative.TpmEnabled }
    if (Test-ObjectProperty $TPMNative 'TpmActivated') { $TPMActivated = [bool]$TPMNative.TpmActivated }
}
if ($null -eq $TPMEnabled -and $TPMCim -and (Test-ObjectProperty $TPMCim 'IsEnabled_InitialValue')) {
    $TPMEnabled = [bool]$TPMCim.IsEnabled_InitialValue
}
if ($null -eq $TPMActivated -and $TPMCim -and (Test-ObjectProperty $TPMCim 'IsActivated_InitialValue')) {
    $TPMActivated = [bool]$TPMCim.IsActivated_InitialValue
}

if ($TPMPresent -and ($TPMEnabled -eq $false -or $TPMActivated -eq $false)) {

    Add-Check `
        -Category 'TPM' `
        -Name 'TPM enabled' `
        -Status 'WARN' `
        -Value "Enabled=$TPMEnabled; Activated=$TPMActivated" `
        -Expected 'Enabled and activated' `
        -Details 'TPM is present but not enabled/activated in firmware. Enable it in UEFI/BIOS setup.'
}


# ---- ready ----

if ($TPMNative -and (Test-ObjectProperty $TPMNative 'TpmReady')) {

    if ($TPMNative.TpmReady) {

        Add-Check `
            -Category 'TPM' `
            -Name 'TPM ready' `
            -Status 'PASS' `
            -Value 'Yes'
    }
    else {

        Add-Check `
            -Category 'TPM' `
            -Name 'TPM ready' `
            -Status 'WARN' `
            -Value 'No' `
            -Expected 'Ready' `
            -Details 'TPM present but not fully provisioned/owned by Windows.'
    }
}
elseif ($TPMPresent -and -not $IsAdmin) {

    Add-Check `
        -Category 'TPM' `
        -Name 'TPM ready' `
        -Status 'UNKNOWN' `
        -Value 'Requires elevation' `
        -Details 'Run as Administrator to read TPM readiness.'
}


if ($TPMNative) {

    $Manufacturer =
        Get-PropertyValue `
            -Object $TPMNative `
            -Property 'ManufacturerIdTxt'


    $ManufacturerVersion =
        Get-PropertyValue `
            -Object $TPMNative `
            -Property 'ManufacturerVersion'


    if ($Manufacturer) {

        Add-Check `
            -Category 'TPM' `
            -Name 'TPM manufacturer' `
            -Status 'INFO' `
            -Value (
                "$Manufacturer $ManufacturerVersion"
            )
    }


    if (
        Test-ObjectProperty `
            -Object $TPMNative `
            -Property 'LockedOut'
    ) {

        if ($TPMNative.LockedOut) {

            Add-Check `
                -Category 'TPM' `
                -Name 'TPM lockout' `
                -Status 'FAIL' `
                -Value 'Locked out'
        }
        else {

            Add-Check `
                -Category 'TPM' `
                -Name 'TPM lockout' `
                -Status 'PASS' `
                -Value 'Not locked out'
        }
    }


    if (
        Test-ObjectProperty `
            -Object $TPMNative `
            -Property 'RestartPending'
    ) {

        if ($TPMNative.RestartPending) {

            Add-Check `
                -Category 'TPM' `
                -Name 'TPM restart pending' `
                -Status 'WARN' `
                -Value 'Yes'
        }
    }
}


# ============================================================================
# MOUNTED VOLUME INVENTORY
# ============================================================================

if (Test-CommandExists 'Get-Volume') {

    try {

        $RawVolumes =
            @(
                Get-Volume `
                    -ErrorAction Stop
            )


        foreach ($Volume in $RawVolumes) {

            $DriveLetterRaw =
                Get-PropertyValue `
                    -Object $Volume `
                    -Property 'DriveLetter'


            $DriveLetter =
                if ($DriveLetterRaw) {
                    [string]$DriveLetterRaw
                }
                else {
                    ''
                }


            $MountPoint =
                if ($DriveLetter) {
                    "$DriveLetter`:"
                }
                else {
                    ''
                }


            $Partition =
                if ($DriveLetter) {
                    Get-PartitionMetadata `
                        -DriveLetter $DriveLetter
                }
                else {
                    $null
                }


            $IsHidden =
                if ($Partition) {
                    [bool](
                        Get-PropertyValue `
                            -Object $Partition `
                            -Property 'IsHidden' `
                            -Default $false
                    )
                }
                else {
                    $false
                }


            $PartitionNumber =
                if ($Partition) {
                    Get-PropertyValue `
                        -Object $Partition `
                        -Property 'PartitionNumber'
                }
                else {
                    $null
                }


            $DiskNumber =
                if ($Partition) {
                    Get-PropertyValue `
                        -Object $Partition `
                        -Property 'DiskNumber'
                }
                else {
                    $null
                }


            $OperationalStatus =
                ConvertTo-JoinedString (
                    Get-PropertyValue `
                        -Object $Volume `
                        -Property 'OperationalStatus'
                )


            $VolumeObject = [PSCustomObject]@{
                DriveLetter       = $DriveLetter
                MountPoint        = $MountPoint
                Label             = [string](
                    Get-PropertyValue `
                        -Object $Volume `
                        -Property 'FileSystemLabel'
                )
                FileSystem        = [string](
                    Get-PropertyValue `
                        -Object $Volume `
                        -Property 'FileSystem'
                )
                DriveType         = [string](
                    Get-PropertyValue `
                        -Object $Volume `
                        -Property 'DriveType'
                )
                HealthStatus      = [string](
                    Get-PropertyValue `
                        -Object $Volume `
                        -Property 'HealthStatus'
                )
                OperationalStatus = $OperationalStatus
                SizeGB            = if (
                    Get-PropertyValue `
                        -Object $Volume `
                        -Property 'Size'
                ) {
                    [math]::Round(
                        (
                            [double]$Volume.Size /
                            1GB
                        ),
                        2
                    )
                }
                else {
                    $null
                }
                FreeGB            = if (
                    $null -ne (
                        Get-PropertyValue `
                            -Object $Volume `
                            -Property 'SizeRemaining'
                    )
                ) {
                    [math]::Round(
                        (
                            [double]$Volume.SizeRemaining /
                            1GB
                        ),
                        2
                    )
                }
                else {
                    $null
                }
                DiskNumber        = $DiskNumber
                PartitionNumber   = $PartitionNumber
                IsHidden          = $IsHidden
                Path              = [string](
                    Get-PropertyValue `
                        -Object $Volume `
                        -Property 'Path'
                )
            }


            $script:Volumes.Add(
                $VolumeObject
            )


            if (
                $MountPoint -and
                -not $IsHidden -and
                $VolumeObject.DriveType -eq 'Fixed'
            ) {

                switch ($VolumeObject.HealthStatus) {

                    'Healthy' {

                        Add-Check `
                            -Category 'Storage Health' `
                            -Name "Volume $MountPoint" `
                            -Status 'PASS' `
                            -Value 'Healthy' `
                            -Details (
                                "$($VolumeObject.FileSystem); " +
                                "$($VolumeObject.SizeGB) GB"
                            )
                    }

                    'Warning' {

                        Add-Check `
                            -Category 'Storage Health' `
                            -Name "Volume $MountPoint" `
                            -Status 'WARN' `
                            -Value 'Warning' `
                            -Details $OperationalStatus
                    }

                    'Unhealthy' {

                        Add-Check `
                            -Category 'Storage Health' `
                            -Name "Volume $MountPoint" `
                            -Status 'FAIL' `
                            -Value 'Unhealthy' `
                            -Details $OperationalStatus
                    }

                    default {

                        Add-Check `
                            -Category 'Storage Health' `
                            -Name "Volume $MountPoint" `
                            -Status 'INFO' `
                            -Value $(
                                if ($VolumeObject.HealthStatus) {
                                    $VolumeObject.HealthStatus
                                }
                                else {
                                    'Unknown'
                                }
                            ) `
                            -Details $OperationalStatus
                    }
                }
            }
        }
    }
    catch {

        Add-Check `
            -Category 'Storage Health' `
            -Name 'Volume inventory' `
            -Status 'UNKNOWN' `
            -Value 'Collection failed' `
            -Details $_.Exception.Message
    }
}


# ============================================================================
# PHYSICAL DISK INVENTORY
# ============================================================================

if (Test-CommandExists 'Get-PhysicalDisk') {

    try {

        $RawPhysicalDisks =
            @(
                Get-PhysicalDisk `
                    -ErrorAction Stop
            )


        foreach ($Disk in $RawPhysicalDisks) {

            $OperationalStatus =
                ConvertTo-JoinedString (
                    Get-PropertyValue `
                        -Object $Disk `
                        -Property 'OperationalStatus'
                )


            $DeviceId =
                [string](
                    Get-PropertyValue `
                        -Object $Disk `
                        -Property 'DeviceId'
                )


            $FriendlyName =
                [string](
                    Get-PropertyValue `
                        -Object $Disk `
                        -Property 'FriendlyName'
                )


            $DiskObject = [PSCustomObject]@{
                DeviceId          = $DeviceId
                FriendlyName      = $FriendlyName
                Manufacturer      = [string](
                    Get-PropertyValue `
                        -Object $Disk `
                        -Property 'Manufacturer'
                )
                Model             = [string](
                    Get-PropertyValue `
                        -Object $Disk `
                        -Property 'Model'
                )
                SerialNumber      = (
                    [string](
                        Get-PropertyValue `
                            -Object $Disk `
                            -Property 'SerialNumber'
                    )
                ).Trim()
                MediaType         = [string](
                    Get-PropertyValue `
                        -Object $Disk `
                        -Property 'MediaType'
                )
                BusType           = [string](
                    Get-PropertyValue `
                        -Object $Disk `
                        -Property 'BusType'
                )
                Usage             = [string](
                    Get-PropertyValue `
                        -Object $Disk `
                        -Property 'Usage'
                )
                CanPool           = Get-PropertyValue `
                    -Object $Disk `
                    -Property 'CanPool'
                HealthStatus      = [string](
                    Get-PropertyValue `
                        -Object $Disk `
                        -Property 'HealthStatus'
                )
                OperationalStatus = $OperationalStatus
                SizeGB            = if (
                    Get-PropertyValue `
                        -Object $Disk `
                        -Property 'Size'
                ) {
                    [math]::Round(
                        (
                            [double]$Disk.Size /
                            1GB
                        ),
                        2
                    )
                }
                else {
                    $null
                }
                PhysicalLocation  = [string](
                    Get-PropertyValue `
                        -Object $Disk `
                        -Property 'PhysicalLocation'
                )
                UniqueId          = [string](
                    Get-PropertyValue `
                        -Object $Disk `
                        -Property 'UniqueId'
                )
            }


            $script:PhysicalDisks.Add(
                $DiskObject
            )


            $DisplayName =
                if ($DeviceId) {
                    "Physical disk $DeviceId - $FriendlyName"
                }
                else {
                    "Physical disk - $FriendlyName"
                }


            switch ($DiskObject.HealthStatus) {

                'Healthy' {

                    Add-Check `
                        -Category 'Storage Health' `
                        -Name $DisplayName `
                        -Status 'PASS' `
                        -Value 'Healthy' `
                        -Details (
                            "$($DiskObject.MediaType); " +
                            "$($DiskObject.BusType); " +
                            "$($DiskObject.SizeGB) GB; " +
                            "$OperationalStatus"
                        )
                }

                'Warning' {

                    Add-Check `
                        -Category 'Storage Health' `
                        -Name $DisplayName `
                        -Status 'WARN' `
                        -Value 'Warning' `
                        -Details $OperationalStatus
                }

                'Unhealthy' {

                    Add-Check `
                        -Category 'Storage Health' `
                        -Name $DisplayName `
                        -Status 'FAIL' `
                        -Value 'Unhealthy' `
                        -Details $OperationalStatus
                }

                default {

                    Add-Check `
                        -Category 'Storage Health' `
                        -Name $DisplayName `
                        -Status 'INFO' `
                        -Value $(
                            if ($DiskObject.HealthStatus) {
                                $DiskObject.HealthStatus
                            }
                            else {
                                'Unknown'
                            }
                        ) `
                        -Details $OperationalStatus
                }
            }
        }
    }
    catch {

        Add-Check `
            -Category 'Storage Health' `
            -Name 'Physical disk inventory' `
            -Status 'UNKNOWN' `
            -Value 'Collection failed' `
            -Details $_.Exception.Message
    }
}


# ============================================================================
# STORAGE POOLS
# ============================================================================

if (Test-CommandExists 'Get-StoragePool') {

    try {

        $Pools =
            @(
                Get-StoragePool `
                    -ErrorAction Stop |
                Where-Object {
                    -not $_.IsPrimordial
                }
            )


        foreach ($Pool in $Pools) {

            $OperationalStatus =
                ConvertTo-JoinedString (
                    Get-PropertyValue `
                        -Object $Pool `
                        -Property 'OperationalStatus'
                )


            $PoolObject = [PSCustomObject]@{
                FriendlyName      = [string]$Pool.FriendlyName
                HealthStatus      = [string]$Pool.HealthStatus
                OperationalStatus = $OperationalStatus
                IsReadOnly        = Get-PropertyValue `
                    -Object $Pool `
                    -Property 'IsReadOnly'
                SizeGB            = if ($Pool.Size) {
                    [math]::Round(
                        ([double]$Pool.Size / 1GB),
                        2
                    )
                }
                else {
                    $null
                }
                AllocatedGB       = if (
                    $null -ne (
                        Get-PropertyValue `
                            -Object $Pool `
                            -Property 'AllocatedSize'
                    )
                ) {
                    [math]::Round(
                        (
                            [double]$Pool.AllocatedSize /
                            1GB
                        ),
                        2
                    )
                }
                else {
                    $null
                }
            }


            $script:StoragePools.Add(
                $PoolObject
            )


            switch ($PoolObject.HealthStatus) {

                'Healthy' {

                    Add-Check `
                        -Category 'Storage Topology' `
                        -Name (
                            "Storage pool: " +
                            $PoolObject.FriendlyName
                        ) `
                        -Status 'PASS' `
                        -Value 'Healthy' `
                        -Details (
                            "$($PoolObject.SizeGB) GB; " +
                            "$OperationalStatus"
                        )
                }

                'Warning' {

                    Add-Check `
                        -Category 'Storage Topology' `
                        -Name (
                            "Storage pool: " +
                            $PoolObject.FriendlyName
                        ) `
                        -Status 'WARN' `
                        -Value 'Warning' `
                        -Details $OperationalStatus
                }

                'Unhealthy' {

                    Add-Check `
                        -Category 'Storage Topology' `
                        -Name (
                            "Storage pool: " +
                            $PoolObject.FriendlyName
                        ) `
                        -Status 'FAIL' `
                        -Value 'Unhealthy' `
                        -Details $OperationalStatus
                }

                default {

                    Add-Check `
                        -Category 'Storage Topology' `
                        -Name (
                            "Storage pool: " +
                            $PoolObject.FriendlyName
                        ) `
                        -Status 'INFO' `
                        -Value $PoolObject.HealthStatus `
                        -Details $OperationalStatus
                }
            }
        }
    }
    catch {

        Add-Check `
            -Category 'Storage Topology' `
            -Name 'Storage pool inventory' `
            -Status 'UNKNOWN' `
            -Value 'Collection failed' `
            -Details $_.Exception.Message
    }
}


# ============================================================================
# STORAGE SPACES / VIRTUAL DISKS
# ============================================================================

if (Test-CommandExists 'Get-VirtualDisk') {

    try {

        $RawVirtualDisks =
            @(
                Get-VirtualDisk `
                    -ErrorAction Stop
            )


        foreach ($VirtualDisk in $RawVirtualDisks) {

            $BackingDisks = @()

            if (
                Test-CommandExists 'Get-PhysicalDisk'
            ) {

                try {

                    $BackingDisks =
                        @(
                            Get-PhysicalDisk `
                                -VirtualDisk $VirtualDisk `
                                -ErrorAction Stop
                        )
                }
                catch {}
            }


            $BackingDiskNames =
                @(
                    $BackingDisks |
                    ForEach-Object {

                        $Id =
                            [string](
                                Get-PropertyValue `
                                    -Object $_ `
                                    -Property 'DeviceId'
                            )

                        $Name =
                            [string](
                                Get-PropertyValue `
                                    -Object $_ `
                                    -Property 'FriendlyName'
                            )

                        if ($Id) {
                            "#$Id $Name"
                        }
                        else {
                            $Name
                        }
                    }
                )


            $LogicalDiskNumbers = @()
            $MountedVolumes = @()


            if (Test-CommandExists 'Get-Disk') {

                try {

                    $LogicalDisks =
                        @(
                            Get-Disk `
                                -VirtualDisk $VirtualDisk `
                                -ErrorAction Stop
                        )


                    $LogicalDiskNumbers =
                        @(
                            $LogicalDisks |
                            ForEach-Object {
                                $_.Number
                            }
                        )


                    foreach ($LogicalDisk in $LogicalDisks) {

                        if (
                            Test-CommandExists 'Get-Partition'
                        ) {

                            try {

                                $Partitions =
                                    @(
                                        Get-Partition `
                                            -DiskNumber $LogicalDisk.Number `
                                            -ErrorAction Stop
                                    )


                                foreach ($Partition in $Partitions) {

                                    if ($Partition.DriveLetter) {

                                        $MountedVolumes +=
                                            "$($Partition.DriveLetter):"
                                    }
                                }
                            }
                            catch {}
                        }
                    }
                }
                catch {}
            }


            $OperationalStatus =
                ConvertTo-JoinedString (
                    Get-PropertyValue `
                        -Object $VirtualDisk `
                        -Property 'OperationalStatus'
                )


            $Resiliency =
                [string](
                    Get-PropertyValue `
                        -Object $VirtualDisk `
                        -Property 'ResiliencySettingName'
                )


            $VirtualDiskObject = [PSCustomObject]@{
                FriendlyName           = [string]$VirtualDisk.FriendlyName
                HealthStatus           = [string]$VirtualDisk.HealthStatus
                OperationalStatus      = $OperationalStatus
                Resiliency             = $Resiliency
                ProvisioningType       = [string](
                    Get-PropertyValue `
                        -Object $VirtualDisk `
                        -Property 'ProvisioningType'
                )
                NumberOfDataCopies     = Get-PropertyValue `
                    -Object $VirtualDisk `
                    -Property 'NumberOfDataCopies'
                PhysicalDiskRedundancy = Get-PropertyValue `
                    -Object $VirtualDisk `
                    -Property 'PhysicalDiskRedundancy'
                SizeGB                 = if ($VirtualDisk.Size) {
                    [math]::Round(
                        (
                            [double]$VirtualDisk.Size /
                            1GB
                        ),
                        2
                    )
                }
                else {
                    $null
                }
                FootprintOnPoolGB      = if (
                    $null -ne (
                        Get-PropertyValue `
                            -Object $VirtualDisk `
                            -Property 'FootprintOnPool'
                    )
                ) {
                    [math]::Round(
                        (
                            [double]$VirtualDisk.FootprintOnPool /
                            1GB
                        ),
                        2
                    )
                }
                else {
                    $null
                }
                LogicalDiskNumbers     = (
                    $LogicalDiskNumbers -join ', '
                )
                MountedVolumes         = (
                    $MountedVolumes -join ', '
                )
                BackingPhysicalDisks   = (
                    $BackingDiskNames -join ', '
                )
            }


            $script:VirtualDisks.Add(
                $VirtualDiskObject
            )


            $TopologyDetails = @()

            if ($Resiliency) {
                $TopologyDetails +=
                    "Layout=$Resiliency"
            }

            if ($BackingDiskNames.Count -gt 0) {
                $TopologyDetails +=
                    (
                        "Physical disks=" +
                        ($BackingDiskNames -join ', ')
                    )
            }

            if ($MountedVolumes.Count -gt 0) {
                $TopologyDetails +=
                    (
                        "Mounted as=" +
                        ($MountedVolumes -join ', ')
                    )
            }

            if (
                $null -ne
                $VirtualDiskObject.PhysicalDiskRedundancy
            ) {

                $TopologyDetails +=
                    (
                        "Physical disk redundancy=" +
                        $VirtualDiskObject.PhysicalDiskRedundancy
                    )
            }


            switch (
                $VirtualDiskObject.HealthStatus
            ) {

                'Healthy' {

                    Add-Check `
                        -Category 'Storage Topology' `
                        -Name (
                            "Virtual disk: " +
                            $VirtualDiskObject.FriendlyName
                        ) `
                        -Status 'PASS' `
                        -Value 'Healthy' `
                        -Details (
                            $TopologyDetails -join '; '
                        )
                }

                'Warning' {

                    Add-Check `
                        -Category 'Storage Topology' `
                        -Name (
                            "Virtual disk: " +
                            $VirtualDiskObject.FriendlyName
                        ) `
                        -Status 'WARN' `
                        -Value 'Warning' `
                        -Details (
                            (
                                $TopologyDetails +
                                "State=$OperationalStatus"
                            ) -join '; '
                        )
                }

                'Unhealthy' {

                    Add-Check `
                        -Category 'Storage Topology' `
                        -Name (
                            "Virtual disk: " +
                            $VirtualDiskObject.FriendlyName
                        ) `
                        -Status 'FAIL' `
                        -Value 'Unhealthy' `
                        -Details (
                            (
                                $TopologyDetails +
                                "State=$OperationalStatus"
                            ) -join '; '
                        )
                }

                default {

                    Add-Check `
                        -Category 'Storage Topology' `
                        -Name (
                            "Virtual disk: " +
                            $VirtualDiskObject.FriendlyName
                        ) `
                        -Status 'INFO' `
                        -Value $(
                            if (
                                $VirtualDiskObject.HealthStatus
                            ) {
                                $VirtualDiskObject.HealthStatus
                            }
                            else {
                                'Unknown'
                            }
                        ) `
                        -Details (
                            $TopologyDetails -join '; '
                        )
                }
            }


            #
            # Layout is INFORMATIONAL.
            #
            # Simple / zero redundancy is not classified as a
            # security failure. It is a storage-resilience choice.
            #

            if ($Resiliency) {

                $LayoutDetail =
                    switch ($Resiliency) {

                        'Simple' {
                            (
                                'No storage redundancy. ' +
                                'This can be intentional for ' +
                                'JBOD/striped/capacity-oriented storage.'
                            )
                        }

                        'Mirror' {
                            'Mirrored Storage Spaces layout.'
                        }

                        'Parity' {
                            'Parity Storage Spaces layout.'
                        }

                        default {
                            "Storage layout: $Resiliency"
                        }
                    }


                Add-Check `
                    -Category 'Storage Topology' `
                    -Name (
                        "Layout: " +
                        $VirtualDiskObject.FriendlyName
                    ) `
                    -Status 'INFO' `
                    -Value $Resiliency `
                    -Details $LayoutDetail
            }
        }
    }
    catch {

        Add-Check `
            -Category 'Storage Topology' `
            -Name 'Virtual disk inventory' `
            -Status 'UNKNOWN' `
            -Value 'Collection failed' `
            -Details $_.Exception.Message
    }
}


# ============================================================================
# BITLOCKER
#
# IMPORTANT:
#
# Do NOT enumerate physical disks or Win32_LogicalDisk and then ask
# BitLocker about every result.
#
# Ask BitLocker which volumes BitLocker knows how to protect.
# ============================================================================

$RawBitLockerVolumes = @()
$BitLockerBulkQuerySucceeded = $false


if (Test-CommandExists 'Get-BitLockerVolume') {

    try {

        $RawBitLockerVolumes =
            @(
                Get-BitLockerVolume `
                    -ErrorAction Stop
            )

        $BitLockerBulkQuerySucceeded = $true
    }
    catch {

        Add-Check `
            -Category 'Encryption' `
            -Name 'BitLocker bulk enumeration' `
            -Status 'WARN' `
            -Value 'Bulk query failed; using mounted-volume fallback' `
            -Details $_.Exception.Message
    }


    #
    # Fallback:
    #
    # Only query real mounted, visible, fixed volumes.
    #
    # This deliberately does NOT query physical disk identities.
    #

    if (-not $BitLockerBulkQuerySucceeded) {

        foreach (
            $Volume in @(
                $script:Volumes |
                Where-Object {
                    $_.MountPoint -and
                    $_.DriveType -eq 'Fixed' -and
                    -not $_.IsHidden
                }
            )
        ) {

            try {

                $Result =
                    Get-BitLockerVolume `
                        -MountPoint $Volume.MountPoint `
                        -ErrorAction Stop

                if ($Result) {
                    $RawBitLockerVolumes += $Result
                }
            }
            catch {

                # Name it as a real volume control so an unreadable volume is
                # scored as a blind spot rather than silently ignored.
                $FailRole =
                    if (
                        $Volume.MountPoint.TrimEnd('\') -ieq
                        ([string]$env:SystemDrive).TrimEnd('\')
                    ) { 'OS volume' }
                    else { 'Data volume' }

                Add-Check `
                    -Category 'Encryption' `
                    -Name (
                        $FailRole + ' ' +
                        $Volume.MountPoint
                    ) `
                    -Status 'UNKNOWN' `
                    -Value 'BitLocker query failed' `
                    -Details (
                        "$($_.Exception.Message) " +
                        "Volume=$($Volume.FileSystem); " +
                        "DiskNumber=$($Volume.DiskNumber)"
                    )
            }
        }
    }


    $SeenBitLockerMountPoints = @{}


    foreach ($BL in $RawBitLockerVolumes) {

        $RawMountPoint =
            [string](
                Get-PropertyValue `
                    -Object $BL `
                    -Property 'MountPoint'
            )


        $MountPoint =
            if ($RawMountPoint) {
                $RawMountPoint.TrimEnd('\')
            }
            else {
                ''
            }


        if ($MountPoint) {
            $SeenBitLockerMountPoints[
                $MountPoint.ToUpperInvariant()
            ] = $true
        }


        $MatchingVolume =
            if ($MountPoint) {
                @(
                    $script:Volumes |
                    Where-Object {
                        $_.MountPoint -ieq $MountPoint
                    }
                ) |
                Select-Object -First 1
            }
            else {
                $null
            }


        $IsHidden =
            if ($MatchingVolume) {
                [bool]$MatchingVolume.IsHidden
            }
            else {
                $false
            }


        $IsVisibleFixed =
            if ($MatchingVolume) {
                (
                    $MatchingVolume.DriveType -eq 'Fixed' -and
                    -not $MatchingVolume.IsHidden
                )
            }
            else {
                $false
            }


        $VolumeStatus =
            [string](
                Get-PropertyValue `
                    -Object $BL `
                    -Property 'VolumeStatus'
            )


        $ProtectionStatus =
            [string](
                Get-PropertyValue `
                    -Object $BL `
                    -Property 'ProtectionStatus'
            )


        $EncryptionMethod =
            [string](
                Get-PropertyValue `
                    -Object $BL `
                    -Property 'EncryptionMethod'
            )


        $LockStatus =
            [string](
                Get-PropertyValue `
                    -Object $BL `
                    -Property 'LockStatus'
            )


        $EncryptionPercentage =
            Get-PropertyValue `
                -Object $BL `
                -Property 'EncryptionPercentage'


        if ($null -eq $EncryptionPercentage) {
            $EncryptionPercentage = 0
        }


        $EncryptionPercentage =
            [int][math]::Round(
                [double]$EncryptionPercentage
            )


        $KeyProtectors =
            @(
                Get-PropertyValue `
                    -Object $BL `
                    -Property 'KeyProtector' |
                ForEach-Object {

                    [string](
                        Get-PropertyValue `
                            -Object $_ `
                            -Property 'KeyProtectorType'
                    )
                } |
                Where-Object {
                    $_
                }
            )


        $KeyProtectorString =
            if ($KeyProtectors.Count -gt 0) {
                $KeyProtectors -join ', '
            }
            else {
                'None'
            }


        $RecoveryProtectorPresent =
            (
                $KeyProtectors -contains
                'RecoveryPassword'
            )


        $VolumeType =
            [string](
                Get-PropertyValue `
                    -Object $BL `
                    -Property 'VolumeType'
            )


        # Never trust VolumeType alone. If the provider returns it blank or
        # unexpected, an unencrypted OS drive would be mis-scored as a mere
        # data drive and dodge the critical cap. Pin it to the real system
        # drive as well.
        $IsOSVolume =
            (
                $VolumeType -eq 'OperatingSystem' -or
                (
                    $MountPoint -and
                    $MountPoint.TrimEnd('\') -ieq ([string]$env:SystemDrive).TrimEnd('\')
                )
            )


        $FullyEncrypted =
            (
                $VolumeStatus -eq 'FullyEncrypted' -or
                $EncryptionPercentage -eq 100
            )


        $ProtectionOn =
            (
                $ProtectionStatus -eq 'On' -or
                $ProtectionStatus -eq '1'
            )


        if (
            $FullyEncrypted -and
            $ProtectionOn
        ) {

            $BLStatus = 'PASS'
            $BLDetails =
                'Fully encrypted and BitLocker protection is active.'
        }
        elseif (
            $FullyEncrypted -and
            -not $ProtectionOn
        ) {

            $BLStatus = 'FAIL'
            $BLDetails =
                (
                    'Volume is encrypted, but BitLocker ' +
                    'protection is suspended/off.'
                )
        }
        elseif (
            $VolumeStatus -match
            'EncryptionInProgress|EncryptionPaused'
        ) {

            $BLStatus = 'WARN'
            $BLDetails =
                'Encryption is not complete.'
        }
        elseif (
            $IsOSVolume
        ) {

            $BLStatus = 'FAIL'
            $BLDetails =
                'Operating-system volume is not encrypted.'
        }
        elseif ($IsHidden) {

            $BLStatus = 'INFO'
            $BLDetails =
                (
                    'Hidden/system volume. Unencrypted state ' +
                    'is not treated as a user-data failure.'
                )
        }
        elseif ($IsVisibleFixed) {

            # A mounted fixed data volume holding plaintext data is a real
            # exposure, not a nicety: it carries its own hard-fail cap.
            $BLStatus = 'FAIL'
            $BLDetails =
                'Mounted fixed data volume is NOT encrypted. Data at rest on this drive is readable by anyone who removes it.'
        }
        else {

            $BLStatus = 'INFO'
            $BLDetails =
                'BitLocker-capable volume.'
        }


        $DisplayMount =
            if ($MountPoint) {
                $MountPoint
            }
            else {
                '<no drive letter>'
            }


        # OS vs data label drives the weighted score (OS encryption is a
        # critical, hard-capped control; data volumes weigh less).
        $VolumeRole =
            if ($IsOSVolume) { 'OS volume' }
            else { 'Data volume' }


        Add-Check `
            -Category 'Encryption' `
            -Name "$VolumeRole $DisplayMount" `
            -Status $BLStatus `
            -Value (
                "$VolumeStatus; " +
                "Protection=$ProtectionStatus; " +
                "$EncryptionPercentage%; " +
                "$EncryptionMethod"
            ) `
            -Expected $(
                if (
                    $IsOSVolume
                ) {
                    'Fully encrypted; protection On'
                }
                else {
                    'Encrypted if sensitive data is stored here'
                }
            ) `
            -Details $BLDetails


        # --- encryption strength + key-protector quality (encrypted volumes) ---

        $IsEncryptedVol =
            (
                $FullyEncrypted -or
                ($EncryptionPercentage -gt 0) -or
                ($VolumeStatus -match 'Encrypt')
            ) -and
            $EncryptionMethod -and
            $EncryptionMethod -notmatch 'None'


        if ($IsEncryptedVol) {

            $EncPretty =
                switch -Regex ($EncryptionMethod) {
                    'XtsAes256' { 'XTS-AES-256'; break }
                    'XtsAes128' { 'XTS-AES-128'; break }
                    'Aes256'    { 'AES-CBC-256'; break }
                    'Aes128'    { 'AES-CBC-128'; break }
                    default     { $EncryptionMethod }
                }

            $EncStatus =
                switch -Regex ($EncryptionMethod) {
                    'XtsAes256'        { 'PASS'; break }
                    'XtsAes128|Aes256' { 'WARN'; break }
                    'Aes128'           { 'WARN'; break }
                    default            { 'INFO' }
                }

            Add-Check `
                -Category 'Encryption' `
                -Name "Encryption strength $DisplayMount" `
                -Status $EncStatus `
                -Value $EncPretty `
                -Expected 'XTS-AES-256' `
                -Details 'XTS-AES-256 is recommended for OS and fixed drives; AES-CBC and 128-bit are weaker/legacy.'


            $HasTpmProt = @($KeyProtectors | Where-Object { $_ -match 'Tpm' }).Count -gt 0
            $HasPinProt = @($KeyProtectors | Where-Object { $_ -match 'Pin' }).Count -gt 0
            $HasSecret  = @($KeyProtectors | Where-Object { $_ -match 'Password|ExternalKey|StartupKey' }).Count -gt 0

            if ($KeyProtectors.Count -eq 0) {
                $KPStatus = 'FAIL'
                $KPValue  = 'None'
                $KPDetails = 'Encrypted but no key protectors - the volume may auto-unlock with no authentication.'
            }
            elseif ($HasTpmProt -and $HasPinProt) {
                $KPStatus = 'PASS'
                $KPValue  = 'TPM + PIN'
                $KPDetails = 'Pre-boot authentication with TPM anti-hammering - strongest common protector.'
            }
            elseif ($HasTpmProt) {
                $KPStatus = 'WARN'
                $KPValue  = 'TPM only'
                $KPDetails = 'Deters casual theft, but no pre-boot secret - weaker to DMA/evil-maid attacks. Add a PIN.'
            }
            elseif ($HasPinProt -or $HasSecret) {
                $KPStatus = 'WARN'
                $KPValue  = 'Password / USB only (no TPM)'
                $KPDetails = 'No TPM binding - vulnerable to offline brute force and lacks measured-boot protection.'
            }
            else {
                $KPStatus = 'INFO'
                $KPValue  = $KeyProtectorString
                $KPDetails = 'Key protectors present.'
            }

            if (-not $RecoveryProtectorPresent -and $KPStatus -ne 'FAIL') {
                $KPDetails = $KPDetails + ' No recovery password present - risk of permanent lockout.'
            }

            Add-Check `
                -Category 'Encryption' `
                -Name "Key protector $DisplayMount" `
                -Status $KPStatus `
                -Value $KPValue `
                -Expected 'TPM + PIN' `
                -Details $KPDetails
        }


        $BitLockerObject = [PSCustomObject]@{
            MountPoint               = $MountPoint
            VolumeType               = $VolumeType
            CapacityGB               = [math]::Round(
                [double](
                    Get-PropertyValue `
                        -Object $BL `
                        -Property 'CapacityGB' `
                        -Default 0
                ),
                2
            )
            VolumeStatus             = $VolumeStatus
            ProtectionStatus         = $ProtectionStatus
            LockStatus               = $LockStatus
            EncryptionPercentage     = $EncryptionPercentage
            EncryptionMethod         = $EncryptionMethod
            KeyProtectors            = $KeyProtectorString
            RecoveryProtectorPresent = $RecoveryProtectorPresent
            AutoUnlockEnabled        = Get-PropertyValue `
                -Object $BL `
                -Property 'AutoUnlockEnabled'
            MetadataVersion          = Get-PropertyValue `
                -Object $BL `
                -Property 'MetadataVersion'
            IsHidden                 = $IsHidden
        }


        $script:BitLockerVolumes.Add(
            $BitLockerObject
        )
    }


    #
    # Sanity check:
    #
    # Any visible fixed mounted volume which BitLocker failed to
    # enumerate gets ONE UNKNOWN.
    #
    # It does not create UNKNOWNs for underlying physical disks.
    #

    foreach (
        $Volume in @(
            $script:Volumes |
            Where-Object {
                $_.MountPoint -and
                $_.DriveType -eq 'Fixed' -and
                -not $_.IsHidden
            }
        )
    ) {

        $Key =
            $Volume.MountPoint.ToUpperInvariant()


        if (
            -not $SeenBitLockerMountPoints.ContainsKey(
                $Key
            )
        ) {

            $AlreadyReported =
                @(
                    $script:Checks |
                    Where-Object {
                        $_.Category -eq 'Encryption' -and
                        $_.Check -match (
                            '(^|\s)' +
                            [regex]::Escape([string]$Volume.MountPoint) +
                            '$'
                        )
                    }
                ).Count -gt 0


            if (-not $AlreadyReported) {

                # A mounted fixed volume the BitLocker provider never returned
                # is an encryption BLIND SPOT, not a non-event. It is named as
                # a real volume control so it is scored, and it runs the same
                # detection ladder before giving up.
                $MissRole =
                    if (
                        $Volume.MountPoint.TrimEnd('\') -ieq
                        ([string]$env:SystemDrive).TrimEnd('\')
                    ) { 'OS volume' }
                    else { 'Data volume' }

                $MissInfo =
                    Get-EncryptableVolumeInfo `
                        -DriveLetter $Volume.MountPoint

                if ($MissInfo) {

                    $MI = @($MissInfo)[0]

                    if ($MI.ConversionText -eq 'FullyEncrypted' -and $MI.ProtectionText -eq 'On') {
                        $MissStatus = 'PASS'
                        $MissDetails = 'Encrypted and protected via the Windows volume-encryption provider.'
                    }
                    elseif ($MI.ConversionText -eq 'FullyEncrypted') {
                        $MissStatus = 'FAIL'
                        $MissDetails = 'Encrypted but protection is off, so the key is released without authentication.'
                    }
                    elseif ($MI.ConversionText -match 'InProgress|Paused') {
                        $MissStatus = 'WARN'
                        $MissDetails = 'Encryption is not complete.'
                    }
                    else {
                        $MissStatus = 'FAIL'
                        $MissDetails = 'Volume is NOT encrypted.'
                    }

                    Add-Check `
                        -Category 'Encryption' `
                        -Name "$MissRole $($Volume.MountPoint)" `
                        -Status $MissStatus `
                        -Value "$($MI.ConversionText); Protection=$($MI.ProtectionText); $($MI.EncryptionMethod)" `
                        -Expected 'Fully encrypted; protection On' `
                        -Details $MissDetails
                }
                else {

                    Add-Check `
                        -Category 'Encryption' `
                        -Name "$MissRole $($Volume.MountPoint)" `
                        -Status 'UNKNOWN' `
                        -Value 'Not returned by any encryption provider' `
                        -Expected 'Fully encrypted; protection On' `
                        -Details (
                            "FileSystem=$($Volume.FileSystem); " +
                            "DiskNumber=$($Volume.DiskNumber). " +
                            'Typical of a spanned/striped dynamic volume or an ' +
                            'unusual pooled layout. BitLocker CANNOT encrypt ' +
                            'dynamic volumes, so unless a third-party product ' +
                            'covers it this data is almost certainly stored in ' +
                            'the clear. Verify manually.'
                        )
                }
            }
        }
    }
}
else {

    Add-Check `
        -Category 'Encryption' `
        -Name 'BitLocker provider' `
        -Status 'INFO' `
        -Value 'Get-BitLockerVolume is unavailable' `
        -Details (
            'Normal on Windows Home. Encryption is resolved below via the ' +
            'Device Encryption WMI provider and third-party FDE detection.'
        )
}


# ============================================================================
# ENCRYPTION FALLBACK LADDER
#
# Guarantees the OS-drive encryption control is always ATTEMPTED, on every
# edition. Runs only when the BitLocker path above produced no usable
# OS-volume verdict (Windows Home, missing cmdlets, failed enumeration).
# ============================================================================

$OSDrive = [string]$env:SystemDrive
if (-not $OSDrive) { $OSDrive = 'C:' }

$IsPortable = Test-IsPortableChassis

if ($null -ne $IsPortable) {

    Add-Check `
        -Category 'System' `
        -Name 'Chassis' `
        -Status 'INFO' `
        -Value $(
            if ($IsPortable) { 'Portable (laptop/tablet)' } else { 'Desktop / fixed' }
        )
}


$OSEncryptionAssessed =
    @(
        $script:Checks |
        Where-Object {
            $_.Category -eq 'Encryption' -and
            $_.Check -match '^OS volume' -and
            $_.Status -in @('PASS', 'WARN', 'FAIL', 'UNKNOWN')
        }
    ).Count -gt 0


if (-not $OSEncryptionAssessed) {

    $PortableNote =
        if ($IsPortable) {
            ' This is a portable device - unencrypted storage is exposed the moment it is lost or stolen.'
        }
        else { '' }

    $Fallback = Get-EncryptableVolumeInfo -DriveLetter $OSDrive

    if ($Fallback) {

        $FB = @($Fallback)[0]

        if ($FB.ConversionText -eq 'FullyEncrypted' -and $FB.ProtectionText -eq 'On') {
            $FBStatus = 'PASS'
            $FBDetails = 'Encrypted and protected via the Windows volume-encryption provider (BitLocker / Device Encryption).'
        }
        elseif ($FB.ConversionText -eq 'FullyEncrypted') {
            $FBStatus = 'FAIL'
            $FBDetails = 'Volume is encrypted but protection is suspended/off, so the key is released without authentication.' + $PortableNote
        }
        elseif ($FB.ConversionText -match 'InProgress|Paused') {
            $FBStatus = 'WARN'
            $FBDetails = 'Encryption is not complete.'
        }
        else {
            $FBStatus = 'FAIL'
            $FBDetails = 'Operating-system volume is NOT encrypted.' + $PortableNote
        }

        Add-Check `
            -Category 'Encryption' `
            -Name "OS volume $OSDrive" `
            -Status $FBStatus `
            -Value "$($FB.ConversionText); Protection=$($FB.ProtectionText); $($FB.EncryptionMethod)" `
            -Expected 'Fully encrypted; protection On' `
            -Details $FBDetails
    }
    else {

        $ThirdParty = @(Get-ThirdPartyEncryptionProducts)

        if ($ThirdParty.Count -gt 0) {

            Add-Check `
                -Category 'Encryption' `
                -Name "OS volume $OSDrive" `
                -Status 'UNKNOWN' `
                -Value 'Third-party encryption product detected' `
                -Expected 'Fully encrypted; protection On' `
                -Details (
                    'Detected: ' + ($ThirdParty -join ', ') +
                    '. Sentinel cannot read the state of third-party full-disk ' +
                    'encryption - verify manually that this volume is actually ' +
                    'encrypted and protected.' + $PortableNote
                )
        }
        else {

            Add-Check `
                -Category 'Encryption' `
                -Name "OS volume $OSDrive" `
                -Status 'UNKNOWN' `
                -Value 'Could not be determined' `
                -Expected 'Fully encrypted; protection On' `
                -Details (
                    'No encryption provider could be queried (the Windows ' +
                    'volume-encryption WMI class was inaccessible and no ' +
                    'third-party product was found). Re-run as Administrator. ' +
                    'Treat this drive as UNENCRYPTED until proven otherwise.' +
                    $PortableNote
                )
        }
    }
}


# ============================================================================
# VIRTUALIZATION BASED SECURITY / DEVICE GUARD
# ============================================================================

try {

    $DeviceGuard =
        Get-CimInstance `
            -Namespace 'root\Microsoft\Windows\DeviceGuard' `
            -ClassName Win32_DeviceGuard `
            -ErrorAction Stop


    $ConfiguredServices =
        @(
            $DeviceGuard.SecurityServicesConfigured |
            ForEach-Object {
                [int]$_
            }
        )


    $RunningServices =
        @(
            $DeviceGuard.SecurityServicesRunning |
            ForEach-Object {
                [int]$_
            }
        )


    switch (
        [int]$DeviceGuard.VirtualizationBasedSecurityStatus
    ) {

        2 {

            Add-Check `
                -Category 'Virtualisation Security' `
                -Name 'Virtualization Based Security' `
                -Status 'PASS' `
                -Value 'Enabled and running'
        }

        1 {

            Add-Check `
                -Category 'Virtualisation Security' `
                -Name 'Virtualization Based Security' `
                -Status 'WARN' `
                -Value 'Enabled but not running'
        }

        0 {

            Add-Check `
                -Category 'Virtualisation Security' `
                -Name 'Virtualization Based Security' `
                -Status 'WARN' `
                -Value 'Not enabled'
        }

        default {

            Add-Check `
                -Category 'Virtualisation Security' `
                -Name 'Virtualization Based Security' `
                -Status 'UNKNOWN' `
                -Value (
                    $DeviceGuard.VirtualizationBasedSecurityStatus
                )
        }
    }


    Add-DeviceGuardServiceCheck `
        -ServiceId 2 `
        -Name 'Memory Integrity / HVCI' `
        -Configured $ConfiguredServices `
        -Running $RunningServices `
        -NotConfiguredStatus 'WARN'


    Add-DeviceGuardServiceCheck `
        -ServiceId 1 `
        -Name 'Credential Guard' `
        -Configured $ConfiguredServices `
        -Running $RunningServices `
        -NotConfiguredStatus 'WARN'


    Add-DeviceGuardServiceCheck `
        -ServiceId 3 `
        -Name 'System Guard Secure Launch' `
        -Configured $ConfiguredServices `
        -Running $RunningServices `
        -NotConfiguredStatus 'INFO'


    Add-DeviceGuardServiceCheck `
        -ServiceId 5 `
        -Name 'Kernel hardware-enforced stack protection' `
        -Configured $ConfiguredServices `
        -Running $RunningServices `
        -NotConfiguredStatus 'INFO'


    Add-Check `
        -Category 'Virtualisation Security' `
        -Name 'Device Guard services running' `
        -Status 'INFO' `
        -Value (
            Get-DeviceGuardServiceNames `
                -Values $RunningServices
        )


    Add-Check `
        -Category 'Virtualisation Security' `
        -Name 'Device Guard services configured' `
        -Status 'INFO' `
        -Value (
            Get-DeviceGuardServiceNames `
                -Values $ConfiguredServices
        )


    if (
        Test-ObjectProperty `
            -Object $DeviceGuard `
            -Property 'CodeIntegrityPolicyEnforcementStatus'
    ) {

        $CIStatus =
            switch (
                [int]$DeviceGuard.CodeIntegrityPolicyEnforcementStatus
            ) {

                0 {
                    'Off'
                }

                1 {
                    'Audit'
                }

                2 {
                    'Enforced'
                }

                default {
                    [string]$DeviceGuard.CodeIntegrityPolicyEnforcementStatus
                }
            }


        Add-Check `
            -Category 'Virtualisation Security' `
            -Name 'Code Integrity policy' `
            -Status 'INFO' `
            -Value $CIStatus
    }
}
catch {

    Add-Check `
        -Category 'Virtualisation Security' `
        -Name 'Device Guard / VBS provider' `
        -Status 'UNKNOWN' `
        -Value 'Unavailable' `
        -Details $_.Exception.Message
}


# ============================================================================
# LSA PROTECTION
# ============================================================================

$LSAPath =
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'


$RunAsPPL =
    Get-RegistryValue `
        -Path $LSAPath `
        -Name 'RunAsPPL'


# The registry only records configuration. Windows 11 22H2+ can enable LSA
# protection with no RunAsPPL value at all, so read the state LSASS is
# actually running with: its process protection level first, then the
# WinInit event 12 written when LSASS starts protected in this boot.
$LsaEffective = Get-LsaProtectionState


$LsaConfigStatus = 'UNKNOWN'
if ($null -eq $RunAsPPL) {
    $LsaConfig = 'No explicit registry configuration'
}
elseif ("$RunAsPPL" -eq '1') {
    $LsaConfig = 'Enabled with UEFI lock'; $LsaConfigStatus = 'PASS'
}
elseif ("$RunAsPPL" -eq '2') {
    $LsaConfig = 'Enabled without UEFI lock'; $LsaConfigStatus = 'PASS'
}
elseif ("$RunAsPPL" -eq '0') {
    $LsaConfig = 'Explicitly disabled'; $LsaConfigStatus = 'WARN'
}
else {
    $LsaConfig = "$RunAsPPL"
}


if ($null -ne $LsaEffective.Protected) {

    Add-Check `
        -Category 'Credential Protection' `
        -Name 'LSA protection (running state)' `
        -Status $(if ($LsaEffective.Protected) { 'PASS' } else { 'WARN' }) `
        -Value $(
            if ($LsaEffective.Protected) { 'LSASS running as a protected process' }
            else { 'LSASS not running as a protected process' }
        ) `
        -Expected 'LSASS running as a protected process (PPL)' `
        -Details ("Source: $($LsaEffective.Source). $($LsaEffective.Detail)")

    # Configuration is evidence only once the effective state is known.
    Add-Check `
        -Category 'Credential Protection' `
        -Name 'LSA protected process configuration' `
        -Status 'INFO' `
        -Value $LsaConfig
}
else {

    # Without the running state, fall back to configuration. An absent
    # value stays UNKNOWN: it neither proves nor disproves protection.
    Add-Check `
        -Category 'Credential Protection' `
        -Name 'LSA protected process configuration' `
        -Status $LsaConfigStatus `
        -Value $LsaConfig `
        -Details (
            'The running LSASS protection level could not be read ' +
            "($($LsaEffective.Detail)). " +
            'Modern Windows 11 may enable LSA protection ' +
            'without this registry value being explicitly present.'
        )
}


# ============================================================================
# WINDOWS SECURITY REGISTERED ANTIVIRUS PRODUCTS
# ============================================================================

try {

    $RegisteredAV =
        @(
            Get-CimInstance `
                -Namespace 'root\SecurityCenter2' `
                -ClassName AntiVirusProduct `
                -ErrorAction Stop
        )


    foreach ($AV in $RegisteredAV) {

        $State =
            Get-PropertyValue `
                -Object $AV `
                -Property 'productState'


        $StateHex =
            if ($null -ne $State) {
                '0x{0:X6}' -f [int]$State
            }
            else {
                ''
            }


        $AVObject = [PSCustomObject]@{
            DisplayName             = [string]$AV.displayName
            ProductState            = $State
            ProductStateHex         = $StateHex
            PathToSignedProductExe  = [string](
                Get-PropertyValue `
                    -Object $AV `
                    -Property 'pathToSignedProductExe'
            )
            PathToSignedReportingExe = [string](
                Get-PropertyValue `
                    -Object $AV `
                    -Property 'pathToSignedReportingExe'
            )
            InstanceGuid            = [string](
                Get-PropertyValue `
                    -Object $AV `
                    -Property 'instanceGuid'
            )
        }


        $script:AntivirusProducts.Add(
            $AVObject
        )
    }


    $AVNames =
        @(
            $script:AntivirusProducts |
            Select-Object `
                -ExpandProperty DisplayName `
                -Unique
        )


    if ($AVNames.Count -gt 0) {

        Add-Check `
            -Category 'Antivirus' `
            -Name 'Registered security products' `
            -Status 'INFO' `
            -Value ($AVNames -join ', ') `
            -Details (
                'Windows Security Center registrations. ' +
                'productState is exported as raw data rather than ' +
                'using undocumented bit-field assumptions.'
            )
    }
    else {

        Add-Check `
            -Category 'Antivirus' `
            -Name 'Registered security products' `
            -Status 'WARN' `
            -Value 'None reported'
    }
}
catch {

    Add-Check `
        -Category 'Antivirus' `
        -Name 'Registered security products' `
        -Status 'UNKNOWN' `
        -Value 'Unable to query Windows Security Center' `
        -Details $_.Exception.Message
}


# ============================================================================
# MICROSOFT DEFENDER
# ============================================================================

if (Test-CommandExists 'Get-MpComputerStatus') {

    try {

        $Defender =
            Get-MpComputerStatus `
                -ErrorAction Stop


        $DefenderMode =
            [string](
                Get-PropertyValue `
                    -Object $Defender `
                    -Property 'AMRunningMode'
            )


        switch ($DefenderMode) {

            'Normal' {

                Add-Check `
                    -Category 'Defender' `
                    -Name 'Defender running mode' `
                    -Status 'PASS' `
                    -Value 'Normal / Active'
            }

            'Passive' {

                Add-Check `
                    -Category 'Defender' `
                    -Name 'Defender running mode' `
                    -Status 'INFO' `
                    -Value 'Passive' `
                    -Details (
                        'This can be normal when another antivirus ' +
                        'product is the active provider.'
                    )
            }

            default {

                Add-Check `
                    -Category 'Defender' `
                    -Name 'Defender running mode' `
                    -Status 'INFO' `
                    -Value $(
                        if ($DefenderMode) {
                            $DefenderMode
                        }
                        else {
                            'Unknown'
                        }
                    )
            }
        }


        if ($DefenderMode -eq 'Normal') {

            $DefenderBooleanChecks = @(
                @{
                    Property = 'RealTimeProtectionEnabled'
                    Name = 'Real-time protection'
                    Failure = 'FAIL'
                },
                @{
                    Property = 'BehaviorMonitorEnabled'
                    Name = 'Behaviour monitoring'
                    Failure = 'WARN'
                },
                @{
                    Property = 'IoavProtectionEnabled'
                    Name = 'Downloaded file scanning'
                    Failure = 'WARN'
                },
                @{
                    Property = 'NISEnabled'
                    Name = 'Network Inspection System'
                    Failure = 'WARN'
                }
            )


            foreach ($CheckDefinition in $DefenderBooleanChecks) {

                if (
                    Test-ObjectProperty `
                        -Object $Defender `
                        -Property $CheckDefinition.Property
                ) {

                    $Enabled =
                        [bool](
                            Get-PropertyValue `
                                -Object $Defender `
                                -Property $CheckDefinition.Property
                        )


                    Add-Check `
                        -Category 'Defender' `
                        -Name $CheckDefinition.Name `
                        -Status $(
                            if ($Enabled) {
                                'PASS'
                            }
                            else {
                                $CheckDefinition.Failure
                            }
                        ) `
                        -Value $Enabled `
                        -Expected 'True'
                }
            }


            if (
                Test-ObjectProperty `
                    -Object $Defender `
                    -Property 'AntivirusSignatureAge'
            ) {

                $SignatureAge =
                    [int]$Defender.AntivirusSignatureAge


                $SignatureStatus =
                    if ($SignatureAge -le 2) {
                        'PASS'
                    }
                    elseif ($SignatureAge -le 7) {
                        'WARN'
                    }
                    else {
                        'FAIL'
                    }


                Add-Check `
                    -Category 'Defender' `
                    -Name 'Signature age' `
                    -Status $SignatureStatus `
                    -Value "$SignatureAge day(s)" `
                    -Expected '2 days or less'
            }
        }


        if (
            Test-ObjectProperty `
                -Object $Defender `
                -Property 'IsTamperProtected'
        ) {

            $TamperProtected =
                [bool]$Defender.IsTamperProtected


            Add-Check `
                -Category 'Defender' `
                -Name 'Tamper Protection' `
                -Status $(
                    if ($TamperProtected) {
                        'PASS'
                    }
                    else {
                        'WARN'
                    }
                ) `
                -Value $TamperProtected `
                -Expected 'True'
        }
    }
    catch {

        Add-Check `
            -Category 'Defender' `
            -Name 'Microsoft Defender status' `
            -Status 'UNKNOWN' `
            -Value 'Collection failed' `
            -Details $_.Exception.Message
    }
}
else {

    Add-Check `
        -Category 'Defender' `
        -Name 'Microsoft Defender status' `
        -Status 'INFO' `
        -Value 'Defender PowerShell provider unavailable'
}


# ============================================================================
# REAL-TIME ANTIVIRUS  (provider-agnostic)
#
# The Defender-specific checks above only fire when Defender is the ACTIVE
# provider. On a machine running third-party AV, Defender sits in Passive mode
# and every Defender check is skipped - which used to leave malware protection
# entirely unscored. This control asks the provider-neutral question instead:
# is *some* real-time antivirus active and up to date?
# ============================================================================

$SCProducts = $null

try {
    $SCProducts =
        @(
            Get-CimInstance `
                -Namespace 'root\SecurityCenter2' `
                -ClassName AntiVirusProduct `
                -ErrorAction Stop
        )
}
catch {
    $SCProducts = $null
}


# Defender's own verdict, taken from the checks already emitted above.
$DefenderRealTime =
    @(
        $script:Checks |
        Where-Object {
            $_.Category -eq 'Defender' -and
            $_.Check -eq 'Real-time protection' -and
            $_.Status -eq 'PASS'
        }
    ).Count -gt 0


$ActiveAV = @()
$StaleAV = @()
$InactiveAV = @()

if ($null -ne $SCProducts) {

    foreach ($P in $SCProducts) {

        $Name = [string](Get-PropertyValue -Object $P -Property 'displayName')
        $State = Get-PropertyValue -Object $P -Property 'productState'
        if (-not $Name -or $null -eq $State) { continue }

        # productState is a packed DWORD: the middle byte carries the
        # "real-time protection on" bit (0x10); the low byte is 0 when
        # signatures are current.
        $Hex = '{0:x6}' -f [int]$State
        $EnabledByte = [Convert]::ToInt32($Hex.Substring(2, 2), 16)
        $UpdatedByte = [Convert]::ToInt32($Hex.Substring(4, 2), 16)

        $Enabled = (($EnabledByte -band 0x10) -ne 0)
        $Current = ($UpdatedByte -eq 0)

        if ($Enabled -and $Current)     { $ActiveAV += $Name }
        elseif ($Enabled)               { $StaleAV += $Name }
        else                            { $InactiveAV += $Name }
    }
}


if ($ActiveAV.Count -gt 0 -or ($DefenderRealTime -and $StaleAV.Count -eq 0 -and $null -eq $SCProducts)) {

    $AVValue =
        if ($ActiveAV.Count -gt 0) { 'Active: ' + ($ActiveAV -join ', ') }
        else { 'Active: Microsoft Defender' }

    Add-Check `
        -Category 'Antivirus' `
        -Name 'Real-time antivirus protection' `
        -Status 'PASS' `
        -Value $AVValue `
        -Expected 'An active, up-to-date real-time antivirus'
}
elseif ($StaleAV.Count -gt 0) {

    Add-Check `
        -Category 'Antivirus' `
        -Name 'Real-time antivirus protection' `
        -Status 'WARN' `
        -Value ('Active but out of date: ' + ($StaleAV -join ', ')) `
        -Expected 'An active, up-to-date real-time antivirus' `
        -Details 'Real-time protection is on but the signatures are stale, so new threats will be missed.'
}
elseif ($DefenderRealTime) {

    Add-Check `
        -Category 'Antivirus' `
        -Name 'Real-time antivirus protection' `
        -Status 'PASS' `
        -Value 'Active: Microsoft Defender' `
        -Expected 'An active, up-to-date real-time antivirus'
}
elseif ($InactiveAV.Count -gt 0) {

    Add-Check `
        -Category 'Antivirus' `
        -Name 'Real-time antivirus protection' `
        -Status 'FAIL' `
        -Value ('Installed but NOT enabled: ' + ($InactiveAV -join ', ')) `
        -Expected 'An active, up-to-date real-time antivirus' `
        -Details 'An antivirus product is registered but its real-time protection is switched off or expired. This machine is effectively unprotected.'
}
elseif ($null -ne $SCProducts) {

    Add-Check `
        -Category 'Antivirus' `
        -Name 'Real-time antivirus protection' `
        -Status 'FAIL' `
        -Value 'No active antivirus found' `
        -Expected 'An active, up-to-date real-time antivirus' `
        -Details 'Windows Security Center reports no antivirus with real-time protection enabled.'
}
else {

    Add-Check `
        -Category 'Antivirus' `
        -Name 'Real-time antivirus protection' `
        -Status 'UNKNOWN' `
        -Value 'Could not be determined' `
        -Expected 'An active, up-to-date real-time antivirus' `
        -Details 'Windows Security Center was unavailable (normal on Server SKUs) and Defender state could not be read. Re-run as Administrator.'
}


# ============================================================================
# WINDOWS FIREWALL
# ============================================================================

if (Test-CommandExists 'Get-NetFirewallProfile') {

    try {

        $FirewallProfiles =
            @(
                Get-NetFirewallProfile `
                    -PolicyStore ActiveStore `
                    -ErrorAction Stop
            )


        foreach ($Profile in $FirewallProfiles) {

            $Enabled =
                [string]$Profile.Enabled


            $FirewallStatus =
                if ($Enabled -eq 'True') {
                    'PASS'
                }
                elseif ($Enabled -eq 'False') {
                    'FAIL'
                }
                else {
                    'UNKNOWN'
                }


            Add-Check `
                -Category 'Firewall' `
                -Name "$($Profile.Name) profile" `
                -Status $FirewallStatus `
                -Value "Enabled=$Enabled" `
                -Expected 'Enabled' `
                -Details (
                    "Inbound=$($Profile.DefaultInboundAction); " +
                    "Outbound=$($Profile.DefaultOutboundAction)"
                )
        }
    }
    catch {

        Add-Check `
            -Category 'Firewall' `
            -Name 'Windows Firewall' `
            -Status 'UNKNOWN' `
            -Value 'Collection failed' `
            -Details $_.Exception.Message
    }
}


# ============================================================================
# USER ACCOUNT CONTROL
# ============================================================================

$UACPath =
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'


$EnableLUA =
    Get-RegistryValue `
        -Path $UACPath `
        -Name 'EnableLUA'


if ($null -eq $EnableLUA) {

    Add-Check `
        -Category 'Privilege Protection' `
        -Name 'User Account Control' `
        -Status 'UNKNOWN' `
        -Value 'Unable to determine'
}
elseif ([int]$EnableLUA -eq 1) {

    Add-Check `
        -Category 'Privilege Protection' `
        -Name 'User Account Control' `
        -Status 'PASS' `
        -Value 'Enabled'
}
else {

    Add-Check `
        -Category 'Privilege Protection' `
        -Name 'User Account Control' `
        -Status 'FAIL' `
        -Value 'Disabled'
}


$ConsentBehavior =
    Get-RegistryValue `
        -Path $UACPath `
        -Name 'ConsentPromptBehaviorAdmin'


if ($null -ne $ConsentBehavior) {

    $ConsentDescription =
        switch ([int]$ConsentBehavior) {

            0 {
                'Elevate without prompting'
            }

            1 {
                'Prompt for credentials on secure desktop'
            }

            2 {
                'Prompt for consent on secure desktop'
            }

            3 {
                'Prompt for credentials'
            }

            4 {
                'Prompt for consent'
            }

            5 {
                'Prompt for consent for non-Windows binaries'
            }

            default {
                "Unknown policy value $ConsentBehavior"
            }
        }


    Add-Check `
        -Category 'Privilege Protection' `
        -Name 'Admin elevation prompts' `
        -Status $(
            if ([int]$ConsentBehavior -eq 0) {
                'WARN'
            }
            else {
                'PASS'
            }
        ) `
        -Value $ConsentDescription
}


$PromptOnSecureDesktop =
    Get-RegistryValue `
        -Path $UACPath `
        -Name 'PromptOnSecureDesktop'


if ($null -ne $PromptOnSecureDesktop) {

    Add-Check `
        -Category 'Privilege Protection' `
        -Name 'UAC Secure Desktop' `
        -Status $(
            if ([int]$PromptOnSecureDesktop -eq 1) {
                'PASS'
            }
            else {
                'WARN'
            }
        ) `
        -Value $(
            if ([int]$PromptOnSecureDesktop -eq 1) {
                'Enabled'
            }
            else {
                'Disabled'
            }
        ) `
        -Expected 'Enabled'
}


# ============================================================================
# SMB SERVER SECURITY
# ============================================================================

if (Test-CommandExists 'Get-SmbServerConfiguration') {

    try {

        $SMBServer =
            Get-SmbServerConfiguration `
                -ErrorAction Stop


        Add-Check `
            -Category 'SMB Security' `
            -Name 'SMBv1 server protocol' `
            -Status $(
                if ($SMBServer.EnableSMB1Protocol) {
                    'FAIL'
                }
                else {
                    'PASS'
                }
            ) `
            -Value $SMBServer.EnableSMB1Protocol `
            -Expected 'False'


        Add-Check `
            -Category 'SMB Security' `
            -Name 'SMBv2/v3 server protocol' `
            -Status $(
                if ($SMBServer.EnableSMB2Protocol) {
                    'PASS'
                }
                else {
                    'FAIL'
                }
            ) `
            -Value $SMBServer.EnableSMB2Protocol `
            -Expected 'True'


        if (
            Test-ObjectProperty `
                -Object $SMBServer `
                -Property 'RequireSecuritySignature'
        ) {

            Add-Check `
                -Category 'SMB Security' `
                -Name 'SMB server signing required' `
                -Status $(
                    if (
                        $SMBServer.RequireSecuritySignature
                    ) {
                        'PASS'
                    }
                    else {
                        'WARN'
                    }
                ) `
                -Value $SMBServer.RequireSecuritySignature `
                -Expected 'True on modern Windows'
        }
    }
    catch {

        Add-Check `
            -Category 'SMB Security' `
            -Name 'SMB server configuration' `
            -Status 'UNKNOWN' `
            -Value 'Collection failed' `
            -Details $_.Exception.Message
    }
}


# ============================================================================
# SMB CLIENT SECURITY
# ============================================================================

if (Test-CommandExists 'Get-SmbClientConfiguration') {

    try {

        $SMBClient =
            Get-SmbClientConfiguration `
                -ErrorAction Stop


        if (
            Test-ObjectProperty `
                -Object $SMBClient `
                -Property 'RequireSecuritySignature'
        ) {

            Add-Check `
                -Category 'SMB Security' `
                -Name 'SMB client signing required' `
                -Status $(
                    if (
                        $SMBClient.RequireSecuritySignature
                    ) {
                        'PASS'
                    }
                    else {
                        'WARN'
                    }
                ) `
                -Value $SMBClient.RequireSecuritySignature `
                -Expected 'True on modern Windows'
        }


        if (
            Test-ObjectProperty `
                -Object $SMBClient `
                -Property 'EnableInsecureGuestLogons'
        ) {

            $InsecureGuests =
                [bool]$SMBClient.EnableInsecureGuestLogons


            Add-Check `
                -Category 'SMB Security' `
                -Name 'Insecure SMB guest logons' `
                -Status $(
                    if ($InsecureGuests) {
                        'FAIL'
                    }
                    else {
                        'PASS'
                    }
                ) `
                -Value $(
                    if ($InsecureGuests) {
                        'Allowed'
                    }
                    else {
                        'Disabled'
                    }
                ) `
                -Expected 'Disabled'
        }
    }
    catch {

        Add-Check `
            -Category 'SMB Security' `
            -Name 'SMB client configuration' `
            -Status 'UNKNOWN' `
            -Value 'Collection failed' `
            -Details $_.Exception.Message
    }
}


# ============================================================================
# REMOTE DESKTOP
# ============================================================================

$TerminalServerPath =
    'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'


$RDPDeny =
    Get-RegistryValue `
        -Path $TerminalServerPath `
        -Name 'fDenyTSConnections'


if ($null -ne $RDPDeny) {

    if ([int]$RDPDeny -eq 1) {

        Add-Check `
            -Category 'Remote Access' `
            -Name 'Remote Desktop' `
            -Status 'INFO' `
            -Value 'Disabled'
    }
    else {

        Add-Check `
            -Category 'Remote Access' `
            -Name 'Remote Desktop' `
            -Status 'INFO' `
            -Value 'Enabled'


        $NLA =
            Get-RegistryValue `
                -Path (
                    'HKLM:\SYSTEM\CurrentControlSet\Control\' +
                    'Terminal Server\WinStations\RDP-Tcp'
                ) `
                -Name 'UserAuthentication'


        if ($null -eq $NLA) {

            Add-Check `
                -Category 'Remote Access' `
                -Name 'RDP Network Level Authentication' `
                -Status 'UNKNOWN' `
                -Value 'Unable to determine'
        }
        elseif ([int]$NLA -eq 1) {

            Add-Check `
                -Category 'Remote Access' `
                -Name 'RDP Network Level Authentication' `
                -Status 'PASS' `
                -Value 'Required'
        }
        else {

            Add-Check `
                -Category 'Remote Access' `
                -Name 'RDP Network Level Authentication' `
                -Status 'FAIL' `
                -Value 'Not required' `
                -Expected 'Required'
        }
    }
}


# ============================================================================
# SUMMARY
# ============================================================================

$Summary = [ordered]@{
    Pass =
        @(
            $script:Checks |
            Where-Object Status -eq 'PASS'
        ).Count

    Warn =
        @(
            $script:Checks |
            Where-Object Status -eq 'WARN'
        ).Count

    Fail =
        @(
            $script:Checks |
            Where-Object Status -eq 'FAIL'
        ).Count

    Unknown =
        @(
            $script:Checks |
            Where-Object Status -eq 'UNKNOWN'
        ).Count

    Info =
        @(
            $script:Checks |
            Where-Object Status -eq 'INFO'
        ).Count
}


$Assessment   = Get-PostureAssessment -Checks $script:Checks -IsAdmin $IsAdmin
$Score        = $Assessment.Score
$ScoreBand    = $Assessment.Band
$ScoreColour  = $Assessment.Colour
$ScoreVerdict = $Assessment.Verdict
$Coverage     = $Assessment.Coverage
$Incomplete   = $Assessment.Incomplete
$HardFails    = $Assessment.HardFails
$NotEvaluated = $Assessment.NotEvaluated


$Report = [PSCustomObject]@{

    # 3.1 added the scoring fields: Score, Posture, Verdict, Coverage,
    # Incomplete, HardFails and NotEvaluated.
    SchemaVersion = '3.1'
    ScoringVersion = 2
    SentinelVersion = $script:SentinelVersion

    GeneratedAt =
        (Get-Date).ToString('o')

    ComputerName =
        $env:COMPUTERNAME

    UserName =
        $env:USERNAME

    Administrator =
        $IsAdmin

    Score =
        $Score

    Posture =
        $ScoreBand

    Verdict =
        $ScoreVerdict

    Coverage =
        $Coverage

    Incomplete =
        $Incomplete

    HardFails =
        @($HardFails)

    NotEvaluated =
        @($NotEvaluated)

    Summary =
        $Summary

    Checks =
        @($script:Checks)

    Storage = [PSCustomObject]@{

        PhysicalDisks =
            @($script:PhysicalDisks)

        StoragePools =
            @($script:StoragePools)

        VirtualDisks =
            @($script:VirtualDisks)

        Volumes =
            @($script:Volumes)

        BitLockerVolumes =
            @($script:BitLockerVolumes)
    }

    AntivirusProducts =
        @($script:AntivirusProducts)
}


# ============================================================================
# CONSOLE REPORT
# ============================================================================

if (-not $Quiet) {

    Write-SentinelBanner `
        -Computer $env:COMPUTERNAME `
        -User $env:USERNAME `
        -Admin $IsAdmin


    $Categories =
        @(
            $script:Checks.Category |
            Select-Object -Unique
        )


    foreach ($Category in $Categories) {

        Write-Host ''

        Write-Host "[$Category]" `
            -ForegroundColor Cyan


        $CategoryChecks =
            @(
                $script:Checks |
                Where-Object {
                    $_.Category -eq $Category
                }
            )


        foreach ($Check in $CategoryChecks) {

            $Colour =
                Get-StatusColour `
                    -Status $Check.Status


            $Line =
                '{0,-8} {1,-46} {2}' -f `
                    $Check.Status,
                    $Check.Check,
                    $Check.Value


            Write-Host `
                $Line `
                -ForegroundColor $Colour


            if (
                $Check.Status -in @(
                    'FAIL',
                    'WARN',
                    'UNKNOWN'
                ) -and
                $Check.Details
            ) {

                Write-Host (
                    '         -> ' +
                    $Check.Details
                ) `
                -ForegroundColor DarkGray
            }
        }
    }


    Write-PostureGauge `
        -Score $Score `
        -Band $ScoreBand `
        -Colour $ScoreColour `
        -Verdict $ScoreVerdict `
        -Coverage $Coverage `
        -Incomplete $Incomplete `
        -HardFails $HardFails `
        -NotEvaluated $NotEvaluated `
        -Summary $Summary


    #
    # Useful storage topology summary
    #

    if ($script:VirtualDisks.Count -gt 0) {

        Write-Host ''
        Write-Host '[Storage map]' `
            -ForegroundColor Cyan


        foreach (
            $VD in $script:VirtualDisks
        ) {

            Write-Host (
                " $($VD.FriendlyName)"
            ) `
                -ForegroundColor White


            if ($VD.MountedVolumes) {

                Write-Host (
                    "   Mounted : " +
                    $VD.MountedVolumes
                )
            }


            if ($VD.Resiliency) {

                Write-Host (
                    "   Layout  : " +
                    $VD.Resiliency
                )
            }


            if ($VD.BackingPhysicalDisks) {

                Write-Host (
                    "   Disks   : " +
                    $VD.BackingPhysicalDisks
                )
            }


            Write-Host (
                "   Health  : " +
                $VD.HealthStatus +
                ' / ' +
                $VD.OperationalStatus
            )
        }
    }
}


# ============================================================================
# EXPORTS
# ============================================================================

if (-not $NoExport) {

    try {

        if (
            -not (
                Test-Path $OutputDirectory
            )
        ) {

            New-Item `
                -Path $OutputDirectory `
                -ItemType Directory `
                -Force |
            Out-Null
        }


        $Timestamp =
            Get-Date `
                -Format 'yyyyMMdd_HHmmss'


        $BaseName =
            "WindowsSecurityAudit_" +
            "$($env:COMPUTERNAME)_" +
            $Timestamp


        $TextFile =
            Join-Path `
                $OutputDirectory `
                "$BaseName.txt"


        $JsonFile =
            Join-Path `
                $OutputDirectory `
                "$BaseName.json"


        $HtmlFile =
            Join-Path `
                $OutputDirectory `
                "$BaseName.html"


        $ChecksCsv =
            Join-Path `
                $OutputDirectory `
                "$BaseName`_checks.csv"


        $PhysicalDisksCsv =
            Join-Path `
                $OutputDirectory `
                "$BaseName`_physical-disks.csv"


        $StoragePoolsCsv =
            Join-Path `
                $OutputDirectory `
                "$BaseName`_storage-pools.csv"


        $VirtualDisksCsv =
            Join-Path `
                $OutputDirectory `
                "$BaseName`_virtual-disks.csv"


        $VolumesCsv =
            Join-Path `
                $OutputDirectory `
                "$BaseName`_volumes.csv"


        $BitLockerCsv =
            Join-Path `
                $OutputDirectory `
                "$BaseName`_bitlocker.csv"


        $AntivirusCsv =
            Join-Path `
                $OutputDirectory `
                "$BaseName`_antivirus.csv"


        #
        # JSON
        #

        $Report |
            ConvertTo-Json `
                -Depth 10 |
            Set-Content `
                -Path $JsonFile `
                -Encoding UTF8


        #
        # HTML DASHBOARD (self-contained, no dependencies)
        #

        if (-not $NoHtml) {

            New-HtmlReport `
                -Report $Report |
                Set-Content `
                    -Path $HtmlFile `
                    -Encoding UTF8

            if (
                $OpenReport -and
                (Test-Path $HtmlFile)
            ) {
                Start-Process $HtmlFile
            }
        }


        #
        # CHECKS CSV
        #

        $script:Checks |
            Export-Csv `
                -Path $ChecksCsv `
                -NoTypeInformation `
                -Encoding UTF8


        #
        # STORAGE CSVs
        #

        if (
            $script:PhysicalDisks.Count -gt 0
        ) {

            $script:PhysicalDisks |
                Export-Csv `
                    -Path $PhysicalDisksCsv `
                    -NoTypeInformation `
                    -Encoding UTF8
        }


        if (
            $script:StoragePools.Count -gt 0
        ) {

            $script:StoragePools |
                Export-Csv `
                    -Path $StoragePoolsCsv `
                    -NoTypeInformation `
                    -Encoding UTF8
        }


        if (
            $script:VirtualDisks.Count -gt 0
        ) {

            $script:VirtualDisks |
                Export-Csv `
                    -Path $VirtualDisksCsv `
                    -NoTypeInformation `
                    -Encoding UTF8
        }


        if (
            $script:Volumes.Count -gt 0
        ) {

            $script:Volumes |
                Export-Csv `
                    -Path $VolumesCsv `
                    -NoTypeInformation `
                    -Encoding UTF8
        }


        if (
            $script:BitLockerVolumes.Count -gt 0
        ) {

            $script:BitLockerVolumes |
                Export-Csv `
                    -Path $BitLockerCsv `
                    -NoTypeInformation `
                    -Encoding UTF8
        }


        if (
            $script:AntivirusProducts.Count -gt 0
        ) {

            $script:AntivirusProducts |
                Export-Csv `
                    -Path $AntivirusCsv `
                    -NoTypeInformation `
                    -Encoding UTF8
        }


        #
        # HUMAN-READABLE TEXT REPORT
        #

        $TextOutput =
            [System.Collections.Generic.List[string]]::new()


        $TextOutput.Add(
            'WINDOWS SECURITY POSTURE AUDIT v3'
        )

        $TextOutput.Add(
            ('=' * 100)
        )

        $TextOutput.Add(
            "Computer: $env:COMPUTERNAME"
        )

        $TextOutput.Add(
            "Generated: $(Get-Date)"
        )

        $TextOutput.Add(
            "Administrator: $IsAdmin"
        )

        $TextOutput.Add('')


        $TextOutput.Add(
            (
                "PASS=$($Summary.Pass)  " +
                "WARN=$($Summary.Warn)  " +
                "FAIL=$($Summary.Fail)  " +
                "UNKNOWN=$($Summary.Unknown)  " +
                "INFO=$($Summary.Info)"
            )
        )


        $TextOutput.Add('')
        $TextOutput.Add('CHECK RESULTS')
        $TextOutput.Add(('-' * 100))


        $FormattedChecks =
            $script:Checks |
            Format-Table `
                Category,
                Status,
                Check,
                Value,
                Details `
                -AutoSize |
            Out-String `
                -Width 400


        $TextOutput.Add(
            $FormattedChecks
        )


        if (
            $script:PhysicalDisks.Count -gt 0
        ) {

            $TextOutput.Add('')
            $TextOutput.Add('PHYSICAL DISKS')
            $TextOutput.Add(('-' * 100))

            $TextOutput.Add(
                (
                    $script:PhysicalDisks |
                    Format-Table `
                        DeviceId,
                        FriendlyName,
                        MediaType,
                        BusType,
                        SizeGB,
                        Usage,
                        HealthStatus,
                        OperationalStatus `
                        -AutoSize |
                    Out-String `
                        -Width 400
                )
            )
        }


        if (
            $script:StoragePools.Count -gt 0
        ) {

            $TextOutput.Add('')
            $TextOutput.Add('STORAGE POOLS')
            $TextOutput.Add(('-' * 100))

            $TextOutput.Add(
                (
                    $script:StoragePools |
                    Format-Table `
                        -AutoSize |
                    Out-String `
                        -Width 400
                )
            )
        }


        if (
            $script:VirtualDisks.Count -gt 0
        ) {

            $TextOutput.Add('')
            $TextOutput.Add('VIRTUAL DISKS / STORAGE SPACES')
            $TextOutput.Add(('-' * 100))

            $TextOutput.Add(
                (
                    $script:VirtualDisks |
                    Format-Table `
                        FriendlyName,
                        MountedVolumes,
                        Resiliency,
                        SizeGB,
                        BackingPhysicalDisks,
                        HealthStatus,
                        OperationalStatus `
                        -AutoSize |
                    Out-String `
                        -Width 400
                )
            )
        }


        if (
            $script:Volumes.Count -gt 0
        ) {

            $TextOutput.Add('')
            $TextOutput.Add('MOUNTED VOLUMES')
            $TextOutput.Add(('-' * 100))

            $TextOutput.Add(
                (
                    $script:Volumes |
                    Where-Object {
                        $_.MountPoint
                    } |
                    Format-Table `
                        MountPoint,
                        Label,
                        FileSystem,
                        DriveType,
                        SizeGB,
                        FreeGB,
                        DiskNumber,
                        IsHidden,
                        HealthStatus `
                        -AutoSize |
                    Out-String `
                        -Width 400
                )
            )
        }


        if (
            $script:BitLockerVolumes.Count -gt 0
        ) {

            $TextOutput.Add('')
            $TextOutput.Add('BITLOCKER VOLUMES')
            $TextOutput.Add(('-' * 100))

            $TextOutput.Add(
                (
                    $script:BitLockerVolumes |
                    Format-Table `
                        MountPoint,
                        VolumeType,
                        CapacityGB,
                        VolumeStatus,
                        ProtectionStatus,
                        EncryptionPercentage,
                        EncryptionMethod,
                        KeyProtectors `
                        -AutoSize |
                    Out-String `
                        -Width 400
                )
            )
        }


        $TextOutput |
            Set-Content `
                -Path $TextFile `
                -Encoding UTF8


        if (-not $Quiet) {

            Write-Host ''
            Write-Host 'Reports written to:' `
                -ForegroundColor Cyan

            if (-not $NoHtml -and (Test-Path $HtmlFile)) {
                Write-Host "  $HtmlFile" `
                    -ForegroundColor Green
            }

            Write-Host "  $TextFile"
            Write-Host "  $JsonFile"
            Write-Host "  $ChecksCsv"

            if (
                Test-Path $PhysicalDisksCsv
            ) {
                Write-Host "  $PhysicalDisksCsv"
            }

            if (
                Test-Path $StoragePoolsCsv
            ) {
                Write-Host "  $StoragePoolsCsv"
            }

            if (
                Test-Path $VirtualDisksCsv
            ) {
                Write-Host "  $VirtualDisksCsv"
            }

            if (
                Test-Path $VolumesCsv
            ) {
                Write-Host "  $VolumesCsv"
            }

            if (
                Test-Path $BitLockerCsv
            ) {
                Write-Host "  $BitLockerCsv"
            }

            if (
                Test-Path $AntivirusCsv
            ) {
                Write-Host "  $AntivirusCsv"
            }
        }
    }
    catch {

        Write-Warning (
            "Report export failed: " +
            $_.Exception.Message
        )
    }
}


# ============================================================================
# OPTIONAL PIPELINE OUTPUT
# ============================================================================

if ($PassThru) {
    $Report
}
