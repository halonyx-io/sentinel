#requires -Version 5.1

<#
.SYNOPSIS
    Regression tests for Sentinel's scoring model.

.DESCRIPTION
    These tests exist because the same bug class has bitten this project twice:
    a security control that silently stops contributing to the score, so an
    unprotected machine reports as a safe one.

    They load the real Get-PostureBand / Get-PostureAssessment functions out of
    WindowsSecurityAudit.ps1 (no copies, no drift) and assert the behaviour that
    must never regress:

      - informational checks can never inflate the score (the dilution bug)
      - a failing critical control caps the whole machine
      - a control that produced NO result is a blind spot, never a pass
      - partial runs can never reach a green band

.EXAMPLE
    .\tests\Test-Sentinel.ps1

.NOTES
    Exits 1 if any test fails, so it can gate CI.
#>

[CmdletBinding()]
param(
    [string]$ScriptPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if (-not $ScriptPath) {
    $ScriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'WindowsSecurityAudit.ps1'
}

if (-not (Test-Path $ScriptPath)) {
    throw "Cannot find WindowsSecurityAudit.ps1 at: $ScriptPath"
}


# ---- load the real scoring functions (parse only; the script never runs) ----
$Ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $ScriptPath, [ref]$null, [ref]$null
)

$Wanted = @('Get-PostureBand', 'Get-PostureAssessment')

$Functions = $Ast.FindAll(
    {
        param($Node)
        $Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $Wanted -contains $Node.Name
    },
    $true
)

foreach ($Function in $Functions) {
    . ([scriptblock]::Create($Function.Extent.Text))
}

foreach ($Name in $Wanted) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Could not load $Name from $ScriptPath"
    }
}


# ---- tiny test harness ----
$script:Passed = 0
$script:Failed = 0

function Assert-That {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Condition,
        [string]$Detail = ''
    )

    if ($Condition) {
        $script:Passed++
        Write-Host ('  PASS  ' + $Name) -ForegroundColor Green
    }
    else {
        $script:Failed++
        Write-Host ('  FAIL  ' + $Name) -ForegroundColor Red
        if ($Detail) {
            Write-Host ('        ' + $Detail) -ForegroundColor DarkGray
        }
    }
}

function New-Check {
    param([string]$Category, [string]$Check, [string]$Status)
    [PSCustomObject]@{
        Category = $Category
        Check    = $Check
        Status   = $Status
        Value    = ''
        Expected = ''
        Details  = ''
    }
}


# A machine where every required control is assessed and healthy.
function Get-HealthyChecks {
    @(
        (New-Check 'Boot Security'        'Secure Boot'                    'PASS')
        (New-Check 'Boot Security'        'Firmware boot mode'             'PASS')
        (New-Check 'TPM'                  'TPM specification'             'PASS')
        (New-Check 'Virtualisation Security' 'Virtualization Based Security' 'PASS')
        (New-Check 'Virtualisation Security' 'Memory Integrity / HVCI'     'PASS')
        (New-Check 'Virtualisation Security' 'Credential Guard'            'PASS')
        (New-Check 'Credential Protection' 'LSA protected process configuration' 'PASS')
        (New-Check 'TPM'                  'TPM present'                    'PASS')
        (New-Check 'Firewall'             'Domain profile'                 'PASS')
        (New-Check 'Firewall'             'Private profile'                'PASS')
        (New-Check 'Firewall'             'Public profile'                 'PASS')
        (New-Check 'SMB Security'         'SMBv1 server protocol'          'PASS')
        (New-Check 'Privilege Protection' 'User Account Control'           'PASS')
        (New-Check 'Antivirus'            'Real-time antivirus protection' 'PASS')
        (New-Check 'Encryption'           'OS volume C:'                   'PASS')
    )
}


Write-Host ''
Write-Host 'Sentinel scoring regression tests' -ForegroundColor Cyan
Write-Host ('-' * 60) -ForegroundColor DarkGray


# ---- 1. a fully assessed healthy machine is the only way to a green band ----
$Healthy = Get-PostureAssessment -Checks (Get-HealthyChecks) -IsAdmin $true

Assert-That 'healthy + fully assessed reaches HARDENED' `
    ($Healthy.Score -eq 100 -and $Healthy.Band -eq 'HARDENED' -and -not $Healthy.Incomplete) `
    "got $($Healthy.Score)/$($Healthy.Band) incomplete=$($Healthy.Incomplete)"


# ---- 2. THE DILUTION BUG: informational checks must not move the score ----
$Diluted = @(Get-HealthyChecks)
1..20 | ForEach-Object {
    $Diluted += (New-Check 'Storage Health' "Volume $_" 'PASS')
    $Diluted += (New-Check 'Storage Health' "Physical disk $_" 'PASS')
}
$DilutedResult = Get-PostureAssessment -Checks $Diluted -IsAdmin $true

Assert-That 'adding 40 healthy disks/volumes does not change the score' `
    ($DilutedResult.Score -eq $Healthy.Score) `
    "baseline $($Healthy.Score), with healthy hardware $($DilutedResult.Score)"


# ---- 3. a failing critical control caps the whole machine ----
$NoEncryption = @(Get-HealthyChecks | Where-Object { $_.Check -ne 'OS volume C:' })
$NoEncryption += (New-Check 'Encryption' 'OS volume C:' 'FAIL')
$NoEncryptionResult = Get-PostureAssessment -Checks $NoEncryption -IsAdmin $true

Assert-That 'unencrypted OS drive caps the score at 35' `
    ($NoEncryptionResult.Score -le 35) `
    "got $($NoEncryptionResult.Score)"

Assert-That 'unencrypted OS drive is reported as a hard fail' `
    (@($NoEncryptionResult.HardFails | Where-Object { $_.Check -eq 'OS volume C:' }).Count -eq 1)

# ...even when everything else on the box is perfect and plentiful
$NoEncryptionPlusDisks = @($NoEncryption)
1..20 | ForEach-Object {
    $NoEncryptionPlusDisks += (New-Check 'Storage Health' "Volume $_" 'PASS')
}
$Rescue = Get-PostureAssessment -Checks $NoEncryptionPlusDisks -IsAdmin $true

Assert-That 'healthy hardware cannot rescue an unencrypted OS drive' `
    ($Rescue.Score -le 35) `
    "got $($Rescue.Score)"


# ---- 4. unencrypted data drives have their own, lesser cap ----
$DataFail = @(Get-HealthyChecks)
$DataFail += (New-Check 'Encryption' 'Data volume D:' 'FAIL')
$DataFailResult = Get-PostureAssessment -Checks $DataFail -IsAdmin $true

Assert-That 'unencrypted data drive caps the score at 65' `
    ($DataFailResult.Score -le 65) `
    "got $($DataFailResult.Score)"

Assert-That 'data drive cap is less severe than the OS drive cap' `
    ($DataFailResult.Score -gt $NoEncryptionResult.Score)


# ---- 5. BLIND SPOTS: a control that produced no result is never a pass ----
$Blind = @(Get-HealthyChecks | Where-Object { $_.Check -ne 'OS volume C:' })
$BlindResult = Get-PostureAssessment -Checks $Blind -IsAdmin $true

Assert-That 'a missing required control is reported as NOT EVALUATED' `
    (@($BlindResult.NotEvaluated | Where-Object { $_.Control -match 'OS drive encryption' }).Count -eq 1)

Assert-That 'a missing critical control caps the score like a failure' `
    ($BlindResult.Score -le 35) `
    "got $($BlindResult.Score)"

Assert-That 'a missing critical control marks the run INCOMPLETE' `
    ($BlindResult.Incomplete)

Assert-That 'a missing control reduces coverage below 100%' `
    ($BlindResult.Coverage -lt 100) `
    "coverage $($BlindResult.Coverage)%"


# ---- 6. undetermined controls never earn a green band ----
$Unknown = @(Get-HealthyChecks | Where-Object { $_.Check -ne 'OS volume C:' })
$Unknown += (New-Check 'Encryption' 'OS volume C:' 'UNKNOWN')
$UnknownResult = Get-PostureAssessment -Checks $Unknown -IsAdmin $true

Assert-That 'unknown OS encryption uses the same score cap as missing OS encryption' `
    ($UnknownResult.Score -eq $BlindResult.Score -and $UnknownResult.Incomplete) `
    "got $($UnknownResult.Score)/$($UnknownResult.Band)"


$UnknownUac = @(Get-HealthyChecks | Where-Object { $_.Check -ne 'User Account Control' })
$UnknownUac += (New-Check 'Privilege Protection' 'User Account Control' 'UNKNOWN')
$UnknownUacResult = Get-PostureAssessment -Checks $UnknownUac -IsAdmin $true
Assert-That 'unknown required UAC prevents a green band even above the coverage threshold' `
    ($UnknownUacResult.Coverage -ge 80 -and $UnknownUacResult.Score -le 74 -and $UnknownUacResult.Incomplete)

# ---- 7. non-elevated runs are always INCOMPLETE and clamped ----
$NotElevated = Get-PostureAssessment -Checks (Get-HealthyChecks) -IsAdmin $false

Assert-That 'a non-elevated run cannot reach a green band' `
    ($NotElevated.Score -le 74 -and $NotElevated.Incomplete) `
    "got $($NotElevated.Score)/$($NotElevated.Band)"


# ---- 8. caps stack by taking the minimum ----
$Stacked = @(Get-HealthyChecks | Where-Object {
    $_.Check -ne 'Public profile' -and $_.Check -ne 'Real-time antivirus protection'
})
$Stacked += (New-Check 'Firewall'  'Public profile'                 'FAIL')
$Stacked += (New-Check 'Antivirus' 'Real-time antivirus protection' 'FAIL')
$StackedResult = Get-PostureAssessment -Checks $Stacked -IsAdmin $true

Assert-That 'stacked caps take the lowest (AV 50 beats firewall 55)' `
    ($StackedResult.Score -le 50) `
    "got $($StackedResult.Score)"


# ---- 9. INFO must not count toward coverage ----
$WithInfo = @(Get-HealthyChecks)
$WithInfo += (New-Check 'Encryption' 'Data volume Z:' 'INFO')
$WithInfoResult = Get-PostureAssessment -Checks $WithInfo -IsAdmin $true

Assert-That 'INFO-status checks do not affect score or coverage' `
    ($WithInfoResult.Score -eq $Healthy.Score -and $WithInfoResult.Coverage -eq $Healthy.Coverage)


$Partial = @(Get-HealthyChecks | Where-Object { $_.Check -notin @('Private profile', 'Public profile', 'Memory Integrity / HVCI') })
$PartialResult = Get-PostureAssessment -Checks $Partial
Assert-That 'a single firewall profile leaves two independently recorded gaps' `
    (@($PartialResult.NotEvaluated | Where-Object Category -eq 'Firewall').Count -eq 2 -and $PartialResult.Score -le 55)
Assert-That 'missing HVCI is recorded as a required gap' `
    (@($PartialResult.NotEvaluated | Where-Object Control -eq 'Memory Integrity / HVCI').Count -eq 1)

$MixedVolumes = @(Get-HealthyChecks) + @(
    (New-Check 'Encryption' 'Data volume D:' 'WARN')
    (New-Check 'Encryption' 'Data volume E:' 'PASS')
)
$MixedResult = Get-PostureAssessment -Checks $MixedVolumes
$MoreVolumes = $MixedVolumes + @(1..20 | ForEach-Object { New-Check 'Encryption' "Data volume additional $_" 'PASS' })
$MoreResult = Get-PostureAssessment -Checks $MoreVolumes
Assert-That 'healthy data volumes cannot outweigh a warning on another volume' `
    ($MixedResult.Score -lt 100 -and $MixedResult.Score -eq $MoreResult.Score)

$Noncritical = @(Get-HealthyChecks) + (New-Check 'Defender' 'Signature age' 'FAIL')
$NoncriticalResult = Get-PostureAssessment -Checks $Noncritical
Assert-That 'noncritical failures reduce the score without appearing as hard failures' `
    ($NoncriticalResult.Score -lt 100 -and $NoncriticalResult.HardFails.Count -eq 0)

# ---- 10. every scoring entry is well-formed ----
$Source = ($Ast.FindAll(
    {
        param($Node)
        $Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $Node.Name -eq 'Get-PostureAssessment'
    }, $true))[0].Extent.Text

$MapBody = [regex]::Match($Source, '(?s)\$Map = @\((.*?)\n    \)').Groups[1].Value
$Entries = [regex]::Matches($MapBody, "Cat = '[^']+'")
$Complete = [regex]::Matches(
    $MapBody,
    "Cat = '[^']+';\s*Pat = '[^']+';\s*W = \d+;\s*Cap = \d+;\s*Crit = \`$\w+;\s*Req = \`$\w+;\s*Name = '[^']+'"
)

Assert-That 'every control-map entry declares Cat/Pat/W/Cap/Crit/Req/Name' `
    ($Entries.Count -gt 0 -and $Entries.Count -eq $Complete.Count) `
    "$($Entries.Count) entries, $($Complete.Count) well-formed"


Write-Host ('-' * 60) -ForegroundColor DarkGray
Write-Host ("  $($script:Passed) passed, $($script:Failed) failed") -ForegroundColor $(
    if ($script:Failed -gt 0) { 'Red' } else { 'Green' }
)
Write-Host ''

if ($script:Failed -gt 0) { exit 1 }
exit 0
