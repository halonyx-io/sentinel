#requires -Version 5.1
<#
.SYNOPSIS
    Regression test: collected strings cannot break out of the dashboard's
    embedded report script.

.DESCRIPTION
    Loads the real New-HtmlReport from WindowsSecurityAudit.ps1, renders a
    report whose fields carry hostile markup, and checks that the payload
    stays inside its <script> element and still decodes to the same data.
    Runs on any platform; it does not audit the machine.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ScriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'WindowsSecurityAudit.ps1'
$Ast = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$null, [ref]$null)
$Renderer = $Ast.Find({
    param($Node)
    $Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -eq 'New-HtmlReport'
}, $true)
if ($null -eq $Renderer) { throw 'New-HtmlReport not found.' }
. ([scriptblock]::Create($Renderer.Extent.Text))

$Hostile = @(
    '</script><script>alert(1)</script>'
    '</SCRIPT ><img src=x onerror=alert(2)>'
    '<!--<script>'
    '"><svg onload=alert(3)>'
    "line$([char]0x2028)separator$([char]0x2029)end"
    '&lt;already&gt; & ampersand'
)

$Report = [PSCustomObject]@{
    SchemaVersion = '3.1'; ScoringVersion = 2
    GeneratedAt = (Get-Date).ToString('o')
    ComputerName = $Hostile[0]; UserName = $Hostile[1]; Administrator = $true
    Score = 50; Posture = $Hostile[2]; Verdict = $Hostile[3]; Coverage = 100; Incomplete = $false
    HardFails = @(); NotEvaluated = @()
    Checks = @(foreach ($Text in $Hostile) {
        [PSCustomObject]@{ Category = $Text; Check = $Text; Status = 'PASS'; Value = $Text; Expected = $Text; Details = $Text }
    })
}

$Html = New-HtmlReport -Report $Report

# JSON strings cannot contain raw newlines, so the payload ends at the first
# ';' that is followed by the blank line before the next code block.
$Match = [regex]::Match($Html, '(?s)const REPORT = (.*?);\r?\n\r?\n/\* -+ ordering')
if (-not $Match.Success) { throw 'Embedded report not found.' }
$Payload = $Match.Groups[1].Value

$Failures = [System.Collections.Generic.List[string]]::new()
foreach ($Bad in @('<', '>', [string][char]0x2028, [string][char]0x2029)) {
    if ($Payload.Contains($Bad)) { $Failures.Add("payload contains a raw '$Bad'") }
}
# The page's own script elements are the only ones: one opener per closer,
# and the hostile strings add neither.
$Openers = [regex]::Matches($Html, '(?i)<script\b').Count
$Closers = [regex]::Matches($Html, '(?i)</script').Count
if ($Openers -ne $Closers -or $Openers -lt 1) { $Failures.Add("script openers $Openers vs closers $Closers") }

$Decoded = $Payload | ConvertFrom-Json
for ($i = 0; $i -lt $Hostile.Count; $i++) {
    if ($Decoded.Checks[$i].Value -cne $Hostile[$i]) { $Failures.Add("string $i did not round-trip") }
}
if ($Decoded.ComputerName -cne $Hostile[0]) { $Failures.Add('ComputerName did not round-trip') }

if ($Failures.Count -gt 0) {
    $Failures | ForEach-Object { Write-Host "  FAIL  $_" -ForegroundColor Red }
    exit 1
}
Write-Host "HTML embedding passed on PowerShell $($PSVersionTable.PSVersion) with $($Hostile.Count) hostile strings." -ForegroundColor Green
exit 0
