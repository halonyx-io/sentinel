#requires -Version 5.1
<#
.SYNOPSIS
Compare two Sentinel JSON exports for the same computer.
.EXAMPLE
./Compare-SentinelReport.ps1 -Before ./before.json -After ./after.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Before,

    [Parameter(Mandatory)]
    [string]$After
)

$ErrorActionPreference = 'Stop'
function Read-Report {
    param([string]$Path)
    $report = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if (-not $report.ComputerName -or $null -eq $report.Checks -or $null -eq $report.Score) {
        throw "Expected a Sentinel JSON report at '$Path'."
    }
    $report
}

function Index-Checks {
    param($Report)
    $index = @{}
    foreach ($check in $Report.Checks) {
        $key = ConvertTo-Json -InputObject @($check.Category, $check.Check) -Compress
        if (-not $index.ContainsKey($key)) {
            $index[$key] = [System.Collections.Generic.List[object]]::new()
        }
        $index[$key].Add($check)
    }
    $index
}

$old = Read-Report $Before
$new = Read-Report $After
if ($old.ComputerName -ne $new.ComputerName) {
    throw 'The reports identify different computers.'
}

$rank = @{ FAIL = 0; WARN = 1; PASS = 2 }
$left = Index-Checks $old
$right = Index-Checks $new
$changes = @(
    foreach ($key in (@($left.Keys) + @($right.Keys) | Sort-Object -Unique)) {
        $a = if ($left.ContainsKey($key)) { $left[$key].ToArray() }
        $b = if ($right.ContainsKey($key)) { $right[$key].ToArray() }
        $oldRows = @($a | Where-Object { $null -ne $_ })
        $newRows = @($b | Where-Object { $null -ne $_ })
        $oldStatus = @($oldRows.Status | Sort-Object)
        $newStatus = @($newRows.Status | Sort-Object)
        $oldEvidence = @($oldRows | ForEach-Object {
            ConvertTo-Json -InputObject @($_.Status, $_.Value, $_.Expected, $_.Details) -Compress
        } | Sort-Object)
        $newEvidence = @($newRows | ForEach-Object {
            ConvertTo-Json -InputObject @($_.Status, $_.Value, $_.Expected, $_.Details) -Compress
        } | Sort-Object)
        if (($oldEvidence -join [char]0) -ceq ($newEvidence -join [char]0)) { continue }
        $kind = if (-not $oldRows.Count) { 'Added' }
        elseif (-not $newRows.Count) { 'Removed' }
        elseif (($oldStatus -join ',') -eq ($newStatus -join ',')) { 'EvidenceChanged' }
        elseif ($oldRows.Count -eq 1 -and $newRows.Count -eq 1 -and
                $rank.ContainsKey($oldStatus[0]) -and $rank.ContainsKey($newStatus[0])) {
            if ($rank[$newStatus[0]] -gt $rank[$oldStatus[0]]) { 'Improved' } else { 'Deteriorated' }
        }
        else { 'AssessmentChanged' }
        $labels = ConvertFrom-Json -InputObject $key
        [PSCustomObject]@{
            Category = $labels[0]
            Check = $labels[1]
            Change = $kind
            Before = $oldRows
            After = $newRows
        }
    }
)

$comparable = $old.SchemaVersion -eq $new.SchemaVersion -and
    $old.ScoringVersion -eq $new.ScoringVersion -and
    $old.Administrator -eq $new.Administrator -and
    $old.Incomplete -eq $new.Incomplete -and $old.Coverage -eq $new.Coverage

$scoreDelta = if ($comparable) { $new.Score - $old.Score }

[PSCustomObject]@{
    ComputerName = $new.ComputerName
    BeforeTime = $old.GeneratedAt
    AfterTime = $new.GeneratedAt
    BeforeScore = $old.Score
    AfterScore = $new.Score
    BeforeCoverage = $old.Coverage
    AfterCoverage = $new.Coverage
    ScoreComparable = $comparable
    ScoreDelta = $scoreDelta
    Changes = $changes
}
