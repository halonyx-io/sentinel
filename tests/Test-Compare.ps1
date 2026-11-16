#requires -Version 5.1
$ErrorActionPreference = 'Stop'
$compare = Join-Path (Split-Path $PSScriptRoot -Parent) 'Compare-SentinelReport.ps1'
$temp = Join-Path ([IO.Path]::GetTempPath()) ('sentinel-compare-' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $temp)
try {
    $before = Join-Path $temp 'before.json'
    $after = Join-Path $temp 'after.json'
    $report = @{
        ComputerName = 'test-host'; Score = 50; SchemaVersion = '3.1'; ScoringVersion = 2
        Administrator = $true; Incomplete = $false; Coverage = 100
    }
    function New-Row($name, $status, $value = '') {
        @{ Category = 'Test'; Check = $name; Status = $status; Value = $value }
    }
    $report.Checks = @(
        (New-Row Recovered FAIL)
        (New-Row Weakened PASS)
        (New-Row Unreadable UNKNOWN)
        (New-Row Missing PASS)
        (New-Row Detail INFO old)
        (New-Row Duplicate PASS a)
        (New-Row Duplicate WARN b)
    )
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $before
    $report.Score = 55
    $report.Checks = @(
        (New-Row Recovered PASS)
        (New-Row Weakened WARN)
        (New-Row Unreadable PASS)
        (New-Row Detail INFO new)
        (New-Row New PASS)
        (New-Row Duplicate WARN b)
        (New-Row Duplicate PASS a)
    )
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $after
    $diff = & $compare -Before $before -After $after
    if (-not $diff.ScoreComparable -or $diff.ScoreDelta -ne 5 -or $diff.Changes.Count -ne 6) {
        throw 'Unexpected comparison totals.'
    }
    $expected = @{
        Recovered='Improved'; Weakened='Deteriorated'; Unreadable='AssessmentChanged'
        Detail='EvidenceChanged'; Missing='Removed'; New='Added'
    }
    foreach ($row in $diff.Changes) {
        if ($expected[$row.Check] -ne $row.Change) { throw "Incorrect classification for $($row.Check)." }
    }
    $report.ScoringVersion = 1
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $after
    $diff = & $compare -Before $before -After $after
    if ($diff.ScoreComparable -or $null -ne $diff.ScoreDelta) { throw 'Changed scoring version was compared.' }
    Write-Host 'Report comparison fixtures passed.'
}
finally {
    Remove-Item -LiteralPath $temp -Recurse
}
