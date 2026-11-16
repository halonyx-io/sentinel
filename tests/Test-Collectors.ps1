#requires -Version 5.1
$ErrorActionPreference = 'Stop'
$audit = Join-Path (Split-Path $PSScriptRoot -Parent) 'WindowsSecurityAudit.ps1'
$temp = Join-Path ([IO.Path]::GetTempPath()) ('sentinel-collectors-' + [guid]::NewGuid().ToString('N'))
try {
    $report = & $audit -Quiet -PassThru -OutputDirectory $temp
    $diagnostics = @($report.Checks | Where-Object Category -eq 'Diagnostics')
    if ($report.ComputerName -ne $env:COMPUTERNAME -or $diagnostics.Count -ne 3 -or $report.ScoringVersion -ne 2) {
        throw 'Unexpected audit report.'
    }
    if (-not ($report.Checks | Where-Object Category -eq 'Collection')) { throw 'Collection checks missing.' }
    $json = @(Get-ChildItem -LiteralPath $temp -Filter '*.json')
    $html = @(Get-ChildItem -LiteralPath $temp -Filter '*.html')
    if ($json.Count -ne 1 -or $html.Count -ne 1) { throw 'Expected JSON and HTML reports.' }
    $saved = Get-Content -LiteralPath $json[0].FullName -Raw | ConvertFrom-Json
    if ($saved.Checks.Count -ne $report.Checks.Count -or $saved.Score -ne $report.Score) {
        throw 'Saved audit disagrees with the pipeline report.'
    }
    $dashboard = Get-Content -LiteralPath $html[0].FullName -Raw
    if ($dashboard -match 'fonts\.googleapis|@@REPORT_JSON@@' -or $dashboard -notmatch 'System drive free space') {
        throw 'The HTML dashboard is missing its embedded offline report.'
    }
    Write-Host "Collectors and exports passed on PowerShell $($PSVersionTable.PSVersion) with $($report.Checks.Count) checks."
}
finally {
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse }
}
