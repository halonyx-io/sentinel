#requires -Version 5.1
<#
.SYNOPSIS
Runs Sentinel on one Windows host over an existing authenticated management channel.

.EXAMPLE
.\Invoke-SentinelRemote.ps1 -ComputerName workstation.example.com

.EXAMPLE
.\Invoke-SentinelRemote.ps1 -ComputerName 192.0.2.10 -UseSSL -Credential (Get-Credential)

.EXAMPLE
./Invoke-SentinelRemote.ps1 -SshHost goliath | ConvertTo-Json -Depth 12
#>
[CmdletBinding(DefaultParameterSetName = 'WinRM')]
param(
    [Parameter(Mandatory, ParameterSetName = 'WinRM')]
    [ValidateNotNullOrEmpty()]
    [string]$ComputerName,

    [Parameter(ParameterSetName = 'WinRM')]
    [switch]$UseSSL,

    [Parameter(ParameterSetName = 'WinRM')]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(Mandatory, ParameterSetName = 'SSH')]
    [ValidatePattern('^(?:[a-zA-Z0-9_.-]+@)?(?:[a-zA-Z0-9_][a-zA-Z0-9_.:-]*|\[[a-fA-F0-9:]+\])$')]
    [string]$SshHost,

    [string]$HtmlPath
)

$ErrorActionPreference = 'Stop'
$auditPath = Join-Path $PSScriptRoot 'WindowsSecurityAudit.ps1'
$source = [IO.File]::ReadAllText($auditPath)
$collect = {
    param([string]$AuditSource)
    $ErrorActionPreference = 'Stop'
    # Module cmdlets (Storage, Defender, NetSecurity) read the global value;
    # over SSH their progress records would otherwise reach stderr as CLIXML.
    $global:ProgressPreference = 'SilentlyContinue'
    $audit = [scriptblock]::Create($AuditSource)
    $report = & $audit -NoExport -Quiet -PassThru
    if ($null -eq $report -or $null -eq $report.PSObject.Properties['Checks']) {
        throw 'Sentinel did not return an audit report.'
    }
    ConvertTo-Json -InputObject $report -Depth 12 -Compress
}

if ($PSCmdlet.ParameterSetName -eq 'SSH') {
    $ssh = Get-Command ssh -CommandType Application | Select-Object -First 1

    # Run one PowerShell statement on the target as a base64 -EncodedCommand.
    # Everything travels on the command line, never stdin: newer Windows
    # OpenSSH deadlocks when a large payload is piped to a non-interactive
    # command, so the audit is staged in command-line-sized pieces instead.
    # -EncodedCommand also sidesteps all cmd.exe / PowerShell quoting.
    $sshOpts = @(
        '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
        '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3'
    )
    function Invoke-RemotePwsh {
        param([string]$Statement, [switch]$CaptureUtf8)
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Statement))
        # cmd.exe caps the command line at 8191 chars; keep well under it.
        if (('powershell.exe -NoProfile -NonInteractive -EncodedCommand ' + $enc).Length -gt 8000) {
            throw 'Internal error: remote command exceeds the shell command-line limit.'
        }
        $saved = $null
        if ($CaptureUtf8) {
            # The remote writes UTF-8; decode it as such on Windows clients too.
            $saved = [Console]::OutputEncoding
            try { [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false) } catch { }
        }
        try {
            $out = & $ssh.Source @sshOpts -- $SshHost powershell.exe -NoProfile -NonInteractive -EncodedCommand $enc
        }
        finally {
            if ($CaptureUtf8 -and $null -ne $saved) { try { [Console]::OutputEncoding = $saved } catch { } }
        }
        [PSCustomObject]@{ Output = @($out); ExitCode = $LASTEXITCODE }
    }

    # Compress the audit source (it is ~75% whitespace and comments) and
    # base64 it, so fewer round trips are needed to stage it on the target.
    $srcBytes = [Text.Encoding]::UTF8.GetBytes($source)
    $buffer = [IO.MemoryStream]::new()
    $gzip = [IO.Compression.GZipStream]::new($buffer, [IO.Compression.CompressionLevel]::Optimal)
    $gzip.Write($srcBytes, 0, $srcBytes.Length)
    $gzip.Dispose()
    $payload = [Convert]::ToBase64String($buffer.ToArray())

    # A GUID path under the target's own TEMP, resolved on the target so no
    # client assumption about the remote profile is baked in.
    $token = [guid]::NewGuid().ToString('N')
    $pathExpr = "`$p = Join-Path `$env:TEMP 'sentinel-$token.gz.b64'"

    # Each piece stays within the command-line budget after -EncodedCommand's
    # UTF-16 + base64 expansion (~2.67x). 2500 chars leaves ample headroom.
    $chunkSize = 2500
    for ($i = 0; $i -lt $payload.Length; $i += $chunkSize) {
        $piece = $payload.Substring($i, [Math]::Min($chunkSize, $payload.Length - $i))
        $writer = if ($i -eq 0) { 'WriteAllText' } else { 'AppendAllText' }
        $stage = Invoke-RemotePwsh -Statement "$pathExpr; [IO.File]::$writer(`$p, '$piece')"
        if ($stage.ExitCode -ne 0) {
            # Best-effort cleanup of any partial file before giving up.
            [void](Invoke-RemotePwsh -Statement "$pathExpr; Remove-Item -LiteralPath `$p -Force -ErrorAction SilentlyContinue")
            throw "Staging the audit on '$SshHost' failed (exit $($stage.ExitCode)). Check the SSH account, known host entry and endpoint access."
        }
    }

    # Decompress on the target, run the audit in memory, emit the tagged
    # report, and always delete the staged file.
    $bootstrap = {
        $ErrorActionPreference = 'Stop'
        PATH_EXPR
        try {
            [Console]::OutputEncoding = [Text.Encoding]::UTF8
            $bytes = [Convert]::FromBase64String([IO.File]::ReadAllText($p))
            $gz = [IO.Compression.GZipStream]::new(
                [IO.MemoryStream]::new($bytes), [IO.Compression.CompressionMode]::Decompress)
            $source = [IO.StreamReader]::new($gz).ReadToEnd()
            # Tag the report so login banners or profile output on stdout
            # cannot be mistaken for it.
            'SENTINEL-REPORT:' + (& { SENTINEL_COLLECT } $source)
        }
        catch {
            [Console]::Error.WriteLine($_.Exception.Message)
            exit 1
        }
        finally {
            Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
        }
    }.ToString().Replace('PATH_EXPR', $pathExpr).Replace('SENTINEL_COLLECT', $collect.ToString())

    $run = Invoke-RemotePwsh -Statement $bootstrap -CaptureUtf8
    if ($run.ExitCode -ne 0) {
        throw "SSH audit of '$SshHost' failed (exit $($run.ExitCode)). Check the SSH account, known host entry and endpoint access."
    }
    $json = @($run.Output | Where-Object { "$_".StartsWith('SENTINEL-REPORT:') } |
        ForEach-Object { "$_".Substring('SENTINEL-REPORT:'.Length) })
}
else {
    $address = $null
    if ([Net.IPAddress]::TryParse($ComputerName, [ref]$address) -and -not $UseSSL) {
        throw 'Use a DNS name with Kerberos, or specify -UseSSL for an IP address with a matching WinRM certificate.'
    }
    $connection = @{
        ComputerName = $ComputerName
        ScriptBlock = $collect
        ArgumentList = @($source)
        SessionOption = (New-PSSessionOption -OpenTimeout 10000 -OperationTimeout 120000)
        ErrorAction = 'Stop'
    }
    if ($UseSSL) {
        $connection.UseSSL = $true
        $connection.Authentication = 'Negotiate'
    }
    else {
        $connection.Authentication = 'Kerberos'
    }
    if ($Credential) { $connection.Credential = $Credential }
    $json = Invoke-Command @connection
}

if (@($json).Count -ne 1 -or -not $json) {
    throw 'Expected one JSON report from the remote host.'
}
$report = ConvertFrom-Json -InputObject ([string]@($json)[0])
if ($null -eq $report -or $null -eq $report.PSObject.Properties['Checks']) {
    throw 'The remote host returned JSON without an audit report.'
}

if ($HtmlPath) {
    # Load the local renderer without running an audit on the client.
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$null, [ref]$null)
    $renderer = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'New-HtmlReport'
    }, $false)
    if ($null -eq $renderer) { throw 'The local audit script has no HTML renderer.' }
    . ([scriptblock]::Create($renderer.Extent.Text))
    New-HtmlReport -Report $report | Set-Content -LiteralPath $HtmlPath -Encoding UTF8
}
$report
