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
    # The bootstrap is constant. The audit travels over stdin, outside the
    # remote shell command line. SSH uses the operator's known hosts and keys.
    $bootstrap = {
        $ErrorActionPreference = 'Stop'
        try {
            [Console]::OutputEncoding = [Text.Encoding]::UTF8
            $source = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd()))
            # Tag the report so login banners or profile output on stdout
            # cannot be mistaken for it.
            'SENTINEL-REPORT:' + (& { SENTINEL_COLLECT } $source)
        }
        catch {
            [Console]::Error.WriteLine($_.Exception.Message)
            exit 1
        }
    }.ToString().Replace('SENTINEL_COLLECT', $collect.ToString())
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bootstrap))
    $payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($source))
    # The remote writes UTF-8; decode it as such on Windows clients too.
    $consoleEncoding = [Console]::OutputEncoding
    try {
        # Hosts without a console (ISE) refuse the change; keep their default.
        try { [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false) } catch { }
        $lines = @($payload | & $ssh.Source -T -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -- $SshHost powershell.exe -NoProfile -NonInteractive -EncodedCommand $encoded)
        $sshExit = $LASTEXITCODE
    }
    finally {
        try { [Console]::OutputEncoding = $consoleEncoding } catch { }
    }
    if ($sshExit -ne 0) {
        throw "SSH audit of '$SshHost' failed (exit $sshExit). Check the SSH account, known host entry and endpoint access."
    }
    $json = @($lines | Where-Object { "$_".StartsWith('SENTINEL-REPORT:') } |
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
