<#
Bounded read-only worker. Start manually inside the registered Server 2022 VM.
No service installation, policy writes, arbitrary commands, or remediation.
FunctionsOnly loads validation helpers without inspecting the host.
#>
[CmdletBinding()]
param(
    [string]$ExchangeDirectory,
    [string]$ExpectedComputerName,
    [string]$ExpectedMachineUuid,
    [string]$ExpectedCollectorSha256,
    [ValidateRange(1,3600)][int]$WatchSeconds = 300,
    [ValidateRange(1,20)][int]$MaxRequests = 5,
    [switch]$FunctionsOnly
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ScanHash([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Assert-ScanRequest($Request, [string]$ComputerName, [string]$MachineUuid,
                            [string]$CollectorHash, [DateTimeOffset]$Now) {
    $fields = @('schema_version','request_id','operation','hostname','machine_uuid','created_at',
                'expires_at','catalogue_id','collector_sha256')
    if ($null -eq $Request -or @(Compare-Object @($Request.PSObject.Properties.Name | Sort-Object) ($fields | Sort-Object)).Count -ne 0) {
        throw 'Unexpected scan request fields'
    }
    foreach ($key in $fields | Where-Object { $_ -ne 'schema_version' }) {
        if ($Request.$key -isnot [string]) { throw 'Invalid scan field type' }
    }
    if ($Request.schema_version -isnot [int] -or $Request.schema_version -ne 1 -or
        $Request.request_id -cnotmatch '^[a-f0-9]{32}$' -or
        $Request.operation -cne 'collect_server2022_evidence' -or
        $Request.hostname -cnotmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,62}$' -or
        $Request.hostname -ine $ComputerName -or $Request.machine_uuid -ine $MachineUuid -or
        $Request.catalogue_id -cne 'cis-server2022-standalone-2.0.0-full1' -or
        $Request.collector_sha256 -cnotmatch '^[a-f0-9]{64}$' -or $Request.collector_sha256 -cne $CollectorHash) {
        throw 'Unsupported scan request or target'
    }
    foreach ($value in @($Request.created_at, $Request.expires_at)) {
        if ($value -notmatch '(Z|[+-]\d{2}:\d{2})$') { throw 'Timezone required' }
    }
    $created = [DateTimeOffset]::Parse($Request.created_at)
    $expires = [DateTimeOffset]::Parse($Request.expires_at)
    if ($created -gt $Now -or $expires -le $Now -or $expires -le $created -or
        ($expires - $created).TotalMinutes -gt 10) { throw 'Expired scan request or clock mismatch' }
}

function Invoke-ReadOnlyScanJob($Request, [string]$RequestHash, [string]$ComputerName,
    [string]$MachineUuid, [string]$CollectorHash, [DateTimeOffset]$Now,
    [scriptblock]$Claim, [scriptblock]$Collect) {
    Assert-ScanRequest $Request $ComputerName $MachineUuid $CollectorHash $Now
    if ($RequestHash -cnotmatch '^[a-f0-9]{64}$') { throw 'Invalid request digest' }
    & $Claim # Exclusive durable claim before collection; never replay on interruption.
    $evidence = $null; $failure = $null; $status = 'collected'
    try {
        [byte[]]$bytes = & $Collect
        if ($null -eq $bytes -or $bytes.Length -eq 0 -or $bytes.Length -gt 65536) { throw 'collection_failed' }
        $evidence = [Convert]::ToBase64String($bytes)
    } catch {
        $status = 'collection_failed'
        $failure = if ($_.Exception.Message -eq 'timeout') { 'timeout' } else { 'collection_failed' }
    }
    return [ordered]@{schema_version=1; request_id=$Request.request_id; request_sha256=$RequestHash;
        status=$status; evidence=$evidence; error=$failure}
}

function New-ScanWorkerReport([string]$ComputerName, [string]$MachineUuid, [string]$CollectorHash,
    [ValidateSet('ready','busy','stopped')][string]$State, [string]$InstanceId, [DateTimeOffset]$Now) {
    $seconds = if ($State -eq 'busy') { 150 } else { 15 }
    return [ordered]@{schema_version=1; hostname=$ComputerName; machine_uuid=$MachineUuid;
        collector_sha256=$CollectorHash; state=$State; worker_instance_id=$InstanceId;
        reported_at=$Now.ToString('o'); valid_until=$Now.AddSeconds($seconds).ToString('o')}
}

if ($FunctionsOnly) { return }
$collectorPath = Join-Path $PSScriptRoot 'Collect-Server2022Evidence.ps1'
if ($ExpectedCollectorSha256 -cnotmatch '^[a-f0-9]{64}$' -or
    (Get-ScanHash ([IO.File]::ReadAllBytes($collectorPath))) -cne $ExpectedCollectorSha256) {
    throw 'Collector must match the independently supplied dashboard SHA-256.'
}
if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit Windows PowerShell in the VM.' }
. $collectorPath -FunctionsOnly -ExpectedComputerName $ExpectedComputerName
$os = Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 15
$computer = Get-CimInstance Win32_ComputerSystem -OperationTimeoutSec 15
Assert-LabTarget $os $computer $ExpectedComputerName
$actualUuid = ([guid](Get-CimInstance Win32_ComputerSystemProduct -OperationTimeoutSec 15).UUID).ToString()
if ([string]::IsNullOrWhiteSpace($ExpectedMachineUuid) -or $actualUuid -ine $ExpectedMachineUuid -or
    $actualUuid -in @('00000000-0000-0000-0000-000000000000','ffffffff-ffff-ffff-ffff-ffffffffffff')) {
    throw 'The independently selected VM UUID must match.'
}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run as administrator inside the VM.' }
if ([string]::IsNullOrWhiteSpace($ExchangeDirectory) -or -not [IO.Path]::IsPathRooted($ExchangeDirectory)) {
    throw 'Supply the absolute shared scan_queue directory inside the VM.'
}
$queue = [IO.Path]::GetFullPath($ExchangeDirectory)
if (-not [IO.Directory]::Exists($queue)) { throw 'Shared queue directory must already exist.' }
$deadline = [DateTimeOffset]::UtcNow.AddSeconds($WatchSeconds)
$processed = 0
$workerInstance = [guid]::NewGuid().ToString('N')
$statusPath = Join-Path $queue ('worker-' + $actualUuid + '.json')
function Publish-WorkerState([string]$State) {
    $report = New-ScanWorkerReport $ExpectedComputerName $actualUuid $ExpectedCollectorSha256 $State $workerInstance ([DateTimeOffset]::UtcNow)
    $partialStatus = Join-Path $queue ($workerInstance + '.status-partial')
    [IO.File]::WriteAllText($partialStatus, ($report | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $partialStatus -Destination $statusPath -Force
}
Write-Host 'Read-only scan worker active. Stop with Ctrl+C. No security changes are permitted.'
try {
while ([DateTimeOffset]::UtcNow -lt $deadline -and $processed -lt $MaxRequests) {
    Publish-WorkerState 'ready'
    foreach ($file in Get-ChildItem -LiteralPath $queue -Filter '*-request.json' -File) {
        if ($processed -ge $MaxRequests -or [DateTimeOffset]::UtcNow -ge $deadline) { break }
        if ($file.Name -cnotmatch '^([a-f0-9]{32})-request\.json$' -or $file.Length -gt 8192) { continue }
        $id = $Matches[1]
        $claimPath = Join-Path $queue ($id + '.claimed')
        $responsePath = Join-Path $queue ($id + '-response.json')
        if ([IO.File]::Exists($claimPath) -or [IO.File]::Exists($responsePath)) { continue }
        try {
            $raw = [IO.File]::ReadAllBytes($file.FullName)
            if ($raw.Length -gt 8192) { continue }
            $request = [Text.Encoding]::UTF8.GetString($raw) | ConvertFrom-Json
            if ($request.request_id -cne $id) { continue }
            Assert-ScanRequest $request $ExpectedComputerName $actualUuid $ExpectedCollectorSha256 ([DateTimeOffset]::UtcNow)
        } catch { continue } # Partial publication, foreign target, or invalid job never claims/collects.
        $claim = {
            $stream = [IO.File]::Open($claimPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
            $stream.Dispose()
        }
        $collect = {
            Publish-WorkerState 'busy'
            if ((Get-ScanHash ([IO.File]::ReadAllBytes($collectorPath))) -cne $ExpectedCollectorSha256) { throw 'collection_failed' }
            $folder = Join-Path ([IO.Path]::GetTempPath()) ('cis-scan-' + [guid]::NewGuid().ToString('N'))
            [void][IO.Directory]::CreateDirectory($folder)
            $output = Join-Path $folder 'evidence.json'
            $process = $null
            try {
                $arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $collectorPath +
                    '" -ExpectedComputerName "' + $ExpectedComputerName + '" -OutputPath "' + $output + '" -Quiet'
                $process = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList $arguments -PassThru -WindowStyle Hidden
                $null = $process.Handle
                if (-not $process.WaitForExit(120000)) { $process.Kill(); $process.WaitForExit(); throw 'timeout' }
                $process.Refresh()
                if ($process.ExitCode -ne 0 -or -not [IO.File]::Exists($output)) { throw 'collection_failed' }
                return ,([IO.File]::ReadAllBytes($output))
            } finally {
                if ($null -ne $process) { $process.Dispose() }
                if ([IO.File]::Exists($output)) { [IO.File]::Delete($output) }
                if ([IO.Directory]::GetFileSystemEntries($folder).Length -eq 0) { [IO.Directory]::Delete($folder, $false) }
            }
        }
        try {
            $response = Invoke-ReadOnlyScanJob $request (Get-ScanHash $raw) $ExpectedComputerName $actualUuid `
                $ExpectedCollectorSha256 ([DateTimeOffset]::UtcNow) $claim $collect
            $partial = Join-Path $queue ($id + '-' + [guid]::NewGuid().ToString('N') + '.partial')
            [IO.File]::WriteAllText($partial, ($response | ConvertTo-Json -Depth 4), [Text.UTF8Encoding]::new($false))
            [IO.File]::Move($partial, $responsePath) # No replacement; host sees only a complete response.
            $processed++
            Write-Host ('Scan response ready: ' + $id + ' / ' + $response.status)
        } catch { Write-Warning ('Scan job interrupted or already claimed: ' + $id) }
        Publish-WorkerState 'ready'
    }
    Start-Sleep -Seconds 2
}
} finally {
    Publish-WorkerState 'stopped'
}
Write-Host ('Read-only worker stopped. Completed requests: ' + $processed)
