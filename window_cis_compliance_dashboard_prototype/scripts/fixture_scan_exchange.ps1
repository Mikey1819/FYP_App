# Fixture-only bridge. Never invokes the real collector or reads machine policy.
param([string]$RequestPath, [string]$EvidencePath, [string]$OutputPath, [switch]$Fail)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\Watch-ScanRequests.ps1" -FunctionsOnly
$raw = [IO.File]::ReadAllBytes($RequestPath)
$request = [Text.Encoding]::UTF8.GetString($raw) | ConvertFrom-Json
$claim = {
    $stream = [IO.File]::Open(($OutputPath + '.claimed'), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
    $stream.Dispose()
}
$collect = {
    if ($Fail) { throw 'timeout' }
    return ,([IO.File]::ReadAllBytes($EvidencePath))
}
$response = Invoke-ReadOnlyScanJob $request (Get-ScanHash $raw) 'FIXTURE-SERVER' `
    '2ca18359-73dc-49ef-9dd3-18602c0d9b55' (Get-ScanHash ([IO.File]::ReadAllBytes("$PSScriptRoot\Collect-Server2022Evidence.ps1"))) `
    ([DateTimeOffset]::Parse($request.created_at).AddSeconds(1)) $claim $collect
[IO.File]::WriteAllText($OutputPath, ($response | ConvertTo-Json -Depth 4), [Text.UTF8Encoding]::new($false))
