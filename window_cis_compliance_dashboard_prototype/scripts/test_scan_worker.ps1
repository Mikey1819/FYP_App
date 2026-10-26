# Pure helper tests. No CIM, registry, collector or security command is invoked.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\Watch-ScanRequests.ps1" -FunctionsOnly
$now = [DateTimeOffset]::Parse('2026-10-26T01:00:00Z')
$hash = 'a' * 64
$uuid = '2ca18359-73dc-49ef-9dd3-18602c0d9b55'
$request = [pscustomobject]@{schema_version=1; request_id=('b'*32); operation='collect_server2022_evidence';
    hostname='FIXTURE-SERVER'; machine_uuid=$uuid; created_at=$now.AddSeconds(-1).ToString('o');
    expires_at=$now.AddMinutes(9).ToString('o'); catalogue_id='cis-server2022-standalone-2.0.0-full1';
    collector_sha256=$hash}
$script:claims = 0; $script:collections = 0
$claim = { $script:claims++ }
$collect = { $script:collections++; return ,([byte[]]@(1,2,3)) }
$variants = @(
    @('schema_version', $true), @('operation', 'execute'), @('request_id', '../bad'),
    @('hostname','OTHER'), @('machine_uuid','00000000-0000-0000-0000-000000000000'),
    @('collector_sha256',('0'*64)), @('catalogue_id','demo-v1'),
    @('created_at',$now.AddSeconds(1).ToString('o')), @('expires_at',$now.ToString('o')),
    @('expires_at',$now.AddHours(1).ToString('o')), @('created_at','2026-10-26T00:59:59'),
    @('hostname',@('FIXTURE-SERVER'))
)
foreach ($pair in $variants) {
    $bad = ($request | ConvertTo-Json | ConvertFrom-Json)
    $bad.($pair[0]) = $pair[1]
    $rejected = $false
    try { Invoke-ReadOnlyScanJob $bad $hash 'FIXTURE-SERVER' $uuid $hash $now $claim $collect | Out-Null }
    catch { $rejected = $true }
    if (-not $rejected) { throw ('Expected rejection: ' + $pair[0]) }
}
if ($script:claims -ne 0 -or $script:collections -ne 0) { throw 'Invalid job reached collection' }
$result = Invoke-ReadOnlyScanJob $request $hash 'FIXTURE-SERVER' $uuid $hash $now $claim { throw 'timeout' }
if ($result.status -ne 'collection_failed' -or $result.error -ne 'timeout' -or $null -ne $result.evidence) {
    throw 'Collection failure was not preserved'
}
$rejected = $false
try { Invoke-ReadOnlyScanJob $request $hash 'FIXTURE-SERVER' $uuid $hash $now { throw 'already claimed' } $collect | Out-Null }
catch { $rejected = $true }
if (-not $rejected -or $script:collections -ne 0) { throw 'Duplicate job reached collector' }
Write-Output 'PASS: scan worker type/operation/target/hash/time guards, failed collection and duplicate claim (fixtures only).'
