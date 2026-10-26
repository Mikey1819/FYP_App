# TEST ADAPTER ONLY: reads fixture files, calls injected callbacks, writes a fixture receipt.
# Does not load the runtime collector, query this machine or invoke any security command.
param([string]$FixtureRequestPath, [string]$BeforePath, [string]$AfterPath, [string]$ReceiptPath)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\Invoke-ApprovedVmAction.ps1" -FunctionsOnly
$fixtureRequestBytes = [IO.File]::ReadAllBytes($FixtureRequestPath)
$fixtureRequest = [Text.Encoding]::UTF8.GetString($fixtureRequestBytes) | ConvertFrom-Json
Assert-ApprovedRequest $fixtureRequest 'FIXTURE-SERVER' '2ca18359-73dc-49ef-9dd3-18602c0d9b55' `
    ([DateTimeOffset]::Parse($fixtureRequest.approved_at).AddMinutes(5))
$fixtureHasher = [Security.Cryptography.SHA256]::Create()
try { $fixtureHash = ([BitConverter]::ToString($fixtureHasher.ComputeHash($fixtureRequestBytes))).Replace('-','').ToLowerInvariant() }
finally { $fixtureHasher.Dispose() }
$script:fixtureReadCount=0; $script:fixtureWrites=0; $script:fixtureClaims=0
$fixtureReader = {
    $pathToRead = if ($script:fixtureReadCount -eq 0) { $BeforePath } else { $AfterPath }
    $script:fixtureReadCount++
    return ,([IO.File]::ReadAllBytes($pathToRead))
}
$fixtureClaim = { $script:fixtureClaims++ }
$fixtureWrite = { $script:fixtureWrites++ } # Counter only. Never execute net/secedit/registry operations.
$fixtureReceipt = Invoke-GuardedAction $fixtureRequest $fixtureHash $fixtureReader $fixtureClaim $fixtureWrite
if ($script:fixtureWrites -ne 1 -or $script:fixtureClaims -ne 1 -or $script:fixtureReadCount -ne 2) {
    throw 'Unexpected fixture callback counts'
}
$fixtureReceipt | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ReceiptPath -Encoding UTF8
Write-Host (Get-RunnerSummary $fixtureReceipt)
