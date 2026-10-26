# Loads functions only. All collection/execution callbacks are fixtures; no host security calls.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\Invoke-ApprovedVmAction.ps1" -FunctionsOnly
function Assert-True($Value, $Message) { if (-not $Value) { throw $Message } }
function Assert-Reject([scriptblock]$Action) {
    $caught = $false
    try { & $Action | Out-Null } catch { $caught = $true }
    Assert-True $caught 'Expected refusal'
}
$script:writes = 0; $script:claims = 0; $script:reads = 0; $script:observed = 0
$request = [pscustomobject]@{
    schema_version=1; request_id=('a' * 32); evidence_sha256=('b' * 64)
    hostname='FIXTURE'; machine_uuid='2ca18359-73dc-49ef-9dd3-18602c0d9b55'
    control_id='1.1.4'; action_id='SET-MINIMUM-PASSWORD-LENGTH-14'
    parameters=[pscustomobject]@{minimum_length=14}; expected_before=0; approved_by='fixture'
    approved_at=[DateTimeOffset]::UtcNow.AddMinutes(-1).ToString('o')
    expires_at=[DateTimeOffset]::UtcNow.AddHours(1).ToString('o')
}
Assert-ApprovedRequest $request 'FIXTURE' $request.machine_uuid ([DateTimeOffset]::UtcNow)
Assert-Reject { Assert-ApprovedRequest $request 'LAPTOP' $request.machine_uuid ([DateTimeOffset]::UtcNow) }
Assert-Reject { Assert-ApprovedRequest $request 'FIXTURE' 'OTHER' ([DateTimeOffset]::UtcNow) }
Assert-Reject { Assert-ApprovedRequest $request 'FIXTURE' $request.machine_uuid ([DateTimeOffset]::UtcNow.AddDays(2)) }
$request.parameters.minimum_length = 1
Assert-Reject { Assert-ApprovedRequest $request 'FIXTURE' $request.machine_uuid ([DateTimeOffset]::UtcNow) }
$request.parameters.minimum_length = 14
$collect = {
    $script:reads++
    $doc = @{target=@{hostname='FIXTURE'; machine_uuid=$request.machine_uuid};
        observations=@(@{control_id='1.1.4'; state='ok'; value=$script:observed;
            source='secedit-export:System Access/MinimumPasswordLength'})}
    return ,([Text.Encoding]::UTF8.GetBytes(($doc | ConvertTo-Json -Depth 5)))
}
$mark = { if ($script:claims -gt 0) { throw 'already attempted' }; $script:claims++ }
$apply = { $script:writes++; $script:observed=14 }
$result = Invoke-GuardedAction $request ('c' * 64) $collect $mark $apply
Assert-True ($script:writes -eq 1 -and $script:reads -eq 2 -and $result.status -eq 'applied') 'Expected apply and readback'
Assert-True ((Get-RunnerSummary $result) -like '*minimum password length is 14*') 'Missing successful read-back'
Assert-True ((Resolve-VmPath '' 'D:\Server Lab') -eq 'D:\Server Lab') 'Output default is not script directory'
Assert-True ((Resolve-VmPath 'request.json' 'D:\Server Lab') -eq 'D:\Server Lab\request.json') 'Relative request not anchored'
Assert-True ((Resolve-VmPath 'E:\Other\request.json' 'D:\Server Lab') -eq 'E:\Other\request.json') 'Absolute request altered'
Assert-Reject { Resolve-VmPath 'C:relative.json' 'D:\Server Lab' }
Assert-Reject { Resolve-VmPath '\relative.json' 'D:\Server Lab' }
# Precondition changed -> zero additional writes; same observation + consumed claim -> zero additional writes.
Assert-Reject { Invoke-GuardedAction $request ('c' * 64) $collect $mark $apply }
$script:observed=0
Assert-Reject { Invoke-GuardedAction $request ('c' * 64) $collect $mark $apply }
Assert-True ($script:writes -eq 1) 'Replay wrote again'
$script:claims=0
$result = Invoke-GuardedAction $request ('c' * 64) $collect $mark { $script:writes++; throw 'fixture failure' }
Assert-True ($result.status -eq 'execution_failed' -and $script:writes -eq 2) 'Failure was retried or misreported'
Assert-True ((Get-RunnerSummary $result) -like '*failed or timed out*') 'Failure summary incorrect'
$script:claims=0; $script:reads=0
$fixtureCollect = $collect
$badAfter = { if ($script:reads -gt 0) { throw 'fixture collection failure' }; & $fixtureCollect }
$result = Invoke-GuardedAction $request ('c' * 64) $badAfter $mark { $script:writes++ }
Assert-True ($result.status -eq 'verification_unavailable' -and $script:writes -eq 3) 'Verification failure retried'
Assert-True ((Get-RunnerSummary $result) -like '*verification evidence is unavailable*') 'Missing evidence reported as pass'
$script:claims=0
$result = Invoke-GuardedAction $request ('c' * 64) $collect $mark { }
Assert-True ((Get-RunnerSummary $result) -like '*check FAILED*') 'Unchanged setting reported as verified'
$tokens=$null; $errors=$null
[void][System.Management.Automation.Language.Parser]::ParseFile("$PSScriptRoot\Invoke-ApprovedVmAction.ps1", [ref]$tokens, [ref]$errors)
Assert-True ($errors.Count -eq 0) 'Runner syntax error'
Write-Output 'PASS: VM runner fixtures: identity, expiry, action constraints, precondition drift, replay, execution/verification failure; no host commands.'
