# Fixture-only checks of the remediation runner's request guards. Never touches machine settings.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\Invoke-RemediationAction.ps1" -FunctionsOnly

$now = [DateTimeOffset]::Parse('2026-10-26T05:00:00+00:00')
function New-Request([hashtable]$Overrides) {
    $request = [ordered]@{
        schema_version = 2; request_id = ('a' * 32); evidence_sha256 = ('b' * 64)
        hostname = 'WIN-LAB'; machine_uuid = 'e5d10741-f200-4292-a099-e6be76032f4e'
        control_id = '1.2.2'; action_id = 'REM-1.2.2'; value = 5; expected_before = 0
        approved_by = 'admin01'; approved_at = '2026-10-26T04:50:00+00:00'; expires_at = '2026-10-26T05:50:00+00:00'
    }
    foreach ($key in $Overrides.Keys) { $request[$key] = $Overrides[$key] }
    return ($request | ConvertTo-Json -Compress) | ConvertFrom-Json
}
function Assert-Refused([hashtable]$Overrides, [string]$Label) {
    try { $null = Assert-RemediationRequest (New-Request $Overrides) 'WIN-LAB' 'e5d10741-f200-4292-a099-e6be76032f4e' $now }
    catch { return }
    throw "Guard accepted an invalid request: $Label"
}

$entry = Assert-RemediationRequest (New-Request @{}) 'WIN-LAB' 'e5d10741-f200-4292-a099-e6be76032f4e' $now
if ($entry.option -ne '/lockoutthreshold') { throw 'Valid request resolved to the wrong implementation.' }
Assert-Refused @{ action_id = 'REM-ARBITRARY' } 'unknown action'
Assert-Refused @{ value = 0 } 'value differs from the library'
Assert-Refused @{ value = '5' } 'string value'
Assert-Refused @{ control_id = '1.1.4' } 'control mismatch'
Assert-Refused @{ hostname = 'OTHER' } 'wrong host'
Assert-Refused @{ machine_uuid = '11111111-2222-3333-4444-555555555555' } 'wrong UUID'
Assert-Refused @{ expected_before = $false } 'boolean precondition for an integer setting'
Assert-Refused @{ schema_version = 1 } 'legacy schema'
Assert-Refused @{ expires_at = '2026-10-26T04:55:00+00:00' } 'expired approval'
Assert-Refused @{ expires_at = '2026-10-26T08:00:00+00:00' } 'approval longer than two hours'
Assert-Refused @{ approved_by = ' ' } 'missing approver'
Assert-Refused @{ command = 'net user x /add' } 'extra command field'
$guest = Assert-RemediationRequest (New-Request @{ control_id = '2.3.1.1'; action_id = 'REM-2.3.1.1'; value = $false; expected_before = $true }) 'WIN-LAB' 'e5d10741-f200-4292-a099-e6be76032f4e' $now
if ($guest.kind -ne 'disable_guest') { throw 'Guest action resolved incorrectly.' }
$auditEntry = Assert-RemediationRequest (New-Request @{ control_id = '17.5.1'; action_id = 'REM-17.5.1'; value = 2; expected_before = 1 }) 'WIN-LAB' 'e5d10741-f200-4292-a099-e6be76032f4e' $now
if ($auditEntry.kind -ne 'audit_flags' -or $auditEntry.guid -ne '0cce9217-69ae-11d9-bed3-505054503030') { throw 'Audit action resolved incorrectly.' }
$rdpEntry = Assert-RemediationRequest (New-Request @{ control_id = '18.10.57.3.9.3'; action_id = 'REM-18.10.57.3.9.3'; value = 2; expected_before = 1 }) 'WIN-LAB' 'e5d10741-f200-4292-a099-e6be76032f4e' $now
if ($rdpEntry.key -ne 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -or $rdpEntry.name -ne 'SecurityLayer') { throw 'RDP action resolved incorrectly.' }
Assert-Refused @{ control_id = '17.5.1'; action_id = 'REM-17.5.1'; value = 3; expected_before = 1 } 'audit value differs from library'
$nla = Assert-RemediationRequest (New-Request @{ control_id = '18.10.57.3.9.4'; action_id = 'REM-18.10.57.3.9.4'; value = 1; expected_before = $null }) 'WIN-LAB' 'e5d10741-f200-4292-a099-e6be76032f4e' $now
if ($nla.name -ne 'UserAuthentication') { throw 'Not-configured NLA policy request resolved incorrectly.' }
Assert-Refused @{ expected_before = $null } 'not-configured precondition for a net accounts action'
$missing = [pscustomobject]@{ observations = @([pscustomobject]@{ control_id = '18.10.57.3.9.4'; state = 'missing'; value = $null }) }
$setTo0 = [pscustomobject]@{ observations = @([pscustomobject]@{ control_id = '18.10.57.3.9.4'; state = 'ok'; value = 0 }) }
if (-not (Test-Precondition $missing '18.10.57.3.9.4' $null)) { throw 'Still not configured must satisfy a null precondition.' }
if (Test-Precondition $setTo0 '18.10.57.3.9.4' $null) { throw 'A policy set since approval must fail a null precondition.' }
if (Test-SameTypedValue 0 $false) { throw '0 must not equal $false.' }
if (-not (Test-SameTypedValue 5 5)) { throw 'Equal integers must match.' }
if (Test-SameTypedValue 5.0 5) { throw 'Floating-point values must not match integer settings.' }
if ((Get-FailureText "Requested registry access`r`nis not allowed.") -cne 'Requested registry access is not allowed.') { throw 'Failure text must be one line.' }
if ((Get-FailureText ('x' * 300)).Length -ne 200) { throw 'Failure text must be bounded.' }
if ((Get-FailureText '  ') -cne 'no detail') { throw 'An empty failure needs a placeholder.' }
Write-Host 'PASS: remediation runner library, identity, value, type, expiry and extra-field guards (fixtures only).'
