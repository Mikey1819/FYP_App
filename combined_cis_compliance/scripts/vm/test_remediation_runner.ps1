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
$fwLog = Assert-RemediationRequest (New-Request @{ control_id = '9.3.6'; action_id = 'REM-9.3.6'; value = 1; expected_before = $null }) 'WIN-LAB' 'e5d10741-f200-4292-a099-e6be76032f4e' $now
if ($fwLog.kind -ne 'reg_dword' -or $fwLog.key -ne 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging' -or $fwLog.name -ne 'LogDroppedPackets') { throw 'Firewall logging action resolved incorrectly.' }
Assert-Refused @{ control_id = '9.3.6'; action_id = 'REM-9.3.6'; value = 0; expected_before = $null } 'firewall logging value differs from library'
# Channel safety: no action may write firewall on/off or inbound-block policy; firewall actions write only under Logging.
foreach ($id in $Library.Keys) {
    $entry = $Library[$id]
    if ($entry.control_id -in @('9.2.1', '9.2.2', '9.3.1', '9.3.2')) { throw "$id would change which traffic the firewall allows." }
    if ($entry.ContainsKey('key') -and $entry.key -like 'SOFTWARE\Policies\Microsoft\WindowsFirewall*' -and $entry.key -notlike '*\Logging') {
        throw "$id writes firewall policy outside Logging."
    }
}
Assert-Refused @{ expected_before = $null } 'not-configured precondition for a net accounts action'
# secedit actions: the table resolves each to its one policy line, and a "Not configured" precondition is refused.
foreach ($case in @(@('1.1.5', 'REM-1.1.5', 1, 0, 'PasswordComplexity'), @('1.1.7', 'REM-1.1.7', 0, 1, 'ClearTextPassword'),
                    @('2.3.10.1', 'REM-2.3.10.1', 0, 1, 'LSAAnonymousNameLookup'))) {
    $sec = Assert-RemediationRequest (New-Request @{ control_id = $case[0]; action_id = $case[1]; value = $case[2]; expected_before = $case[3] }) 'WIN-LAB' 'e5d10741-f200-4292-a099-e6be76032f4e' $now
    if ($sec.kind -ne 'secedit' -or $sec.setting -cne $case[4]) { throw "$($case[1]) resolved incorrectly." }
    Assert-Refused @{ control_id = $case[0]; action_id = $case[1]; value = $case[2]; expected_before = $null } "$($case[1]) not-configured precondition"
    Assert-Refused @{ control_id = $case[0]; action_id = $case[1]; value = $case[3]; expected_before = $case[3] } "$($case[1]) value differs from library"
}
# The template holds exactly one setting line, so secedit has nothing else to apply.
$template = @(New-OneSettingTemplate 'PasswordComplexity' 1)
$settingLines = @(Get-SystemAccessLines $template)
if ($settingLines.Count -ne 1 -or $settingLines[0] -cne 'PasswordComplexity = 1') { throw 'Template must hold only the one setting.' }
if ($template[0] -cne '[Unicode]' -or $template -notcontains 'signature="$CHICAGO$"') { throw 'Template header is malformed.' }
# Reading an export: only [System Access] lines count, and every line other than the setting is compared.
$export = @('[Unicode]', 'Unicode=yes', '[System Access]', 'MinimumPasswordAge = 0', 'PasswordComplexity = 0',
            'ClearTextPassword = 0', '', '[Event Audit]', 'AuditLogonEvents = 0', '[Version]', 'signature="$CHICAGO$"')
$access = @(Get-SystemAccessLines $export)
if ($access.Count -ne 3) { throw 'Only [System Access] lines must be read.' }
if ((Get-SettingValue $access 'PasswordComplexity') -cne '0') { throw 'Setting value read incorrectly.' }
if ($null -ne (Get-SettingValue $access 'LSAAnonymousNameLookup')) { throw 'An absent setting must read as null.' }
$changed = @($access | ForEach-Object { $_ -replace '^PasswordComplexity = 0$', 'PasswordComplexity = 1' })
if ((Get-OtherSettings $access 'PasswordComplexity') -cne (Get-OtherSettings $changed 'PasswordComplexity')) { throw 'Changing only the setting must leave the others equal.' }
$alsoOther = @($changed | ForEach-Object { $_ -replace '^MinimumPasswordAge = 0$', 'MinimumPasswordAge = 3' })
if ((Get-OtherSettings $access 'PasswordComplexity') -ceq (Get-OtherSettings $alsoOther 'PasswordComplexity')) { throw 'A second changed setting must be detected.' }
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
# Every control character (NUL to 0x1F, not just line breaks) becomes one space.
$controls = 'Access' + [char]0 + [char]31 + 'denied' + [char]9 + 'end'
if ((Get-FailureText $controls) -cne 'Access denied end') { throw 'Control characters must not reach the agent or the page.' }
Write-Host 'PASS: remediation runner library, identity, value, type, expiry and extra-field guards (fixtures only).'
