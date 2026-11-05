<#
Sent to the lab VM over WinRM by scripts/tools/cross_check_controls.py; runs there as Administrator. Read-only.
An independent cross-check of the 32 assessed controls for the compliance-accuracy evaluation:
it reads each value with a different tool from the collector (net accounts instead of the secedit
export, Get-LocalUser instead of Win32_UserAccount, reg.exe instead of the .NET registry API,
auditpol /get instead of auditpol /backup). Three values exist only in the security policy
database, so they are read from a secedit export like the collector; confirm those in secpol.msc.
It returns the values as JSON, and cross_check_controls.py compares them with the dashboard's stored scan.
FunctionsOnly loads the parsers for fixture tests without inspecting this computer.
#>
[CmdletBinding()]
param(
    [switch]$FunctionsOnly
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$NetAccounts = [ordered]@{
    '1.1.1' = 'Length of password history maintained'; '1.1.2' = 'Maximum password age (days)'
    '1.1.3' = 'Minimum password age (days)'; '1.1.4' = 'Minimum password length'
    '1.2.1' = 'Lockout duration (minutes)'; '1.2.2' = 'Lockout threshold'
    '1.2.4' = 'Lockout observation window (minutes)'
}
# Words net accounts prints instead of a number, as the collector's secedit value. Any other word is
# left unparsed (shown raw) rather than guessed.
$NetWords = @{ '1.1.1' = @{ 'None' = 0 }; '1.1.2' = @{ 'Unlimited' = -1 }; '1.2.2' = @{ 'Never' = 0 } }
$SeceditOnly = [ordered]@{ '1.1.5' = 'PasswordComplexity'; '1.1.7' = 'ClearTextPassword'; '2.3.10.1' = 'LSAAnonymousNameLookup' }
$Fw = 'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall'
$Ts = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$Lsa = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
$Registry = [ordered]@{
    '2.3.1.2' = @($Lsa, 'LimitBlankPasswordUse'); '2.3.10.2' = @($Lsa, 'RestrictAnonymousSAM')
    '2.3.10.3' = @($Lsa, 'RestrictAnonymous')
    '9.2.1' = @("$Fw\PrivateProfile", 'EnableFirewall'); '9.2.2' = @("$Fw\PrivateProfile", 'DefaultInboundAction')
    '9.2.6' = @("$Fw\PrivateProfile\Logging", 'LogDroppedPackets'); '9.2.7' = @("$Fw\PrivateProfile\Logging", 'LogSuccessfulConnections')
    '9.3.1' = @("$Fw\PublicProfile", 'EnableFirewall'); '9.3.2' = @("$Fw\PublicProfile", 'DefaultInboundAction')
    '9.3.6' = @("$Fw\PublicProfile\Logging", 'LogDroppedPackets'); '9.3.7' = @("$Fw\PublicProfile\Logging", 'LogSuccessfulConnections')
    '18.10.57.2.2' = @($Ts, 'DisablePasswordSaving'); '18.10.57.3.9.1' = @($Ts, 'fPromptForPassword')
    '18.10.57.3.9.3' = @($Ts, 'SecurityLayer'); '18.10.57.3.9.4' = @($Ts, 'UserAuthentication')
    '18.10.57.3.9.5' = @($Ts, 'MinEncryptionLevel')
}
$Audit = [ordered]@{
    '17.1.1' = '0cce923f-69ae-11d9-bed3-505054503030'; '17.2.2' = '0cce9237-69ae-11d9-bed3-505054503030'
    '17.2.3' = '0cce9235-69ae-11d9-bed3-505054503030'; '17.5.1' = '0cce9217-69ae-11d9-bed3-505054503030'
    '17.5.4' = '0cce9215-69ae-11d9-bed3-505054503030'
}
$AuditWords = @{ 'No Auditing' = 0; 'Success' = 1; 'Failure' = 2; 'Success and Failure' = 3 }

function New-Row([string]$Control, [string]$Method, $Value, [string]$Raw) {
    [pscustomobject]@{ control_id = $Control; value = $Value; raw = $Raw; method = $Method }
}

function Read-NetAccounts([string[]]$Lines, [string]$Control) {
    $label = $NetAccounts[$Control]
    $found = @($Lines | Where-Object { $_ -match ('^' + [regex]::Escape($label) + ':\s+(\S.*)$') } |
        ForEach-Object { $Matches[1].Trim() })
    if ($found.Count -ne 1) { return @($null, 'label not found') }
    if ($found[0] -match '^\d+$') { return @([int]$found[0], $found[0]) }
    $words = $NetWords[$Control]
    if ($null -ne $words -and $words.ContainsKey($found[0])) { return @($words[$found[0]], $found[0]) }
    return @($null, $found[0])
}

function Read-RegQuery([string[]]$Lines, [string]$Name) {
    # reg.exe prints "    Name    REG_DWORD    0x1"; a missing value is Not configured.
    foreach ($line in $Lines) {
        if ($line -match ('^\s+' + [regex]::Escape($Name) + '\s+(REG_\w+)\s+(\S+)\s*$')) {
            if ($Matches[1] -ne 'REG_DWORD') { return @($null, ($Matches[1] + ' ' + $Matches[2])) }
            return @([uint32]::Parse($Matches[2].Substring(2), 'HexNumber'), $Matches[2])
        }
    }
    return @($null, 'not configured')
}

function Read-AuditGet([string[]]$CsvLines) {
    $rows = @($CsvLines | Where-Object { $_.Trim() } | ConvertFrom-Csv)
    if ($rows.Count -ne 1) { return @($null, 'subcategory not found') }
    $setting = [string]$rows[0].'Inclusion Setting'
    if ($AuditWords.ContainsKey($setting)) { return @($AuditWords[$setting], $setting) }
    return @($null, $setting)
}

function Read-SeceditValue([string[]]$Lines, [string]$Key) {
    $found = @($Lines | Where-Object { $_.Trim() -match ('^' + [regex]::Escape($Key) + '\s*=\s*(-?\d+)$') } |
        ForEach-Object { $Matches[1] })
    if ($found.Count -ne 1) { return @($null, 'not in export') }
    return @([int]$found[0], $found[0])
}

if ($FunctionsOnly) { return }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open Windows PowerShell as Administrator inside the lab VM.'
}
$rows = @()
$net = @(& net.exe accounts)
foreach ($control in $NetAccounts.Keys) {
    $value, $raw = Read-NetAccounts $net $control
    $rows += New-Row $control ('net accounts: ' + $NetAccounts[$control]) $value $raw
}
$guest = @(Get-LocalUser | Where-Object { $_.SID.Value -match '-501$' })
$rows += New-Row '2.3.1.1' 'Get-LocalUser (RID 501): Enabled' $(if ($guest.Count -eq 1) { [bool]$guest[0].Enabled } else { $null }) `
    $(if ($guest.Count -eq 1) { $guest[0].Name + ' Enabled=' + $guest[0].Enabled } else { 'guest not found' })
$export = Join-Path ([IO.Path]::GetTempPath()) ('crosscheck-' + [guid]::NewGuid().ToString('N') + '.inf')
try {
    $null = & secedit.exe /export /cfg $export /areas SECURITYPOLICY /quiet
    $policy = @(Get-Content -LiteralPath $export)
} finally {
    if (Test-Path -LiteralPath $export) { Remove-Item -LiteralPath $export }
}
foreach ($control in $SeceditOnly.Keys) {
    $value, $raw = Read-SeceditValue $policy $SeceditOnly[$control]
    $rows += New-Row $control ('secedit export (same source as collector): ' + $SeceditOnly[$control]) $value $raw
}
foreach ($control in $Registry.Keys) {
    $key, $name = $Registry[$control]
    # reg.exe reports a missing value on stderr; that is Not configured, not a failure.
    $lines = @(& { $ErrorActionPreference = 'Continue'; & reg.exe query $key /v $name 2>$null })
    $value, $raw = Read-RegQuery $lines $name
    $rows += New-Row $control ('reg query: ' + $key + ' ' + $name) $value $raw
}
foreach ($control in $Audit.Keys) {
    $value, $raw = Read-AuditGet @(& auditpol.exe /get ('/subcategory:{' + $Audit[$control] + '}') /r)
    $rows += New-Row $control ('auditpol /get: {' + $Audit[$control] + '}') $value $raw
}

$report = [pscustomobject]@{
    hostname = $env:COMPUTERNAME; collected_at = [DateTimeOffset]::UtcNow.ToString('o'); rows = $rows
}
Write-Output ($report | ConvertTo-Json -Depth 4 -Compress)
