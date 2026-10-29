# Parser tests for Get-CrossCheckValues.ps1 with fixture text only; reads nothing from this computer.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\Get-CrossCheckValues.ps1" -FunctionsOnly
function Assert-Pair($Actual, $Value, $Raw) {
    if ($Actual.Count -ne 2 -or $Actual[0] -cne $Value -or $Actual[1] -cne $Raw) {
        throw "Expected ($Value, $Raw); received ($($Actual -join ', '))"
    }
}
$net = @('Force user logoff how long after time expires?:       Never', 'Minimum password age (days):                          0',
    'Maximum password age (days):                          Unlimited', 'Minimum password length:                              14',
    'Length of password history maintained:                None', 'Lockout threshold:                                    Never',
    'Lockout duration (minutes):                           30', 'Lockout observation window (minutes):                 30',
    'Computer role:                                        SERVER', 'The command completed successfully.')
Assert-Pair (Read-NetAccounts $net '1.1.4') 14 '14'
Assert-Pair (Read-NetAccounts $net '1.1.1') 0 'None'
Assert-Pair (Read-NetAccounts $net '1.1.2') -1 'Unlimited'
Assert-Pair (Read-NetAccounts $net '1.2.2') 0 'Never'
Assert-Pair (Read-NetAccounts $net '1.1.3') 0 '0'
Assert-Pair (Read-NetAccounts @('Lockout duration (minutes):   Never') '1.2.1') $null 'Never'
Assert-Pair (Read-NetAccounts @() '1.2.4') $null 'label not found'
$reg = @('', 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile',
    '    EnableFirewall    REG_DWORD    0x1', '    EnableFirewallX    REG_DWORD    0x0', '')
Assert-Pair (Read-RegQuery $reg 'EnableFirewall') ([uint32]1) '0x1'
Assert-Pair (Read-RegQuery @('    MinEncryptionLevel    REG_DWORD    0xffffffff') 'MinEncryptionLevel') ([uint32]::MaxValue) '0xffffffff'
Assert-Pair (Read-RegQuery @() 'EnableFirewall') $null 'not configured'
Assert-Pair (Read-RegQuery @('    SecurityLayer    REG_SZ    2') 'SecurityLayer') $null 'REG_SZ 2'
$header = 'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting'
Assert-Pair (Read-AuditGet @($header, 'SRV,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,', '')) 3 'Success and Failure'
Assert-Pair (Read-AuditGet @($header, 'SRV,System,Account Lockout,{0CCE9217-69AE-11D9-BED3-505054503030},No Auditing,')) 0 'No Auditing'
Assert-Pair (Read-AuditGet @($header)) $null 'subcategory not found'
Assert-Pair (Read-SeceditValue @('[System Access]', 'PasswordComplexity = 1', 'ClearTextPassword = 0') 'ClearTextPassword') 0 '0'
Assert-Pair (Read-SeceditValue @('[System Access]') 'LSAAnonymousNameLookup') $null 'not in export'
Write-Output 'PASS: cross-check parsers for net accounts, reg query, auditpol /get and secedit (fixtures only).'
