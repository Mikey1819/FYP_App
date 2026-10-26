# Pure helper tests only: no actual WMI, registry or secedit collection.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\Collect-Server2022Evidence.ps1" -FunctionsOnly
function Assert-Equal($Actual, $Expected) {
    if ($Actual -cne $Expected) { throw "Expected $Expected; received $Actual" }
}
function Assert-Rejected([scriptblock]$Action) {
    $rejected = $false
    try { & $Action } catch { $rejected = $true }
    if (-not $rejected) { throw 'Expected rejection' }
}
$os = [pscustomobject]@{ Caption='Microsoft Windows Server 2022 Standard Evaluation'; Version='10.0.20348';
    BuildNumber='20348'; OSArchitecture='64-bit'; ProductType=3 }
$computer = [pscustomobject]@{ Name='FIXTURE-SERVER'; PartOfDomain=$false; DomainRole=2 }
Assert-LabTarget $os $computer 'FIXTURE-SERVER'
Assert-Rejected { Assert-LabTarget $os $computer 'OTHER' }
$os.ProductType = 1
Assert-Rejected { Assert-LabTarget $os $computer 'FIXTURE-SERVER' }
$os.ProductType = 3
$computer.PartOfDomain = $true
Assert-Rejected { Assert-LabTarget $os $computer 'FIXTURE-SERVER' }
$computer.PartOfDomain = $false
$computer.DomainRole = 3
Assert-Rejected { Assert-LabTarget $os $computer 'FIXTURE-SERVER' }
$computer.DomainRole = 2
Assert-Equal (Read-PolicyInteger @('[System Access]', 'MinimumPasswordLength = 14', 'LockoutBadCount = 0') 'MinimumPasswordLength') 14
Assert-Equal (Read-PolicyInteger @('[System Access]', 'LockoutBadCount = 0') 'LockoutBadCount') 0
Assert-Equal (Read-PolicyInteger @('[Other]', 'LockoutBadCount = 5') 'LockoutBadCount') $null
Assert-Rejected { Read-PolicyInteger @('[System Access]', 'LockoutBadCount=1', 'LockoutBadCount=5') 'LockoutBadCount' }
Assert-Rejected { Read-PolicyInteger @('[System Access]', 'LockoutBadCount=-1') 'LockoutBadCount' }
Assert-Rejected { Read-PolicyInteger @('[System Access]', 'LockoutBadCount=word') 'LockoutBadCount' }
$zero = New-Observation 'fixture' 'fixture' { 0 }
Assert-Equal $zero.state 'ok'; Assert-Equal $zero.value 0
$disabled = New-Observation 'fixture' 'fixture' { $false }
Assert-Equal $disabled.state 'ok'; Assert-Equal $disabled.value $false
$missing = New-Observation 'fixture' 'fixture' { $null }
Assert-Equal $missing.state 'missing'; Assert-Equal $missing.value $null
$failed = New-Observation 'fixture' 'fixture' { throw 'secret exception detail' }
Assert-Equal $failed.state 'error'; Assert-Equal $failed.error 'collection_failed'
$timeout = New-Observation 'fixture' 'fixture' { throw 'timeout' }
Assert-Equal $timeout.error 'timeout'
$expanded = @(Get-AccountPolicyObservations -Lines @('[System Access]',
    'MaximumPasswordAge=-1', 'LockoutDuration=-1', 'PasswordHistorySize=24',
    'PasswordComplexity=1', 'PasswordComplexity=0', 'MinimumPasswordAge=-1'))
Assert-Equal $expanded.Count 9
Assert-Equal ($expanded | Where-Object control_id -eq '1.1.2').value -1
Assert-Equal ($expanded | Where-Object control_id -eq '1.2.1').value -1
Assert-Equal ($expanded | Where-Object control_id -eq '1.1.1').value 24
Assert-Equal ($expanded | Where-Object control_id -eq '1.1.5').error 'invalid_value'
Assert-Equal ($expanded | Where-Object control_id -eq '1.1.3').error 'invalid_value'
Assert-Equal ($expanded | Where-Object control_id -eq '1.2.4').state 'missing'
$exportFailed = @(Get-AccountPolicyObservations -Lines @() -PolicyError 'timeout')
Assert-Equal $exportFailed.Count 9
foreach ($row in $exportFailed) { Assert-Equal $row.state 'error'; Assert-Equal $row.error 'timeout' }
# auditpol /backup rows: GUID with braces, numeric Setting Value (locale-independent).
$auditRows = @(
    [pscustomobject]@{ 'Subcategory GUID' = '{0CCE923F-69AE-11D9-BED3-505054503030}'; 'Setting Value' = '1' },
    [pscustomobject]@{ 'Subcategory GUID' = '{0cce9215-69ae-11d9-bed3-505054503030}'; 'Setting Value' = '3' },
    [pscustomobject]@{ 'Subcategory GUID' = '{0cce9217-69ae-11d9-bed3-505054503030}'; 'Setting Value' = 'Failure' })
Assert-Equal (Read-AuditSetting $auditRows '0cce923f-69ae-11d9-bed3-505054503030') 1
Assert-Equal (Read-AuditSetting $auditRows '0cce9215-69ae-11d9-bed3-505054503030') 3
Assert-Equal (Read-AuditSetting $auditRows '0cce9235-69ae-11d9-bed3-505054503030') $null
Assert-Rejected { Read-AuditSetting $auditRows '0cce9217-69ae-11d9-bed3-505054503030' }
$audit = @(Get-AuditObservations -Rows $auditRows)
Assert-Equal $audit.Count 5
Assert-Equal ($audit | Where-Object control_id -eq '17.1.1').value 1
Assert-Equal ($audit | Where-Object control_id -eq '17.5.4').value 3
Assert-Equal ($audit | Where-Object control_id -eq '17.5.1').error 'invalid_value'
Assert-Equal ($audit | Where-Object control_id -eq '17.2.3').state 'missing'
Assert-Equal ($audit | Where-Object control_id -eq '17.2.2').source 'auditpol-backup:{0cce9237-69ae-11d9-bed3-505054503030}/Setting Value'
$auditFailed = @(Get-AuditObservations -Rows @() -AuditError 'timeout')
foreach ($row in $auditFailed) { Assert-Equal $row.state 'error'; Assert-Equal $row.error 'timeout' }
Assert-Equal $PolicyDwords.Count 11
$tokens = $null; $parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile(
    "$PSScriptRoot\Collect-Server2022Evidence.ps1", [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw ($parseErrors | Out-String) }
Write-Output 'PASS: collector syntax, target rejection, policy and audit parsing, missing/error handling (fixtures only).'
