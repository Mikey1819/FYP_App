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
$tokens = $null; $parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile(
    "$PSScriptRoot\Collect-Server2022Evidence.ps1", [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw ($parseErrors | Out-String) }
Write-Output 'PASS: collector syntax, target rejection, policy parsing, missing/error handling (fixtures only).'
