<#
Run ONLY inside the selected standalone Server 2022 lab VM.
Reads configuration; writes a new JSON evidence file and temporary secedit export/log.
Never applies a security policy, edits registry/services, or enables remote access.
FunctionsOnly loads helpers for fixture tests without inspecting this computer.
#>
[CmdletBinding()]
param(
    [string]$ExpectedComputerName,
    [string]$OutputPath,
    [switch]$FunctionsOnly
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-LabTarget {
    param($Os, $Computer, [string]$ExpectedName)
    if ([string]::IsNullOrWhiteSpace($ExpectedName) -or $Computer.Name -ine $ExpectedName) {
        throw 'Supply the exact VM computer name using -ExpectedComputerName.'
    }
    if ($Os.Caption -notlike '*Windows Server 2022*' -or $Os.Version -ne '10.0.20348' -or
        $Os.BuildNumber -ne '20348' -or $Os.OSArchitecture -ne '64-bit' -or
        $Os.ProductType -ne 3 -or $Computer.PartOfDomain -ne $false -or $Computer.DomainRole -ne 2) {
        throw 'Unsupported target: only a standalone Windows Server 2022 x64 lab is permitted.'
    }
}

function Read-PolicyInteger {
    param([string[]]$Lines, [string]$Key)
    $inSection = $false
    $found = @()
    foreach ($line in $Lines) {
        $clean = $line.Trim()
        if ($clean -match '^\[(.+)\]$') {
            $inSection = $Matches[1] -eq 'System Access'
        } elseif ($inSection -and $clean -match ('^' + [regex]::Escape($Key) + '\s*=\s*(.*)$')) {
            $found += $Matches[1].Trim()
        }
    }
    if ($found.Count -eq 0) { return $null }
    if ($found.Count -ne 1 -or $found[0] -notmatch '^\d+$') { throw 'invalid_value' }
    return [uint32]::Parse($found[0], [Globalization.CultureInfo]::InvariantCulture)
}

function Read-PolicyDword {
    param([string]$SubKey, [string]$ValueName)
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    $key = $null
    try {
        $key = $base.OpenSubKey($SubKey, $false)
        if ($null -eq $key -or $ValueName -notin $key.GetValueNames()) { return $null }
        if ($key.GetValueKind($ValueName) -ne [Microsoft.Win32.RegistryValueKind]::DWord) {
            throw 'invalid_value'
        }
        # Preserve unsigned DWORD values without interpreting nonzero as compliant.
        return [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$key.GetValue($ValueName)), 0)
    } finally {
        if ($null -ne $key) { $key.Dispose() }
        $base.Dispose()
    }
}

function New-Observation {
    param([string]$ControlId, [string]$Source, [scriptblock]$Read)
    $value = $null
    $errorCode = $null
    $state = 'ok'
    try {
        $value = & $Read
        if ($null -eq $value) { $state = 'missing' }
    } catch {
        $state = 'error'
        $value = $null
        $errorCode = 'collection_failed'
        if ($_.Exception.Message -in @('invalid_value', 'timeout', 'ambiguous_account')) {
            $errorCode = $_.Exception.Message
        }
    }
    return [ordered]@{
        control_id = $ControlId; source = $Source; state = $state
        value = $value; error = $errorCode; collected_at = [DateTimeOffset]::UtcNow.ToString('o')
    }
}

if ($FunctionsOnly) { return }

# Identity checks occur before temporary files or security configuration collection.
if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit Windows PowerShell.' }
$os = Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 15
$computer = Get-CimInstance Win32_ComputerSystem -OperationTimeoutSec 15
Assert-LabTarget -Os $os -Computer $computer -ExpectedName $ExpectedComputerName
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open Windows PowerShell as Administrator inside the lab VM.'
}
$product = Get-CimInstance Win32_ComputerSystemProduct -OperationTimeoutSec 15
$machineUuid = [guid]::Parse($product.UUID).ToString()
if ($machineUuid -in @('00000000-0000-0000-0000-000000000000', 'ffffffff-ffff-ffff-ffff-ffffffffffff')) {
    throw 'A non-placeholder machine UUID is required.'
}
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path ([Environment]::GetFolderPath('Desktop')) (
        'Server2022-evidence-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '.json')
}
$fullOutput = [IO.Path]::GetFullPath($OutputPath)
if ([IO.File]::Exists($fullOutput)) { throw 'Output already exists; choose a new filename.' }
if (-not [IO.Directory]::Exists([IO.Path]::GetDirectoryName($fullOutput))) {
    throw 'Output directory must already exist.'
}
$started = [DateTimeOffset]::UtcNow
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$tempFolder = [IO.Path]::Combine($tempRoot, 'cis-readonly-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($tempFolder)
$policyFile = Join-Path $tempFolder 'policy.inf'
$logFile = Join-Path $tempFolder 'export.log'
$policyLines = @()
$policyError = $null
$process = $null
try {
    try {
        $seceditPath = Join-Path $env:SystemRoot 'System32\secedit.exe'
        $arguments = '/export /cfg "' + $policyFile + '" /areas SECURITYPOLICY /log "' + $logFile + '" /quiet'
        $process = Start-Process -FilePath $seceditPath -ArgumentList $arguments -PassThru -WindowStyle Hidden
        $null = $process.Handle
        if (-not $process.WaitForExit(30000)) {
            $process.Kill()
            $process.WaitForExit()
            throw 'timeout'
        }
        # Refresh process state before reading ExitCode on Windows PowerShell 5.1.
        $process.Refresh()
        if ($process.ExitCode -ne 0 -or -not [IO.File]::Exists($policyFile)) { throw 'collection_failed' }
        $policyLines = [IO.File]::ReadAllLines($policyFile, [Text.Encoding]::Unicode)
    } catch {
        $policyError = if ($_.Exception.Message -eq 'timeout') { 'timeout' } else { 'collection_failed' }
    }
    $observations = @(
        New-Observation '1.1.4' 'secedit-export:System Access/MinimumPasswordLength' {
            if ($null -ne $policyError) { throw $policyError }
            Read-PolicyInteger $policyLines 'MinimumPasswordLength'
        }
        New-Observation '1.2.2' 'secedit-export:System Access/LockoutBadCount' {
            if ($null -ne $policyError) { throw $policyError }
            Read-PolicyInteger $policyLines 'LockoutBadCount'
        }
        New-Observation '2.3.1.1' 'Win32_UserAccount:LocalAccount=True,SID-RID=501/Disabled' {
            $guest = @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' -OperationTimeoutSec 15 |
                Where-Object { $_.SID -match '^S-1-5-21-\d+-\d+-\d+-501$' })
            if ($guest.Count -ne 1) { throw 'ambiguous_account' }
            if ($guest[0].Disabled -isnot [bool]) { throw 'invalid_value' }
            return (-not $guest[0].Disabled)
        }
        New-Observation '9.3.1' 'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile:EnableFirewall' {
            Read-PolicyDword 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' 'EnableFirewall'
        }
        New-Observation '18.10.57.3.9.4' 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:UserAuthentication' {
            Read-PolicyDword 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'UserAuthentication'
        }
    )
    $payload = [ordered]@{
        schema_version = 1; collector_id = 'server2022-readonly-v1'
        catalogue_id = 'cis-server2022-standalone-2.0.0-preview1'
        benchmark_sha256 = '474f467dd90b5cd50598589e427c2360502b8d25e633f729efd89f44662c5d1d'
        profile = 'Level 1 - Member Server'; evidence_mode = 'Imported'
        started_at = $started.ToString('o'); completed_at = [DateTimeOffset]::UtcNow.ToString('o')
        target = [ordered]@{
            hostname = [string]$computer.Name; machine_uuid = $machineUuid
            os_caption = [string]$os.Caption; os_version = [string]$os.Version
            build_number = [string]$os.BuildNumber; os_architecture = [string]$os.OSArchitecture
            product_type = [int]$os.ProductType; part_of_domain = [bool]$computer.PartOfDomain
            domain_role = [int]$computer.DomainRole
        }
        observations = $observations
    }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($payload | ConvertTo-Json -Depth 6))
    $outputStream = [IO.File]::Open($fullOutput, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
    try { $outputStream.Write($bytes, 0, $bytes.Length) } finally { $outputStream.Dispose() }
    Write-Host ('Saved read-only evidence: ' + $fullOutput)
    Write-Host ('Target: ' + $computer.Name + ' / ' + $machineUuid)
    Write-Host 'No hardening applied. Missing policy values require manual review.'
} finally {
    if ($null -ne $process) { $process.Dispose() }
    # Only delete known files created in this run's generated temporary directory.
    if ([IO.Path]::GetFullPath($tempFolder).StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) {
        foreach ($createdFile in @($policyFile, $logFile)) {
            if ([IO.File]::Exists($createdFile)) { [IO.File]::Delete($createdFile) }
        }
        if ([IO.Directory]::Exists($tempFolder) -and [IO.Directory]::GetFileSystemEntries($tempFolder).Length -eq 0) {
            [IO.Directory]::Delete($tempFolder, $false)
        }
    }
}
