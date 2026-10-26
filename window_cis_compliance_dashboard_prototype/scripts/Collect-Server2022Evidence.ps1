<#
Run ONLY inside the selected standalone Server 2022 lab VM.
Reads configuration; writes a new JSON evidence file and temporary secedit export/log.
Never applies a security policy, edits registry/services, or enables remote access.
FunctionsOnly loads helpers for fixture tests without inspecting this computer.
EmitJson returns the evidence JSON on the output stream instead of writing a file;
the Scanner Agent uses it when invoking this collector over PowerShell Remoting.
#>
[CmdletBinding()]
param(
    [string]$ExpectedComputerName,
    [string]$OutputPath,
    [switch]$Quiet,
    [switch]$FunctionsOnly,
    [switch]$EmitJson
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
    param([string[]]$Lines, [string]$Key, [switch]$AllowMinusOne)
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
    if ($found.Count -eq 1 -and $AllowMinusOne -and $found[0] -eq '-1') { return -1 }
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

function Get-AccountPolicyObservations {
    param([string[]]$Lines, [string]$PolicyError)
    $settings = @(
        @('1.1.4', 'MinimumPasswordLength'), @('1.2.2', 'LockoutBadCount'),
        @('1.1.1', 'PasswordHistorySize'), @('1.1.2', 'MaximumPasswordAge'),
        @('1.1.3', 'MinimumPasswordAge'), @('1.1.5', 'PasswordComplexity'),
        @('1.1.7', 'ClearTextPassword'), @('1.2.1', 'LockoutDuration'),
        @('1.2.4', 'ResetLockoutCount')
    )
    foreach ($setting in $settings) {
        $key = $setting[1]
        New-Observation $setting[0] ('secedit-export:System Access/' + $key) {
            if (-not [string]::IsNullOrEmpty($PolicyError)) { throw $PolicyError }
            Read-PolicyInteger -Lines $Lines -Key $key -AllowMinusOne:($key -in @('MaximumPasswordAge', 'LockoutDuration'))
        }
    }
}

function Get-LocalSecurityObservations {
    param([string[]]$Lines, [string]$PolicyError)
    New-Observation '2.3.10.1' 'secedit-export:System Access/LSAAnonymousNameLookup' {
        if (-not [string]::IsNullOrEmpty($PolicyError)) { throw $PolicyError }
        Read-PolicyInteger -Lines $Lines -Key 'LSAAnonymousNameLookup'
    }
    foreach ($setting in @(@('2.3.1.2', 'LimitBlankPasswordUse'),
                          @('2.3.10.2', 'RestrictAnonymousSAM'),
                          @('2.3.10.3', 'RestrictAnonymous'))) {
        $valueName = $setting[1]
        New-Observation $setting[0] ('HKLM\SYSTEM\CurrentControlSet\Control\Lsa:' + $valueName) {
            Read-PolicyDword 'SYSTEM\CurrentControlSet\Control\Lsa' $valueName
        }
    }
}

$PolicyDwords = @(
    @('9.2.1', 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile', 'EnableFirewall'),
    @('9.2.2', 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile', 'DefaultInboundAction'),
    @('9.2.6', 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging', 'LogDroppedPackets'),
    @('9.2.7', 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging', 'LogSuccessfulConnections'),
    @('9.3.2', 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile', 'DefaultInboundAction'),
    @('9.3.6', 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging', 'LogDroppedPackets'),
    @('9.3.7', 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging', 'LogSuccessfulConnections'),
    @('18.10.57.2.2', 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services', 'DisablePasswordSaving'),
    @('18.10.57.3.9.1', 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services', 'fPromptForPassword'),
    @('18.10.57.3.9.3', 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services', 'SecurityLayer'),
    @('18.10.57.3.9.5', 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services', 'MinEncryptionLevel')
)
# Subcategory GUIDs exactly as printed in each benchmark audit step (locale-independent).
$AuditSubcategories = @(
    @('17.1.1', '0cce923f-69ae-11d9-bed3-505054503030'), @('17.2.2', '0cce9237-69ae-11d9-bed3-505054503030'),
    @('17.2.3', '0cce9235-69ae-11d9-bed3-505054503030'), @('17.5.1', '0cce9217-69ae-11d9-bed3-505054503030'),
    @('17.5.4', '0cce9215-69ae-11d9-bed3-505054503030')
)

function Get-PolicyDwordObservations {
    foreach ($policy in $PolicyDwords) {
        $policyKey = $policy[1]
        $policyName = $policy[2]
        New-Observation $policy[0] ('HKLM\' + $policyKey + ':' + $policyName) { Read-PolicyDword $policyKey $policyName }
    }
}

function Read-AuditSetting {
    # auditpol /backup "Setting Value": 0 none, 1 Success, 2 Failure, 3 Success and Failure.
    param([object[]]$Rows, [string]$Guid)
    $found = @($Rows | Where-Object { ([string]$_.'Subcategory GUID').Trim('{}') -ieq $Guid })
    if ($found.Count -eq 0) { return $null }
    if ($found.Count -ne 1 -or [string]$found[0].'Setting Value' -notmatch '^[0-3]$') { throw 'invalid_value' }
    return [int]$found[0].'Setting Value'
}

function Get-AuditObservations {
    param([object[]]$Rows, [string]$AuditError)
    foreach ($subcategory in $AuditSubcategories) {
        $auditGuid = $subcategory[1]
        New-Observation $subcategory[0] ('auditpol-backup:{' + $auditGuid + '}/Setting Value') {
            if (-not [string]::IsNullOrEmpty($AuditError)) { throw $AuditError }
            Read-AuditSetting -Rows $Rows -Guid $auditGuid
        }
    }
}

function Invoke-BoundedTool([string]$Executable, [string]$Arguments) {
    $tool = Start-Process -FilePath (Join-Path $env:SystemRoot ('System32\' + $Executable)) -ArgumentList $Arguments `
        -PassThru -WindowStyle Hidden
    try {
        $null = $tool.Handle
        if (-not $tool.WaitForExit(30000)) { $tool.Kill(); $tool.WaitForExit(); throw 'timeout' }
        $tool.Refresh()
        if ($tool.ExitCode -ne 0) { throw 'collection_failed' }
    } finally { $tool.Dispose() }
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
if (-not $EmitJson) {
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $OutputPath = Join-Path ([Environment]::GetFolderPath('Desktop')) (
            'Server2022-evidence-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '.json')
    }
    $fullOutput = [IO.Path]::GetFullPath($OutputPath)
    if ([IO.File]::Exists($fullOutput)) { throw 'Output already exists; choose a new filename.' }
    if (-not [IO.Directory]::Exists([IO.Path]::GetDirectoryName($fullOutput))) {
        throw 'Output directory must already exist.'
    }
}
$started = [DateTimeOffset]::UtcNow
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$tempFolder = [IO.Path]::Combine($tempRoot, 'cis-readonly-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($tempFolder)
$policyFile = Join-Path $tempFolder 'policy.inf'
$logFile = Join-Path $tempFolder 'export.log'
$auditFile = Join-Path $tempFolder 'audit.csv'
$auditRows = @()
$auditError = $null
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
    try {
        # Read-only backup of the effective advanced audit policy into this run's temp folder.
        Invoke-BoundedTool 'auditpol.exe' ('/backup /file:"' + $auditFile + '"')
        if (-not [IO.File]::Exists($auditFile)) { throw 'collection_failed' }
        $auditRows = @(Import-Csv -Path $auditFile)
    } catch {
        $auditError = if ($_.Exception.Message -eq 'timeout') { 'timeout' } else { 'collection_failed' }
    }
    $observations = @(
        Get-AccountPolicyObservations -Lines $policyLines -PolicyError $policyError
        Get-LocalSecurityObservations -Lines $policyLines -PolicyError $policyError
        Get-PolicyDwordObservations
        Get-AuditObservations -Rows $auditRows -AuditError $auditError
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
    # Effective state is context, not a replacement for the benchmark's explicit policy audit.
    $effective = @(
        New-Observation 'firewall_public_enabled' 'Get-NetFirewallProfile:ActiveStore/Public/Enabled' {
            $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -Name Public -ErrorAction Stop)
            if ($profiles.Count -ne 1 -or [string]$profiles[0].Enabled -notin @('True', 'False')) {
                throw 'invalid_value'
            }
            return ([string]$profiles[0].Enabled -eq 'True')
        }
        New-Observation 'firewall_private_enabled' 'Get-NetFirewallProfile:ActiveStore/Private/Enabled' {
            $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -Name Private -ErrorAction Stop)
            if ($profiles.Count -ne 1 -or [string]$profiles[0].Enabled -notin @('True', 'False')) {
                throw 'invalid_value'
            }
            return ([string]$profiles[0].Enabled -eq 'True')
        }
        foreach ($profileName in @('Private', 'Public')) {
            New-Observation ('firewall_' + $profileName.ToLowerInvariant() + '_inbound_blocked') `
                ('Get-NetFirewallProfile:ActiveStore/' + $profileName + '/DefaultInboundAction') {
                $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -Name $profileName -ErrorAction Stop)
                $action = if ($profiles.Count -eq 1) { [string]$profiles[0].DefaultInboundAction } else { '' }
                # NotConfigured means the Windows default applies, which blocks unsolicited inbound traffic.
                if ($action -notin @('Block', 'Allow', 'NotConfigured')) { throw 'invalid_value' }
                return ($action -ne 'Allow')
            }
        }
        New-Observation 'nla_required' 'Win32_TSGeneralSetting:RDP-tcp/UserAuthenticationRequired' {
            $settings = @(Get-CimInstance -Namespace 'root\CIMv2\TerminalServices' -ClassName Win32_TSGeneralSetting `
                -Filter "TerminalName='RDP-tcp'" -OperationTimeoutSec 15)
            if ($settings.Count -ne 1 -or $settings[0].UserAuthenticationRequired -notin @(0, 1)) {
                throw 'invalid_value'
            }
            return [int]$settings[0].UserAuthenticationRequired
        }
        New-Observation 'nla_policy_source' 'Win32_TSGeneralSetting:RDP-tcp/PolicySourceUserAuthenticationRequired' {
            $settings = @(Get-CimInstance -Namespace 'root\CIMv2\TerminalServices' -ClassName Win32_TSGeneralSetting `
                -Filter "TerminalName='RDP-tcp'" -OperationTimeoutSec 15)
            if ($settings.Count -ne 1 -or $settings[0].PolicySourceUserAuthenticationRequired -notin @(0, 1, 2)) {
                throw 'invalid_value'
            }
            return [int]$settings[0].PolicySourceUserAuthenticationRequired
        }
    )
    $payload = [ordered]@{
        schema_version = 5; collector_id = 'server2022-readonly-v5'
        catalogue_id = 'cis-server2022-standalone-2.0.0-full1'
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
        effective_context = $effective
    }
    $json = $payload | ConvertTo-Json -Depth 6
    if ($EmitJson) {
        Write-Output $json
        return
    }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
    $outputStream = [IO.File]::Open($fullOutput, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
    try { $outputStream.Write($bytes, 0, $bytes.Length) } finally { $outputStream.Dispose() }
    if (-not $Quiet) {
        Write-Host ('Saved read-only evidence: ' + $fullOutput)
        Write-Host ('Target: ' + $computer.Name + ' / ' + $machineUuid)
        Write-Host 'Collection complete. This collector only reads settings; it does not report action execution status.'
    }
} finally {
    if ($null -ne $process) { $process.Dispose() }
    # Only delete known files created in this run's generated temporary directory.
    if ([IO.Path]::GetFullPath($tempFolder).StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) {
        foreach ($createdFile in @($policyFile, $logFile, $auditFile)) {
            if ([IO.File]::Exists($createdFile)) { [IO.File]::Delete($createdFile) }
        }
        if ([IO.Directory]::Exists($tempFolder) -and [IO.Directory]::GetFileSystemEntries($tempFolder).Length -eq 0) {
            [IO.Directory]::Delete($tempFolder, $false)
        }
    }
}
