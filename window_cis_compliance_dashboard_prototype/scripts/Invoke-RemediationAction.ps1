<#
Remediation Agent runner, invoked over PowerShell Remoting inside the lab VM only.
Executes exactly one administrator-approved action from the fixed library below.
A request supplies an action ID and value, which must match this table; it never
supplies a command. Before writing: identity, request hash, approval expiry, replay
ledger and a fresh precondition read. After writing: fresh read-back for verification.
ListActions prints the library for the Python parity test; FunctionsOnly loads helpers.
#>
[CmdletBinding()]
param(
    [string]$RequestJson,
    [string]$ExpectedRequestSha256,
    [string]$ExpectedComputerName,
    [string]$ExpectedMachineUuid,
    [string]$CollectorText,
    [switch]$ListActions,
    [switch]$FunctionsOnly
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$LsaKey = 'SYSTEM\CurrentControlSet\Control\Lsa'
$TsKey = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$Library = [ordered]@{
    'REM-1.1.1'    = @{ control_id = '1.1.1'; value = 24; kind = 'net_accounts'; option = '/uniquepw' }
    'REM-1.1.2'    = @{ control_id = '1.1.2'; value = 365; kind = 'net_accounts'; option = '/maxpwage' }
    'REM-1.1.3'    = @{ control_id = '1.1.3'; value = 1; kind = 'net_accounts'; option = '/minpwage' }
    'REM-1.1.4'    = @{ control_id = '1.1.4'; value = 14; kind = 'net_accounts'; option = '/minpwlen' }
    'REM-1.2.2'    = @{ control_id = '1.2.2'; value = 5; kind = 'net_accounts'; option = '/lockoutthreshold' }
    'REM-1.2.1'    = @{ control_id = '1.2.1'; value = 15; kind = 'net_accounts'; option = '/lockoutduration' }
    'REM-1.2.4'    = @{ control_id = '1.2.4'; value = 15; kind = 'net_accounts'; option = '/lockoutwindow' }
    'REM-2.3.1.1'  = @{ control_id = '2.3.1.1'; value = $false; kind = 'disable_guest' }
    'REM-2.3.1.2'  = @{ control_id = '2.3.1.2'; value = 1; kind = 'reg_dword'; key = $LsaKey; name = 'LimitBlankPasswordUse' }
    'REM-2.3.10.2' = @{ control_id = '2.3.10.2'; value = 1; kind = 'reg_dword'; key = $LsaKey; name = 'RestrictAnonymousSAM' }
    'REM-2.3.10.3' = @{ control_id = '2.3.10.3'; value = 1; kind = 'reg_dword'; key = $LsaKey; name = 'RestrictAnonymous' }
    'REM-17.1.1'   = @{ control_id = '17.1.1'; value = 3; kind = 'audit_flags'; guid = '0cce923f-69ae-11d9-bed3-505054503030' }
    'REM-17.2.2'   = @{ control_id = '17.2.2'; value = 1; kind = 'audit_flags'; guid = '0cce9237-69ae-11d9-bed3-505054503030' }
    'REM-17.2.3'   = @{ control_id = '17.2.3'; value = 3; kind = 'audit_flags'; guid = '0cce9235-69ae-11d9-bed3-505054503030' }
    'REM-17.5.1'   = @{ control_id = '17.5.1'; value = 2; kind = 'audit_flags'; guid = '0cce9217-69ae-11d9-bed3-505054503030' }
    'REM-17.5.4'   = @{ control_id = '17.5.4'; value = 3; kind = 'audit_flags'; guid = '0cce9215-69ae-11d9-bed3-505054503030' }
    'REM-18.10.57.2.2'   = @{ control_id = '18.10.57.2.2'; value = 1; kind = 'reg_dword'; key = $TsKey; name = 'DisablePasswordSaving' }
    'REM-18.10.57.3.9.1' = @{ control_id = '18.10.57.3.9.1'; value = 1; kind = 'reg_dword'; key = $TsKey; name = 'fPromptForPassword' }
    'REM-18.10.57.3.9.3' = @{ control_id = '18.10.57.3.9.3'; value = 2; kind = 'reg_dword'; key = $TsKey; name = 'SecurityLayer' }
    'REM-18.10.57.3.9.4' = @{ control_id = '18.10.57.3.9.4'; value = 1; kind = 'reg_dword'; key = $TsKey; name = 'UserAuthentication' }
    'REM-18.10.57.3.9.5' = @{ control_id = '18.10.57.3.9.5'; value = 3; kind = 'reg_dword'; key = $TsKey; name = 'MinEncryptionLevel' }
}

function Assert-ExactFields($Object, [string[]]$Fields) {
    $names = @($Object.PSObject.Properties.Name)
    if (@(Compare-Object ($names | Sort-Object) ($Fields | Sort-Object)).Count -ne 0) {
        throw 'Unexpected or missing request fields.'
    }
}

function Test-SameTypedValue($Observed, $Expected) {
    # PowerShell treats 0 -eq $false as true; compare type families first.
    if (($Observed -is [bool]) -ne ($Expected -is [bool])) { return $false }
    if (-not ($Observed -is [bool]) -and -not ($Observed -is [int] -or $Observed -is [long])) { return $false }
    return $Observed -eq $Expected
}

function Assert-RemediationRequest($Request, [string]$ComputerName, [string]$MachineUuid, [DateTimeOffset]$Now) {
    Assert-ExactFields $Request @('schema_version', 'request_id', 'evidence_sha256', 'hostname', 'machine_uuid',
        'control_id', 'action_id', 'value', 'expected_before', 'approved_by', 'approved_at', 'expires_at')
    if (-not $Library.Contains([string]$Request.action_id)) { throw 'Action is not in the pre-approved library.' }
    $entry = $Library[[string]$Request.action_id]
    # A null precondition means "Not configured" (value absent); only registry policy actions can set one.
    $beforeTypeOk = if ($null -eq $Request.expected_before) { $entry.kind -eq 'reg_dword' }
                    else { ($Request.expected_before -is [bool]) -eq ($entry.value -is [bool]) }
    if ($Request.schema_version -isnot [int] -or $Request.schema_version -ne 2 -or
        $Request.request_id -cnotmatch '^[a-f0-9]{32}$' -or $Request.evidence_sha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $Request.hostname -ine $ComputerName -or $Request.machine_uuid -ine $MachineUuid -or
        $Request.control_id -cne $entry.control_id -or -not (Test-SameTypedValue $Request.value $entry.value) -or
        -not $beforeTypeOk -or
        [string]::IsNullOrWhiteSpace($Request.approved_by)) {
        throw 'Request is outside the approved library contract.'
    }
    $approved = [DateTimeOffset]::Parse($Request.approved_at)
    $expires = [DateTimeOffset]::Parse($Request.expires_at)
    if ($approved -gt $Now.AddMinutes(5) -or $expires -le $Now -or $expires -le $approved -or
        ($expires - $approved).TotalHours -gt 2) { throw 'Approval expired or clock is incorrect.' }
    return $entry
}

function Get-ObservedValue($Evidence, [string]$ControlId) {
    $rows = @($Evidence.observations | Where-Object { $_.control_id -ceq $ControlId })
    if ($rows.Count -ne 1 -or $rows[0].state -cne 'ok') { throw 'Precondition could not be collected.' }
    return $rows[0].value
}

function Test-Precondition($Evidence, [string]$ControlId, $ExpectedBefore) {
    # Approved observation must still hold: the same typed value, or still "Not configured" (missing).
    $rows = @($Evidence.observations | Where-Object { $_.control_id -ceq $ControlId })
    if ($null -eq $ExpectedBefore) { return ($rows.Count -eq 1 -and $rows[0].state -ceq 'missing') }
    return (Test-SameTypedValue (Get-ObservedValue $Evidence $ControlId) $ExpectedBefore)
}

function Invoke-LibraryAction($Entry) {
    # Constant implementations only; values come from this table, never from the request.
    switch ($Entry.kind) {
        'net_accounts' {
            $arguments = @('accounts', ($Entry.option + ':' + [string]$Entry.value))
            $process = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\net.exe') `
                -ArgumentList $arguments -PassThru -WindowStyle Hidden
            try {
                $null = $process.Handle
                if (-not $process.WaitForExit(30000)) { $process.Kill(); throw 'Execution timeout; outcome uncertain.' }
                $process.Refresh()
                if ($process.ExitCode -ne 0) { throw 'net.exe accounts failed.' }
            } finally { $process.Dispose() }
        }
        'reg_dword' {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                [Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
            try {
                # CreateSubKey opens an existing key or creates a missing policy key.
                $key = $base.CreateSubKey($Entry.key, $true)
                try { $key.SetValue($Entry.name, [int]$Entry.value, [Microsoft.Win32.RegistryValueKind]::DWord) }
                finally { $key.Dispose() }
            } finally { $base.Dispose() }
        }
        'audit_flags' {
            # Enable only the required flags; never disable existing auditing.
            $arguments = @('/set', ('/subcategory:{' + $Entry.guid + '}'))
            if ($Entry.value -band 1) { $arguments += '/success:enable' }
            if ($Entry.value -band 2) { $arguments += '/failure:enable' }
            $process = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\auditpol.exe') `
                -ArgumentList $arguments -PassThru -WindowStyle Hidden
            try {
                $null = $process.Handle
                if (-not $process.WaitForExit(30000)) { $process.Kill(); throw 'Execution timeout; outcome uncertain.' }
                $process.Refresh()
                if ($process.ExitCode -ne 0) { throw 'auditpol /set failed.' }
            } finally { $process.Dispose() }
        }
        'disable_guest' {
            $guest = @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' -OperationTimeoutSec 15 |
                Where-Object { $_.SID -match '^S-1-5-21-\d+-\d+-\d+-501$' })
            if ($guest.Count -ne 1) { throw 'Built-in Guest account is ambiguous.' }
            Disable-LocalUser -SID $guest[0].SID
        }
        default { throw 'Unknown implementation kind.' }
    }
}

if ($ListActions) {
    $table = [ordered]@{}
    foreach ($id in $Library.Keys) { $table[$id] = [ordered]@{ control_id = $Library[$id].control_id; value = $Library[$id].value } }
    Write-Output ($table | ConvertTo-Json -Compress)
    return
}
if ($FunctionsOnly) { return }

if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit PowerShell.' }
$os = Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 15
$computer = Get-CimInstance Win32_ComputerSystem -OperationTimeoutSec 15
if ([string]::IsNullOrWhiteSpace($ExpectedComputerName) -or $computer.Name -ine $ExpectedComputerName -or
    $os.Caption -notlike '*Windows Server 2022*' -or $os.BuildNumber -ne '20348' -or $os.ProductType -ne 3 -or
    $computer.PartOfDomain -ne $false -or $computer.DomainRole -ne 2) {
    throw 'Unsupported target: only the registered standalone Windows Server 2022 lab VM is permitted.'
}
$actualUuid = ([guid](Get-CimInstance Win32_ComputerSystemProduct -OperationTimeoutSec 15).UUID).ToString()
if ([string]::IsNullOrWhiteSpace($ExpectedMachineUuid) -or $actualUuid -ine $ExpectedMachineUuid) {
    throw 'Machine UUID does not match the registered target.'
}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'VM administrator required.' }
if ($ExpectedRequestSha256 -cnotmatch '^[a-f0-9]{64}$' -or [string]::IsNullOrEmpty($RequestJson) -or
    [string]::IsNullOrEmpty($CollectorText)) { throw 'Request, its hash and the collector are required.' }
$requestBytes = [Text.Encoding]::UTF8.GetBytes($RequestJson)
if ($requestBytes.Length -gt 8192) { throw 'Request exceeds size limit.' }
$sha = [Security.Cryptography.SHA256]::Create()
try { $hash = ([BitConverter]::ToString($sha.ComputeHash($requestBytes))).Replace('-', '').ToLowerInvariant() }
finally { $sha.Dispose() }
if ($hash -cne $ExpectedRequestSha256) { throw 'Request hash does not match the approved request.' }
$request = $RequestJson | ConvertFrom-Json
$entry = Assert-RemediationRequest $request $ExpectedComputerName $actualUuid ([DateTimeOffset]::UtcNow)

$collectorBlock = [scriptblock]::Create($CollectorText)
$collect = {
    $json = @(& $collectorBlock -ExpectedComputerName $ExpectedComputerName -EmitJson)
    if ($json.Count -ne 1) { throw 'collection_failed' }
    return [string]$json[0]
}
# Machine-local ledger: one attempt per approved request, even across sessions or rollbacks of the host.
$ledger = Join-Path $env:ProgramData 'FYP-ApprovedVmActions'
[void][IO.Directory]::CreateDirectory($ledger)
$guard = [IO.File]::Open((Join-Path $ledger 'runner.lock'), [IO.FileMode]::OpenOrCreate,
    [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
try {
    $claim = Join-Path $ledger ($request.request_id + '.attempt')
    if ([IO.File]::Exists($claim)) { throw 'Request already attempted. Review its outcome; do not replay.' }
    $before = & $collect
    $beforeDocument = $before | ConvertFrom-Json
    if ($beforeDocument.target.hostname -ine $request.hostname -or $beforeDocument.target.machine_uuid -ine $request.machine_uuid) {
        throw 'Precondition target mismatch.'
    }
    if (-not (Test-Precondition $beforeDocument $entry.control_id $request.expected_before)) {
        throw 'Configuration changed since assessment. Rescan and obtain a new approval.'
    }
    $null = Assert-RemediationRequest $request $ExpectedComputerName $actualUuid ([DateTimeOffset]::UtcNow)
    # Durable CreateNew claim BEFORE any write. A crash consumes this request; it is never retried.
    $stream = [IO.File]::Open($claim, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($requestBytes, 0, $requestBytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    $status = 'applied'
    try { Invoke-LibraryAction $entry } catch { $status = 'execution_failed' }
    $after = $null
    try { $after = & $collect } catch { if ($status -eq 'applied') { $status = 'verification_unavailable' } }
    $receipt = [ordered]@{
        schema_version = 2; request_id = $request.request_id; request_sha256 = $hash; status = $status
        before_evidence = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($before))
        after_evidence = $(if ($null -ne $after) { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($after)) } else { $null })
    }
    Write-Output ($receipt | ConvertTo-Json -Compress)
} finally { $guard.Dispose() }
