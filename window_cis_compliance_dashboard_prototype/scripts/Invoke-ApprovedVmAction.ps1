<#
ONE-SHOT LAB VM RUNNER. Never run on the development laptop.
Only fixed net.exe accounts /minpwlen:14 is executable. No request-supplied command.
Requires a digest copied independently from Streamlit and a local administrator confirmation.
FunctionsOnly exposes pure/core helpers for fixture tests without touching the machine.
#>
[CmdletBinding()]
param(
    [string]$RequestPath,
    [string]$ExpectedRequestSha256,
    [string]$ExpectedComputerName,
    [string]$ExpectedMachineUuid,
    [string]$OutputDirectory,
    [switch]$FunctionsOnly
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-VmPath([string]$Path, [string]$BaseDirectory) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return [IO.Path]::GetFullPath($BaseDirectory) }
    if ([IO.Path]::IsPathRooted($Path)) {
        if ($Path -notmatch '^[a-zA-Z]:[\\/]' -and $Path -notmatch '^\\\\') {
            throw 'Drive-relative or root-relative paths are ambiguous.'
        }
        return [IO.Path]::GetFullPath($Path)
    }
    return [IO.Path]::GetFullPath([IO.Path]::Combine($BaseDirectory, $Path))
}

function Get-RunnerSummary($Receipt) {
    if ($Receipt.status -eq 'execution_failed') {
        return 'Action command failed or timed out. Outcome requires review; no automatic retry.'
    }
    if ($Receipt.status -eq 'verification_unavailable' -or $null -eq $Receipt.after_evidence) {
        return 'Action command completed, but fresh verification evidence is unavailable.'
    }
    try {
        $after = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Receipt.after_evidence)) | ConvertFrom-Json
        $value = Get-PasswordObservation $after
        if ($value -ge 14) {
            return "Post-action check: minimum password length is $value (required: at least 14). Return the receipt to save verification."
        }
        return "Post-action check FAILED: minimum password length is $value (required: at least 14). No automatic retry."
    } catch { return 'Action command completed; password-length read-back could not be evaluated. Return receipt for review.' }
}

function Assert-ExactFields($Object, [string[]]$Fields) {
    $names = @($Object.PSObject.Properties.Name)
    if (@(Compare-Object ($names | Sort-Object) ($Fields | Sort-Object)).Count -ne 0) {
        throw 'Unexpected or missing request fields.'
    }
}

function Assert-ApprovedRequest($Request, [string]$ComputerName, [string]$MachineUuid, [DateTimeOffset]$Now) {
    Assert-ExactFields $Request @('schema_version','request_id','evidence_sha256','hostname','machine_uuid',
        'control_id','action_id','parameters','expected_before','approved_by','approved_at','expires_at')
    Assert-ExactFields $Request.parameters @('minimum_length')
    if ($Request.schema_version -isnot [int] -or $Request.schema_version -ne 1 -or
        $Request.request_id -cnotmatch '^[a-f0-9]{32}$' -or
        $Request.evidence_sha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $Request.hostname -ine $ComputerName -or $Request.machine_uuid -ine $MachineUuid -or
        $Request.action_id -cne 'SET-MINIMUM-PASSWORD-LENGTH-14' -or $Request.control_id -cne '1.1.4' -or
        $Request.parameters.minimum_length -isnot [int] -or $Request.parameters.minimum_length -ne 14 -or
        $Request.expected_before -isnot [int] -or $Request.expected_before -lt 0 -or $Request.expected_before -ge 14 -or
        [string]::IsNullOrWhiteSpace($Request.approved_by)) { throw 'Request is outside the supported approval contract.' }
    $approved = [DateTimeOffset]::Parse($Request.approved_at)
    $expires = [DateTimeOffset]::Parse($Request.expires_at)
    if ($approved -gt $Now -or $expires -le $Now -or $expires -le $approved -or
        ($expires - $approved).TotalHours -gt 24) { throw 'Approval expired or clock is incorrect.' }
}

function Get-PasswordObservation($Evidence) {
    $rows = @($Evidence.observations | Where-Object { $_.control_id -ceq '1.1.4' })
    if ($rows.Count -ne 1 -or $rows[0].state -cne 'ok' -or
        $rows[0].value -isnot [int] -or $rows[0].source -cne 'secedit-export:System Access/MinimumPasswordLength') {
        throw 'Password precondition could not be collected.'
    }
    return $rows[0].value
}

function Invoke-GuardedAction($Request, [string]$RequestHash, [scriptblock]$Collect,
    [scriptblock]$MarkAttempt, [scriptblock]$Apply) {
    # Collect returns original JSON bytes. The runtime collector enforces the server role.
    Write-Host 'Pre-action check: collecting current settings (read-only).'
    $before = & $Collect
    $document = [Text.Encoding]::UTF8.GetString($before) | ConvertFrom-Json
    if ($document.target.hostname -ine $Request.hostname -or $document.target.machine_uuid -ine $Request.machine_uuid) {
        throw 'Precondition target mismatch.'
    }
    if ((Get-PasswordObservation $document) -ne $Request.expected_before) {
        throw 'Configuration changed since assessment. Collect/import again and obtain a new approval.'
    }
    # Durable CreateNew claim BEFORE any write. A crash consumes this request; never retry it.
    & $MarkAttempt
    $status = 'applied'
    Write-Host 'Executing approved action: set minimum password length to 14.'
    try { & $Apply } catch { $status = 'execution_failed' }
    $after = $null
    Write-Host 'Post-action check: collecting fresh verification evidence (read-only).'
    try { $after = & $Collect } catch {
        if ($status -eq 'applied') { $status = 'verification_unavailable' }
    }
    return [ordered]@{
        schema_version=1; request_id=$Request.request_id; request_sha256=$RequestHash; status=$status
        before_evidence=[Convert]::ToBase64String($before)
        after_evidence=$(if ($null -ne $after) { [Convert]::ToBase64String($after) } else { $null })
    }
}

if ($FunctionsOnly) { return }
if ([string]::IsNullOrWhiteSpace($RequestPath)) { throw 'Supply the approved request filename using -RequestPath.' }
$resolvedRequestPath = Resolve-VmPath $RequestPath $PSScriptRoot
$resolvedOutputDirectory = Resolve-VmPath $OutputDirectory $PSScriptRoot
if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit Windows PowerShell in the VM.' }
. "$PSScriptRoot\Collect-Server2022Evidence.ps1" -FunctionsOnly -ExpectedComputerName $ExpectedComputerName
$os = Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 15
$computer = Get-CimInstance Win32_ComputerSystem -OperationTimeoutSec 15
Assert-LabTarget $os $computer $ExpectedComputerName
$actualUuid = ([guid](Get-CimInstance Win32_ComputerSystemProduct -OperationTimeoutSec 15).UUID).ToString()
if ([string]::IsNullOrWhiteSpace($ExpectedMachineUuid) -or $actualUuid -ine $ExpectedMachineUuid -or
    $actualUuid -in @('00000000-0000-0000-0000-000000000000','ffffffff-ffff-ffff-ffff-ffffffffffff')) {
    throw 'Independent VM UUID confirmation required.'
}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'VM administrator required.' }
if ($ExpectedRequestSha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'Copy the request SHA-256 from Streamlit.' }
$requestBytes = [IO.File]::ReadAllBytes($resolvedRequestPath)
if ($requestBytes.Length -gt 8192) { throw 'Request exceeds size limit.' }
$sha = [Security.Cryptography.SHA256]::Create()
try { $hash = ([BitConverter]::ToString($sha.ComputeHash($requestBytes))).Replace('-','').ToLowerInvariant() }
finally { $sha.Dispose() }
if ($hash -cne $ExpectedRequestSha256) { throw 'Request hash does not match the approved download.' }
$request = [Text.Encoding]::UTF8.GetString($requestBytes) | ConvertFrom-Json
Assert-ApprovedRequest $request $ExpectedComputerName $actualUuid ([DateTimeOffset]::UtcNow)
$output = $resolvedOutputDirectory
if (-not [IO.Directory]::Exists($output)) { throw 'Output directory must already exist inside the VM.' }
$receiptPath = Join-Path $output ($request.request_id + '-receipt.json')
if ([IO.File]::Exists($receiptPath)) { throw 'Receipt already exists; import it instead of retrying.' }
Write-Host "VM: $ExpectedComputerName / $actualUuid"
Write-Host "Action: minimum password length $($request.expected_before) -> 14; approved by $($request.approved_by)"
Write-Host 'Applies to future local password changes; existing passwords are not rotated.'
$phrase = 'APPLY ' + $request.request_id
if ((Read-Host "Type exactly $phrase to apply this one change") -cne $phrase) { throw 'Cancelled; no hardening applied.' }

# Machine-local ledger survives copying the same request into a different exchange folder.
$ledger = Join-Path $env:ProgramData 'FYP-ApprovedVmActions'
[void][IO.Directory]::CreateDirectory($ledger)
$guard = [IO.File]::Open((Join-Path $ledger 'runner.lock'), [IO.FileMode]::OpenOrCreate,
    [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
try {
    Assert-ApprovedRequest $request $ExpectedComputerName $actualUuid ([DateTimeOffset]::UtcNow)
    $claim = Join-Path $ledger ($request.request_id + '.attempt')
    if ([IO.File]::Exists($claim)) { throw 'Request already attempted. Review outcome; do not replay.' }
    $collector = Join-Path $PSScriptRoot 'Collect-Server2022Evidence.ps1'
    $collect = {
        $evidencePath = Join-Path $output ('evidence-' + [guid]::NewGuid().ToString('N') + '.json')
        # Invoke in child scope so collector variables cannot overwrite runner state.
        & $collector -ExpectedComputerName $ExpectedComputerName -OutputPath $evidencePath -Quiet | Out-Null
        return ,([IO.File]::ReadAllBytes($evidencePath))
    }
    $mark = {
        if ([DateTimeOffset]::UtcNow -ge [DateTimeOffset]::Parse($request.expires_at)) { throw 'Approval expired.' }
        $stream = [IO.File]::Open($claim, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write($requestBytes, 0, $requestBytes.Length); $stream.Flush($true) }
        finally { $stream.Dispose() }
    }
    $apply = {
        # Constant executable and constant arguments; no text supplied by request/model is executed.
        $process = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\net.exe') `
            -ArgumentList @('accounts', '/minpwlen:14') -PassThru -WindowStyle Hidden
        try {
            $null = $process.Handle
            if (-not $process.WaitForExit(30000)) { $process.Kill(); throw 'Execution timeout; outcome uncertain.' }
            $process.Refresh()
            if ($process.ExitCode -ne 0) { throw 'Execution failed.' }
        } finally { $process.Dispose() }
    }
    $receipt = Invoke-GuardedAction $request $hash $collect $mark $apply
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($receipt | ConvertTo-Json -Depth 5))
    $stream = [IO.File]::Open($receiptPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    Write-Host "Return this receipt to Streamlit for deterministic verification: $receiptPath"
    Write-Host "Runner status: $($receipt.status). No automatic retries."
    Write-Host (Get-RunnerSummary $receipt)
} finally { $guard.Dispose() }
