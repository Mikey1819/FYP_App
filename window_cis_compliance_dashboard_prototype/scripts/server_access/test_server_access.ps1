# Fixture-only checks of the server access helper's planning logic. Never touches WinRM or the firewall.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\FYP-ServerAccess.ps1" -FunctionsOnly
function Assert-True([bool]$Condition, [string]$Label) { if (-not $Condition) { throw "Failed: $Label" } }

Assert-True (Test-ScannerAddress '192.168.56.1') 'host-only laptop address'
Assert-True (Test-ScannerAddress ' 10.0.0.5 ') 'surrounding spaces are trimmed'
foreach ($bad in @('', ' ', '0.0.0.0', '255.255.255.255', '127.0.0.1', '224.0.0.1', '192.168.56.0/24', 'Any',
                   'LocalSubnet', '1', '192.168.56', '::1', 'fe80::1', '192.168.56.1,10.0.0.1', '300.1.1.1')) {
    Assert-True (-not (Test-ScannerAddress $bad)) "rejects '$bad'"
}

$rejected = $false
try { Assert-ServerOs ([pscustomobject]@{ ProductType = 1 }) } catch { $rejected = $true }
Assert-True $rejected 'refuses a workstation such as the laptop'
Assert-ServerOs ([pscustomobject]@{ ProductType = 3 })

$now = [DateTimeOffset]::Parse('2026-11-03T05:00:00+00:00')
$rules = [ordered]@{ 'WINRM-HTTP-In-TCP' = $false; 'WINRM-HTTP-In-TCP-PUBLIC' = $null }
$off = [pscustomobject]@{ winrm_running = $false; winrm_start_mode = 'Manual'; http_listener = $false
                          builtin_rules = $rules; token_filter_policy = $null }
$state = New-AccessState $off '192.168.56.1' $now
Assert-True ($state.helper_enabled_remoting -and -not $state.remoting_was_on) 'remoting off: the helper turns it on'
$full = @('remove_rule', 'disable_remoting', 'remove_listener', 'restore_builtin_rules', 'restore_token_filter', 'restore_service')
Assert-True (((Get-RevertPlan $state) -join ',') -ceq ($full -join ',')) 'remoting off: revert undoes everything'
# Revert reads the saved JSON, not the in-memory object.
$saved = ($state | ConvertTo-Json -Depth 4) | ConvertFrom-Json
Assert-True (((Get-RevertPlan $saved) -join ',') -ceq ($full -join ',')) 'plan survives the JSON round trip'
Assert-True ($null -eq $saved.token_filter_policy -and $saved.builtin_rules.'WINRM-HTTP-In-TCP' -eq $false) 'prior values survive'

$on = [pscustomobject]@{ winrm_running = $true; winrm_start_mode = 'Auto'; http_listener = $true
                         builtin_rules = $rules; token_filter_policy = 0 }
$state = New-AccessState $on '192.168.56.1' $now
Assert-True ((-not $state.helper_enabled_remoting) -and $state.remoting_was_on) 'remoting on: left as it was'
Assert-True (((Get-RevertPlan $state) -join ',') -ceq 'remove_rule') 'remoting on: revert removes only the rule'
$noListener = [pscustomobject]@{ winrm_running = $true; winrm_start_mode = 'Auto'; http_listener = $false
                                 builtin_rules = $rules; token_filter_policy = $null }
Assert-True ((New-AccessState $noListener '192.168.56.1' $now).helper_enabled_remoting) 'running without a listener counts as off'

# Pairing messages: the same examples the dashboard's Python tests use (pairing_vectors.json).
$vectors = Get-Content "$PSScriptRoot\pairing_vectors.json" -Raw | ConvertFrom-Json
$f = $vectors.find; $g = $vectors.found
Assert-True ((Get-PairingMac $vectors.code @('find', 1, $f.nonce_l, $f.laptop_name)) -ceq $f.mac) 'find signature matches Python'
Assert-True ((Get-PairingMac $vectors.code @('found', 1, $g.nonce_l, $g.nonce_s, $g.hostname, $g.machine_uuid, $g.port,
    $g.pairing_id)) -ceq $g.mac) 'found signature matches Python'
$found = New-PairFound $vectors.code $g.nonce_l $g.hostname $g.machine_uuid.ToUpper() $g.port $g.pairing_id $g.nonce_s
$foundBack = [Text.Encoding]::UTF8.GetString($found) | ConvertFrom-Json
Assert-True ($foundBack.mac -ceq $g.mac -and $foundBack.machine_uuid -ceq $g.machine_uuid) 'built answer carries the same signature'
$question = Read-PairFind ([Text.Encoding]::UTF8.GetBytes($f.raw)) $vectors.code
Assert-True ($question.laptop_name -ceq 'DESKTOP-KHOO') 'accepts the Python-built question'
function Get-PairError([byte[]]$Raw, [string]$Code) { try { $null = Read-PairFind $Raw $Code; 'accepted' } catch { $_.Exception.Message } }
$raw = [Text.Encoding]::UTF8.GetBytes($f.raw)
Assert-True ((Get-PairError $raw $vectors.wrong_code) -ceq 'wrong_code') 'a wrong code is a counted wrong attempt'
$tampered = [Text.Encoding]::UTF8.GetBytes($f.raw.Replace('DESKTOP-KHOO', 'DESKTOP-EVIL'))
Assert-True ((Get-PairError $tampered $vectors.code) -ceq 'wrong_code') 'a changed field breaks the signature'
foreach ($bad in @('hello', '{}', '[]', 'null', '{"v":1,"type":"found"}', $f.raw.Replace('"v":1', '"v":2'),
                   $f.raw.Replace('"v":1', '"v":true'), $f.raw.Replace('"v":1', '"v":1,"extra":1'),
                   $f.raw.Replace('DESKTOP-KHOO', 'DESK TOP'), ('x' * 2000))) {
    Assert-True ((Get-PairError ([Text.Encoding]::UTF8.GetBytes($bad)) $vectors.code) -ceq 'not_ours') "ignores '$($bad.Substring(0, [Math]::Min(30, $bad.Length)))'"
}
Assert-True ((Get-PairError ([byte[]](0xC3, 0x28)) $vectors.code) -ceq 'not_ours') 'ignores invalid UTF-8'
$codes = @(1..20 | ForEach-Object { New-PairingCode })
Assert-True (@($codes | Where-Object { $_ -cmatch '^\d{9}$' }).Count -eq 20) 'codes are 9 digits'
Assert-True (@($codes | Sort-Object -Unique).Count -gt 15) 'codes are random'
Assert-True ((New-Nonce) -cmatch '^[0-9a-f]{32}$') 'nonce is 128 bits of hex'

if (([Environment]::OSVersion.Platform -eq 'Win32NT')) {
    $form = New-HelperForm
    $buttons = @($form.Controls | Where-Object { $_ -is [Windows.Forms.Button] } | ForEach-Object { $_.Text })
    Assert-True (($buttons -join '|') -ceq 'Check status|Allow scanning|Revert changes') 'window has the three buttons'
    Assert-True (@($form.Controls | Where-Object { $_.Tag -is [scriptblock] }).Count -eq 3) 'each button carries its action'
    $form.Dispose()
}
Write-Host 'PASS: server access helper address, workstation, state, revert-plan and pairing-message checks; window builds (fixtures only).'
