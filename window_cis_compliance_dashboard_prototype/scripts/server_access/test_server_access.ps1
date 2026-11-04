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

# Pairing decisions (no network, no firewall): accept once, count wrong codes, stop, expire, answer a lost reply again.
function New-Find([string]$Code, [string]$Nonce = (New-Nonce), [string]$Name = 'DESKTOP-KHOO') {
    $mac = Get-PairingMac $Code @('find', 1, $Nonce, $Name)
    return ,[Text.Encoding]::UTF8.GetBytes((@{ v = 1; type = 'find'; nonce_l = $Nonce; laptop_name = $Name; mac = $mac } | ConvertTo-Json -Compress))
}
$t0 = [DateTimeOffset]::Parse('2026-11-05T12:00:00+00:00')
$s = New-PairingSession $t0
$right = New-Find $s.code
$wrongCode = if ($s.code -eq '000000000') { '111111111' } else { '000000000' }
Assert-True ((Get-PairDecision $s ([Text.Encoding]::UTF8.GetBytes('hello')) '192.168.1.23' $t0).action -ceq 'ignore') 'noise is ignored, not counted'
Assert-True ((Get-PairDecision $s $right '127.0.0.1' $t0).action -ceq 'ignore') 'loopback can never pair'
Assert-True ((Get-PairDecision $s (New-Find $wrongCode) '192.168.1.99' $t0).action -ceq 'wrong') 'a wrong code is counted'
Assert-True ($s.wrong['192.168.1.99'] -eq 1 -and -not $s.done) 'one wrong code does not stop pairing'
$ok = Get-PairDecision $s $right '192.168.1.23' $t0.AddMinutes(1)
Assert-True ($ok.action -ceq 'accept' -and $ok.find.laptop_name -ceq 'DESKTOP-KHOO' -and $s.result -ceq 'paired') 'the right code pairs'
Assert-True ((Get-PairDecision $s $right '192.168.1.23' $t0.AddMinutes(1).AddSeconds(3)).action -ceq 'repeat') 'a repeated question gets the answer again'
Assert-True ((Get-PairDecision $s $right '192.168.1.50' $t0.AddMinutes(1).AddSeconds(3)).action -ceq 'ignore') 'not from another address'
Assert-True ((Get-PairDecision $s (New-Find $s.code) '192.168.1.23' $t0.AddMinutes(1).AddSeconds(3)).action -ceq 'ignore') 'the code works once'
Assert-True ((Get-PairDecision $s $right '192.168.1.23' $t0.AddMinutes(1).AddSeconds(30)).action -ceq 'ignore') 'repeats end after a few seconds'

$s = New-PairingSession $t0
foreach ($i in 1..4) { Assert-True ((Get-PairDecision $s (New-Find $wrongCode) '192.168.1.99' $t0).action -ceq 'wrong') "wrong code $i" }
$stop = Get-PairDecision $s (New-Find $wrongCode) '192.168.1.99' $t0
Assert-True ($stop.action -ceq 'stop' -and $s.result -ceq 'too_many_wrong') 'five wrong codes from one address stop pairing'
Assert-True ((Get-PairDecision $s (New-Find $s.code) '192.168.1.23' $t0).action -ceq 'ignore') 'after stopping, even the right code is refused'
$s = New-PairingSession $t0
foreach ($i in 1..19) { $null = Get-PairDecision $s (New-Find $wrongCode) ("10.0.0.$i") $t0 }
Assert-True ((Get-PairDecision $s (New-Find $wrongCode) '10.0.0.20' $t0).action -ceq 'stop') 'twenty wrong codes in total stop pairing'
$s = New-PairingSession $t0
Assert-True ((Get-PairDecision $s (New-Find $s.code) '192.168.1.23' $t0.AddMinutes(10)).action -ceq 'stop' -and $s.result -ceq 'expired') 'the code expires after 10 minutes'

# Pairing records: one per laptop, replaced when the same laptop pairs again, at most 10, removable by id.
$list = Add-PairingEntry @() '192.168.1.23' 'DESKTOP-KHOO' ('a' * 32) $t0
$list = Add-PairingEntry $list '192.168.1.40' 'OTHER-PC' ('b' * 32) $t0
$list = Add-PairingEntry $list '192.168.0.105' 'desktop-khoo' ('c' * 32) $t0
Assert-True (($list | ForEach-Object { $_.laptop_address }) -join ',' -ceq '192.168.1.40,192.168.0.105') 'a laptop pairing again keeps one record, at its new address'
$list = Remove-PairingEntry $list ('b' * 32)
Assert-True ($list.Count -eq 1 -and $list[0].pairing_id -ceq ('c' * 32)) 'a pairing is removed by its id'
Assert-True ((Remove-PairingEntry @() ('b' * 32)).Count -eq 0) 'removing from no pairings is fine'
$rejected = $false; try { $null = Add-PairingEntry @() '127.0.0.1' 'X' ('d' * 32) $t0 } catch { $rejected = $true }
Assert-True $rejected 'loopback cannot be recorded'
$full = @(); foreach ($i in 1..10) { $full = Add-PairingEntry $full "10.0.0.$i" "PC$i" ((New-Nonce)) $t0 }
$rejected = $false; try { $null = Add-PairingEntry $full '10.0.0.11' 'PC11' ((New-Nonce)) $t0 } catch { $rejected = $true }
Assert-True $rejected 'at most 10 laptops'
$roundTrip = ([ordered]@{ schema_version = 1; pairings = @($list) } | ConvertTo-Json -Depth 4) | ConvertFrom-Json
Assert-True (@($roundTrip.pairings).Count -eq 1 -and $roundTrip.pairings[0].laptop_name -ceq 'desktop-khoo') 'one record survives the JSON round trip as a list'

# The listener's network handling, over real UDP on this computer's own address (not loopback, which can never
# pair). Saving records and reading the identity are replaced for the test: no firewall rule, no file is written.
$own = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
    $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' -and (Test-ScannerAddress $_.IPAddress) } |
    ForEach-Object { $_.IPAddress }) | Select-Object -First 1
$script:Saved = @()
function Save-Pairings([object[]]$Pairings) { $script:Saved = @($Pairings | Where-Object { $null -ne $_ }) }
function Get-Pairings { $script:Saved }
function Get-ServerIdentity { [pscustomobject]@{ hostname = 'WIN-TEST'; machine_uuid = 'e5d10741-f200-4292-a099-e6be76032f4e' } }

# What the dashboard reads over WinRM: pairings is always a JSON list, also with none or one laptop.
foreach ($n in 0, 1, 2) {
    $script:Saved = @(); foreach ($i in 1..$n) { if ($n) { $script:Saved = Add-PairingEntry $script:Saved "10.0.0.$i" "PC$i" ((New-Nonce)) $t0 } }
    $json = Get-RemoteReport | ConvertTo-Json -Depth 4 -Compress
    Assert-True ($json -cmatch ('"pairings":\[' + $(if ($n) { '\{' } else { '\]' }))) "report lists $n pairing(s) as a JSON list"
    Assert-True ($json -cmatch '"machine_uuid":"e5d10741-f200-4292-a099-e6be76032f4e"') 'report carries the identity'
}
$script:Saved = @()

if ($own) {
    $server = New-Object Net.Sockets.UdpClient (New-Object Net.IPEndPoint([Net.IPAddress]::Parse($own), 0))
    $laptop = New-Object Net.Sockets.UdpClient (New-Object Net.IPEndPoint([Net.IPAddress]::Parse($own), 0))
    try {
        $laptop.Client.ReceiveTimeout = 3000
        $listener = [pscustomobject]@{ udp = $server; session = New-PairingSession ([DateTimeOffset]::UtcNow); done = @() }
        $nonce = New-Nonce
        $question = New-Find $listener.session.code $nonce
        [void]$laptop.Send($question, $question.Length, $server.Client.LocalEndPoint)
        Start-Sleep -Milliseconds 200
        $lines = @(Receive-PairPackets $listener)
        Assert-True ($lines.Count -eq 1 -and $lines[0] -like "Paired with DESKTOP-KHOO ($own)*") 'the listener pairs over UDP'
        $from = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
        $answer = [Text.Encoding]::UTF8.GetString($laptop.Receive([ref]$from)) | ConvertFrom-Json
        $expected = Get-PairingMac $listener.session.code @('found', 1, $nonce, $answer.nonce_s, 'WIN-TEST',
            'e5d10741-f200-4292-a099-e6be76032f4e', 5985, $answer.pairing_id)
        Assert-True ($answer.mac -ceq $expected -and $answer.nonce_l -ceq $nonce) 'the laptop receives a signed answer to its question'
        Assert-True ($script:Saved.Count -eq 1 -and $script:Saved[0].laptop_address -ceq $own -and
                     $script:Saved[0].pairing_id -ceq $answer.pairing_id) 'the laptop is recorded at the address it came from'
        [void]$laptop.Send($question, $question.Length, $server.Client.LocalEndPoint)  # Its answer was "lost".
        Start-Sleep -Milliseconds 200
        $null = Receive-PairPackets $listener
        $again = [Text.Encoding]::UTF8.GetString($laptop.Receive([ref]$from)) | ConvertFrom-Json
        Assert-True ($again.pairing_id -ceq $answer.pairing_id -and $script:Saved.Count -eq 1) 'a repeated question gets the same answer, no new record'
    } finally { $server.Close(); $laptop.Close() }
} else { Write-Host 'SKIP: no IPv4 network address for the UDP listener check.' }

if (([Environment]::OSVersion.Platform -eq 'Win32NT')) {
    $form = New-HelperForm
    $buttons = @($form.Controls | Where-Object { $_ -is [Windows.Forms.Button] } | ForEach-Object { $_.Text })
    Assert-True (($buttons -join '|') -ceq 'Check status|Start pairing|Revert changes') 'window has the three buttons'
    Assert-True (@($form.Controls | Where-Object { $_.Tag -is [scriptblock] }).Count -eq 3) 'each button carries its action'
    $form.Dispose()
}
Write-Host 'PASS: server access helper address, workstation, state, revert-plan and pairing-message checks; window builds (fixtures only).'
