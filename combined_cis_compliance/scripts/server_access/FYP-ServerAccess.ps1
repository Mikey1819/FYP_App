<#
Server access helper for the FYP hardening dashboard. Run it ON the Windows server to be checked, as an
administrator. "Start pairing" shows a one-time code; the laptop that types it into the dashboard is paired, and
one firewall rule lets only paired laptops reach WinRM (TCP 5985). PowerShell Remoting is turned on only if it was
off. Revert undoes exactly what the helper changed, from the state saved before its first change: anything that was
already on stays on. It never changes a CIS setting, never enables Basic login or unencrypted WinRM traffic, and
never handles a password. Design: docs/design/LAN_PAIRING_DESIGN.md.

  .\FYP-ServerAccess.ps1                                     window: Check status, Start pairing, Revert changes
  .\FYP-ServerAccess.ps1 -Action Pair                        pairing without a window (for example Server Core)
  .\FYP-ServerAccess.ps1 -Action Status
  .\FYP-ServerAccess.ps1 -Action Revert
The dashboard runs ListPairings, RemovePairing -PairingId <id> and CloseAccess over WinRM (JSON output).
FunctionsOnly loads the helpers for test_server_access.ps1 (same folder).
#>
[CmdletBinding()]
param(
    [ValidateSet('Window', 'Status', 'Pair', 'Revert', 'ListPairings', 'RemovePairing', 'CloseAccess')]
    [string]$Action = 'Window',
    [string]$PairingId,
    [switch]$FunctionsOnly
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RuleName = 'FYP-ServerAccess-WinRM'
$StateDir = Join-Path $env:ProgramData 'FYP-ServerAccess'
$StatePath = Join-Path $StateDir 'state.json'
$BuiltInRules = @('WINRM-HTTP-In-TCP', 'WINRM-HTTP-In-TCP-PUBLIC')
$PolicyKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$WinRmPort = 5985

# ---------------------------------------------------------------------------------------------------------------
# Pairing messages. The same rules as hardening/pairing.py in the dashboard; both are tested against the examples
# in pairing_vectors.json (same folder). The code is never sent: each side proves it knows the code with an
# HMAC-SHA256 signature keyed by it.
# ---------------------------------------------------------------------------------------------------------------
$PairingPort = 47815        # UDP, local network only.
$PairingVersion = 1
$PairingMaxMessage = 1024   # Bytes.
$FindKeys = @('laptop_name', 'mac', 'nonce_l', 'type', 'v')
$StrictUtf8 = New-Object Text.UTF8Encoding($false, $true)  # Throws on invalid bytes instead of guessing.

function Test-PairingCode([string]$Code) { return $Code -cmatch '^\d{9}$' }

function New-RandomBytes([int]$Count) {
    $bytes = New-Object byte[] $Count
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return ,$bytes
}

function ConvertTo-Hex([byte[]]$Bytes) { return (($Bytes | ForEach-Object { $_.ToString('x2') }) -join '') }

function New-PairingCode {
    # 9 random digits. Bytes 250-255 are skipped so every digit is equally likely.
    $digits = ''
    while ($digits.Length -lt 9) {
        foreach ($b in (New-RandomBytes 16)) { if ($b -lt 250 -and $digits.Length -lt 9) { $digits += [string]($b % 10) } }
    }
    return $digits
}

function New-Nonce { return ConvertTo-Hex (New-RandomBytes 16) }  # 128 random bits, used once.

function Get-PairingMac([string]$Code, [object[]]$Fields) {
    if (-not (Test-PairingCode $Code)) { throw 'The pairing code must be 9 digits.' }
    $hmac = New-Object Security.Cryptography.HMACSHA256 (, [Text.Encoding]::ASCII.GetBytes('FYP-PAIR-v1:' + $Code))
    try {
        $text = ($Fields | ForEach-Object { [string]$_ }) -join "`n"
        return ConvertTo-Hex $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($text))
    } finally { $hmac.Dispose() }
}

function Test-SameText([string]$A, [string]$B) {
    # Compares every character, so the time taken does not reveal how much of a signature was right.
    if ($A.Length -ne $B.Length) { return $false }
    $difference = 0
    for ($i = 0; $i -lt $A.Length; $i++) { $difference = $difference -bor ([int]$A[$i] -bxor [int]$B[$i]) }
    return $difference -eq 0
}

function Read-PairFind([byte[]]$Raw, [string]$Code) {
    # A laptop's question. Throws 'not_ours' for anything that is not a well-formed find message (not counted as a
    # guess), and 'wrong_code' when the format is right but the proof is not (counted as a wrong attempt).
    if ($null -eq $Raw -or $Raw.Length -gt $PairingMaxMessage) { throw 'not_ours' }
    try { $message = $StrictUtf8.GetString($Raw) | ConvertFrom-Json } catch { throw 'not_ours' }
    if ($null -eq $message -or $message -isnot [pscustomobject]) { throw 'not_ours' }
    # ForEach-Object, not .Name: under strict mode .Name on an empty list ('{}') throws a different error.
    $names = @($message.PSObject.Properties | ForEach-Object { $_.Name } | Sort-Object)
    if (($names -join ',') -cne ($FindKeys -join ',')) { throw 'not_ours' }
    if ($message.type -cne 'find' -or $message.v -isnot [int] -or $message.v -ne $PairingVersion) { throw 'not_ours' }
    foreach ($text in @($message.nonce_l, $message.laptop_name, $message.mac)) { if ($text -isnot [string]) { throw 'not_ours' } }
    if ($message.nonce_l -cnotmatch '^[0-9a-f]{32}$' -or $message.mac -cnotmatch '^[0-9a-f]{64}$' -or
        $message.laptop_name -cnotmatch '^[A-Za-z0-9._-]{1,63}$') { throw 'not_ours' }
    $expected = Get-PairingMac $Code @('find', $PairingVersion, $message.nonce_l, $message.laptop_name)
    if (-not (Test-SameText $expected $message.mac)) { throw 'wrong_code' }
    return $message
}

function New-PairFound([string]$Code, [string]$NonceL, [string]$HostName, [string]$MachineUuid, [int]$Port,
                       [string]$PairingId, [string]$NonceS, [string]$Os, [string]$OsName, [string]$OsVersion) {
    # The answer to one checked question: who this server is, which system it runs (so the administrator never has
    # to say it), and the proof that it knows the code too.
    $uuid = ([guid]$MachineUuid).ToString()
    $message = [ordered]@{ v = $PairingVersion; type = 'found'; nonce_l = $NonceL; nonce_s = $NonceS
        hostname = $HostName; machine_uuid = $uuid; port = $Port; pairing_id = $PairingId
        os = $Os; os_name = $OsName; os_version = $OsVersion }
    $message.mac = Get-PairingMac $Code @('found', $PairingVersion, $NonceL, $NonceS, $HostName, $uuid, $Port, $PairingId,
                                          $Os, $OsName, $OsVersion)
    return ,[Text.Encoding]::UTF8.GetBytes(($message | ConvertTo-Json -Compress))
}

function Test-ScannerAddress([string]$Address) {
    # Exactly one IPv4 unicast address (the admin laptop): never a range, "Any", loopback or multicast.
    $parsed = $null
    if ([string]::IsNullOrWhiteSpace($Address) -or -not [Net.IPAddress]::TryParse($Address.Trim(), [ref]$parsed) -or
        $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $Address.Trim() -cne $parsed.ToString()) {
        return $false
    }
    $first = $parsed.GetAddressBytes()[0]
    return -not ($parsed.ToString() -in @('0.0.0.0', '255.255.255.255') -or $first -eq 127 -or $first -ge 224)
}

function Assert-ServerOs($Os) {
    # The dashboard scans Windows Server only; this also keeps the helper off the admin laptop itself.
    if ($Os.ProductType -eq 1) { throw 'This is a workstation. Run the helper on the server to be scanned, not on the laptop.' }
}

function Test-Administrator {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ServerState {
    # Read-only snapshot of everything the helper may change, so Revert can put back exactly this.
    $service = Get-Service WinRM
    $startMode = [string](Get-CimInstance Win32_Service -Filter "Name='WinRM'" -OperationTimeoutSec 15).StartMode
    $listener = $false
    if ($service.Status -eq 'Running') {
        $listener = [bool]@(Get-ChildItem WSMan:\localhost\Listener -ErrorAction SilentlyContinue |
            Where-Object { $_.Keys -contains 'Transport=HTTP' }).Count
    }
    $rules = [ordered]@{}
    foreach ($name in $BuiltInRules) {
        $rule = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
        $rules[$name] = if ($rule) { [string]$rule.Enabled -eq 'True' } else { $null }
    }
    $policy = Get-ItemProperty $PolicyKey -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue
    return [pscustomobject]@{
        winrm_running = $service.Status -eq 'Running'; winrm_start_mode = $startMode; http_listener = $listener
        builtin_rules = $rules; token_filter_policy = $(if ($policy) { [int]$policy.LocalAccountTokenFilterPolicy } else { $null })
        helper_rule = [bool](Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue)
    }
}

function New-AccessState($Before, [string]$Address, [DateTimeOffset]$Now) {
    $remotingOn = [bool]($Before.winrm_running -and $Before.http_listener)
    return [ordered]@{
        schema_version = 1; created_at = $Now.ToString('o'); scanner_address = $Address; rule_name = $RuleName
        remoting_was_on = $remotingOn; helper_enabled_remoting = -not $remotingOn
        winrm_running = [bool]$Before.winrm_running; winrm_start_mode = [string]$Before.winrm_start_mode
        builtin_rules = $Before.builtin_rules; token_filter_policy = $Before.token_filter_policy
    }
}

function Get-RevertPlan($State) {
    # Only what the helper changed. If remoting was already on, the helper added one rule and nothing else.
    $steps = @('remove_rule')
    if ($State.helper_enabled_remoting) {
        $steps += 'disable_remoting', 'remove_listener', 'restore_builtin_rules', 'restore_token_filter', 'restore_service'
    }
    return $steps
}

function Set-BuiltInRules($Rules) {
    foreach ($property in $Rules.PSObject.Properties) {
        if ($property.Name -notin $BuiltInRules) { continue }  # Only the two built-in WinRM rules, whatever the file holds.
        if (-not (Get-NetFirewallRule -Name $property.Name -ErrorAction SilentlyContinue)) { continue }
        if ($property.Value -eq $true) { Enable-NetFirewallRule -Name $property.Name }
        else { Disable-NetFirewallRule -Name $property.Name }
    }
}

function Set-TokenFilterPolicy($Value) {
    # Enable-PSRemoting may set this; the helper never leaves it wider than it was.
    if ($null -eq $Value) { Remove-ItemProperty $PolicyKey -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue }
    else { Set-ItemProperty $PolicyKey -Name LocalAccountTokenFilterPolicy -Value ([int]$Value) -Type DWord }
}

# ---------------------------------------------------------------------------------------------------------------
# Paired laptops. Each laptop that paired is one record in pairings.json, and the
# firewall rule lets exactly those addresses reach WinRM. The dashboard can list and remove them over WinRM.
# ---------------------------------------------------------------------------------------------------------------
$PairingsPath = Join-Path $StateDir 'pairings.json'
$PairingRuleName = 'FYP-ServerAccess-Pairing'
$MaxPairings = 10
$CodeMinutes = 10          # A code is valid this long.
$WrongPerAddress = 5       # Wrong codes from one address before pairing stops.
$WrongTotal = 20           # Wrong codes in total before pairing stops.
$RepeatSeconds = 10        # After pairing, a repeated question (lost answer) is answered again for this long.

function New-PrivateFolder {
    # The saved state and pairing records are readable by administrators and SYSTEM only, not by ordinary users.
    if (-not (Test-Path $StateDir)) { [void][IO.Directory]::CreateDirectory($StateDir) }
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-32-544', 'S-1-5-18')) {  # Administrators, SYSTEM
        $who = New-Object Security.Principal.SecurityIdentifier $sid
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($who, 'FullControl',
            'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    Set-Acl -Path $StateDir -AclObject $acl
}

function Get-Pairings {
    # Callers wrap the result in @(): PowerShell returns no records as nothing and one record as itself.
    if (-not (Test-Path $PairingsPath)) { return }
    $data = Get-Content $PairingsPath -Raw | ConvertFrom-Json
    $data.pairings | Where-Object { $null -ne $_ }
}

function Add-PairingEntry([object[]]$Pairings, [string]$Address, [string]$LaptopName, [string]$PairingId, [DateTimeOffset]$Now) {
    # The same laptop (by name) or the same address pairing again replaces its old record: one record per laptop.
    if (-not (Test-ScannerAddress $Address)) { throw "'$Address' is not a single IPv4 address of a laptop." }
    $kept = @($Pairings | Where-Object { $null -ne $_ -and $_.laptop_name -ine $LaptopName -and $_.laptop_address -cne $Address })
    if ($kept.Count -ge $MaxPairings) { throw "At most $MaxPairings laptops can be paired. Remove one first." }
    $entry = [pscustomobject][ordered]@{ pairing_id = $PairingId; laptop_address = $Address; laptop_name = $LaptopName
                                         paired_at = $Now.ToString('o') }
    return ,@($kept + $entry)
}

function Remove-PairingEntry([object[]]$Pairings, [string]$PairingId) {
    return ,@($Pairings | Where-Object { $null -ne $_ -and $_.pairing_id -cne $PairingId })
}

function Set-PairedRule([string[]]$Addresses) {
    # One rule, listing only the paired laptops' addresses; no paired laptop means no rule at all.
    $Addresses = @($Addresses | Where-Object { Test-ScannerAddress $_ } | Sort-Object -Unique)
    $rule = Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue
    if ($Addresses.Count -eq 0) {
        if ($rule) { Remove-NetFirewallRule -Name $RuleName }
    } elseif ($rule) {
        Set-NetFirewallRule -Name $RuleName -RemoteAddress $Addresses
    } else {
        New-NetFirewallRule -Name $RuleName -DisplayName 'FYP scanner access: WinRM from paired laptops' `
            -Group 'FYP Server Access' -Direction Inbound -Protocol TCP -LocalPort $WinRmPort -RemoteAddress $Addresses `
            -Profile Any -Action Allow | Out-Null
    }
}

function Save-Pairings([object[]]$Pairings) {
    New-PrivateFolder
    $Pairings = @($Pairings | Where-Object { $null -ne $_ })
    $doc = [ordered]@{ schema_version = 1; pairings = $Pairings }
    Set-Content -Path $PairingsPath -Value ($doc | ConvertTo-Json -Depth 4) -Encoding UTF8
    Set-PairedRule @($Pairings | ForEach-Object { $_.laptop_address })
}

function Open-ServerAccess {
    # The first change on this server: save how it is now, then turn PowerShell Remoting on if it was off.
    # Later calls change nothing here, so Revert always returns the server to how it was before the very first one.
    if (-not (Test-Administrator)) { throw 'Run the helper as administrator.' }
    Assert-ServerOs (Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 15)
    if (Test-Path $StatePath) { return @() }
    $before = Get-ServerState
    $state = New-AccessState $before '' ([DateTimeOffset]::UtcNow)
    New-PrivateFolder
    Set-Content -Path $StatePath -Value ($state | ConvertTo-Json -Depth 4) -Encoding UTF8  # Saved before any change.
    $done = @("Saved the current state to $StatePath.")
    if ($state.helper_enabled_remoting) {
        Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null
        # Enable-PSRemoting opens the built-in WinRM rules to wide ranges; put them back so only the
        # paired-laptops rule lets traffic in.
        Set-BuiltInRules ([pscustomobject]$state.builtin_rules)
        Set-TokenFilterPolicy $state.token_filter_policy
        $done += 'Turned on PowerShell Remoting (WinRM service and HTTP listener), keeping the built-in WinRM firewall rules as they were.'
    } else { $done += 'PowerShell Remoting was already on; left it as it was.' }
    return $done
}

function ConvertTo-OsName([string]$Caption) {
    # The system's full name as the dashboard accepts it: plain printable ASCII, at most 100 characters.
    $name = ($Caption -replace '[^\x20-\x7E]', '').Trim()
    if ($name.Length -gt 100) { $name = $name.Substring(0, 100).Trim() }
    if (-not $name) { $name = 'Windows' }
    return $name
}

function Get-ServerIdentity {
    # Who this server is, and which operating system it runs. The dashboard reads the system from the pairing
    # answer and shows it as a note (hardening/system_detect.py), so nobody has to type it.
    $product = Get-CimInstance Win32_ComputerSystemProduct -OperationTimeoutSec 15
    $os = Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 15
    return [pscustomobject]@{ hostname = $env:COMPUTERNAME; machine_uuid = ([guid]$product.UUID).ToString()
                              os = 'windows'; os_name = ConvertTo-OsName ([string]$os.Caption); os_version = [string]$os.Version }
}

# ---------------------------------------------------------------------------------------------------------------
# Pairing session: one code, one listener, until a laptop pairs, the code expires or too many wrong codes arrive.
# Get-PairDecision only decides (no network, no firewall), so the tests can check every rule with fixtures.
# ---------------------------------------------------------------------------------------------------------------
function New-PairingSession([DateTimeOffset]$Now) {
    return [pscustomobject]@{ code = New-PairingCode; expires = $Now.AddMinutes($CodeMinutes); wrong = @{}; wrong_seen = @{}
        wrong_total = 0; done = $false; result = ''; accepted_nonce = ''; accepted_address = ''; reply = $null
        closes_at = $null }
}

function Get-PairDecision($Session, [byte[]]$Raw, [string]$Address, [DateTimeOffset]$Now) {
    # Returns action: ignore | wrong | stop | accept | repeat.
    if ($Session.done) {
        # Already paired: a laptop that did not receive the answer asks again with the same question.
        if ($Session.result -eq 'paired' -and $Now -lt $Session.closes_at -and $Address -ceq $Session.accepted_address) {
            try { $find = Read-PairFind $Raw $Session.code } catch { return [pscustomobject]@{ action = 'ignore' } }
            if ($find.nonce_l -ceq $Session.accepted_nonce) { return [pscustomobject]@{ action = 'repeat' } }
        }
        return [pscustomobject]@{ action = 'ignore' }
    }
    if ($Now -ge $Session.expires) {
        $Session.done = $true; $Session.result = 'expired'
        return [pscustomobject]@{ action = 'stop'; reason = 'The code expired. Click Start pairing for a new code.' }
    }
    if (-not (Test-ScannerAddress $Address)) { return [pscustomobject]@{ action = 'ignore' } }
    try { $find = Read-PairFind $Raw $Session.code }
    catch {
        if ($_.Exception.Message -ne 'wrong_code') { return [pscustomobject]@{ action = 'ignore' } }
        # The dashboard sends each question 3 times in case one is lost: a byte-identical repeat from the same address
        # is one attempt. A different guess has a different signature, so it always counts.
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $attempt = $Address + '|' + [BitConverter]::ToString($sha.ComputeHash($Raw)) } finally { $sha.Dispose() }
        if ($Session.wrong_seen.ContainsKey($attempt)) { return [pscustomobject]@{ action = 'ignore' } }
        $Session.wrong_seen[$attempt] = $true
        $count = 1 + [int]$Session.wrong[$Address]
        $Session.wrong[$Address] = $count
        $Session.wrong_total++
        if ($count -ge $WrongPerAddress -or $Session.wrong_total -ge $WrongTotal) {
            $Session.done = $true; $Session.result = 'too_many_wrong'
            return [pscustomobject]@{ action = 'stop'; reason = "Too many wrong codes (last from $Address). Pairing stopped; click Start pairing for a new code." }
        }
        return [pscustomobject]@{ action = 'wrong'; reason = "Wrong code from $Address ($count of $WrongPerAddress)." }
    }
    $Session.done = $true; $Session.result = 'paired'
    $Session.accepted_nonce = $find.nonce_l; $Session.accepted_address = $Address
    $Session.closes_at = $Now.AddSeconds($RepeatSeconds)
    return [pscustomobject]@{ action = 'accept'; find = $find }
}

function Complete-Pairing($Session, $Find, [string]$Address) {
    # Record the laptop, open WinRM to its address, and build the signed answer.
    $pairingId = New-Nonce
    Save-Pairings (Add-PairingEntry @(Get-Pairings) $Address $Find.laptop_name $pairingId ([DateTimeOffset]::UtcNow))
    $me = Get-ServerIdentity
    $Session.reply = New-PairFound $Session.code $Find.nonce_l $me.hostname $me.machine_uuid $WinRmPort $pairingId (New-Nonce) `
        $me.os $me.os_name $me.os_version
    return "Paired with $($Find.laptop_name) ($Address). Only paired laptops can reach WinRM on this server."
}

function Start-PairingListener {
    # Opens UDP $PairingPort to the local subnet only, for as long as this pairing runs.
    $done = Open-ServerAccess
    if (-not (Get-NetFirewallRule -Name $PairingRuleName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name $PairingRuleName -DisplayName 'FYP server access: pairing (temporary)' `
            -Group 'FYP Server Access' -Direction Inbound -Protocol UDP -LocalPort $PairingPort `
            -RemoteAddress LocalSubnet -Profile Any -Action Allow | Out-Null
    }
    try { $udp = New-Object Net.Sockets.UdpClient($PairingPort) }
    catch {
        Remove-NetFirewallRule -Name $PairingRuleName -ErrorAction SilentlyContinue
        throw "UDP port $PairingPort is in use. Is another helper window already pairing?"
    }
    return [pscustomobject]@{ udp = $udp; session = New-PairingSession ([DateTimeOffset]::UtcNow); done = $done }
}

function Stop-PairingListener($Listener) {
    if ($Listener -and $Listener.udp) { $Listener.udp.Close(); $Listener.udp = $null }
    if (Get-NetFirewallRule -Name $PairingRuleName -ErrorAction SilentlyContinue) { Remove-NetFirewallRule -Name $PairingRuleName }
}

function Receive-PairPackets($Listener) {
    # Handles every waiting message; called a few times a second by the window's timer or the console loop.
    $session = $Listener.session
    $lines = @()
    while ($Listener.udp -and $Listener.udp.Available -gt 0) {
        $remote = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
        $raw = $Listener.udp.Receive([ref]$remote)
        $address = $remote.Address.ToString()
        $decision = Get-PairDecision $session $raw $address ([DateTimeOffset]::UtcNow)
        switch ($decision.action) {
            'wrong' { $lines += $decision.reason }
            'stop' { $lines += $decision.reason }
            'accept' {
                $lines += Complete-Pairing $session $decision.find $address
                [void]$Listener.udp.Send($session.reply, $session.reply.Length, $remote)
            }
            'repeat' { [void]$Listener.udp.Send($session.reply, $session.reply.Length, $remote) }
        }
    }
    if (-not $session.done -and [DateTimeOffset]::UtcNow -ge $session.expires) {
        $session.done = $true; $session.result = 'expired'
        $lines += 'The code expired. Click Start pairing for a new code.'
    }
    return $lines
}

function Test-ListenerFinished($Listener) {
    # Paired: keep answering repeats for a few seconds. Expired or stopped: finished at once.
    $s = $Listener.session
    return $s.done -and ($s.result -ne 'paired' -or [DateTimeOffset]::UtcNow -ge $s.closes_at)
}

# ---------------------------------------------------------------------------------------------------------------
# Status, Revert, and the actions the dashboard runs over WinRM (JSON output).
# ---------------------------------------------------------------------------------------------------------------
function Get-StatusLines {
    $os = Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 15
    $addresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
        ForEach-Object { "$($_.IPAddress) ($($_.InterfaceAlias))" })
    $lines = @('THIS SERVER', "  Computer name : $env:COMPUTERNAME", "  Addresses     : $($addresses -join ', ')",
        "  System        : $($os.Caption)", '', 'ACCESS')
    if (-not (Test-Administrator)) { return $lines + '  Run as administrator to see the WinRM and firewall state.' }
    $state = Get-ServerState
    $lines += "  WinRM service : $(if ($state.winrm_running) { 'running' } else { 'stopped' }) ($($state.winrm_start_mode))"
    $lines += "  HTTP listener : $(if ($state.http_listener) { 'yes' } else { 'no' })"
    $pairings = @(Get-Pairings)
    if ($pairings.Count) {
        $lines += "  Paired laptops (they can reach WinRM on TCP $WinRmPort):"
        foreach ($p in $pairings) { $lines += "    $($p.laptop_name)  $($p.laptop_address)  since $($p.paired_at)" }
    } else { $lines += '  Paired laptops: none' }
    if (Test-Path $StatePath) {
        $saved = Get-Content $StatePath -Raw | ConvertFrom-Json
        $lines += "  Changed since : $($saved.created_at) (click Revert when you have finished)"
    }
    if ($state.winrm_running) {
        $unencrypted = (Get-Item WSMan:\localhost\Service\AllowUnencrypted).Value
        $basic = (Get-Item WSMan:\localhost\Service\Auth\Basic).Value
        if ($unencrypted -eq 'true' -or $basic -eq 'true') {
            $lines += '  WARNING       : WinRM allows unencrypted traffic or Basic login; the helper does not need either.'
        }
    }
    return $lines
}

function Invoke-Revert {
    if (-not (Test-Administrator)) { throw 'Run the helper as administrator.' }
    $extra = @()
    if (Get-NetFirewallRule -Name $PairingRuleName -ErrorAction SilentlyContinue) {
        Remove-NetFirewallRule -Name $PairingRuleName; $extra += 'Removed the temporary pairing rule.'
    }
    if (Test-Path $PairingsPath) { Remove-Item $PairingsPath -Force; $extra += 'Deleted the pairing records.' }
    if (-not (Test-Path $StatePath)) {
        if (Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue) {
            Remove-NetFirewallRule -Name $RuleName
            return $extra + @("No saved state; removed the leftover rule '$RuleName'.")
        }
        return $extra + @('Nothing else to revert: the helper has not changed this server.')
    }
    $state = Get-Content $StatePath -Raw | ConvertFrom-Json
    $done = $extra
    foreach ($step in Get-RevertPlan $state) {
        switch ($step) {
            'remove_rule' {
                if (Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue) { Remove-NetFirewallRule -Name $RuleName }
                $done += "Removed firewall rule '$RuleName'."
            }
            'disable_remoting' { Disable-PSRemoting -Force -WarningAction SilentlyContinue; $done += 'Turned PowerShell Remoting off.' }
            'remove_listener' {
                if ((Get-Service WinRM).Status -eq 'Running') {
                    Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -contains 'Transport=HTTP' } |
                        Remove-Item -Recurse -Force
                }
                $done += 'Removed the WinRM HTTP listener.'
            }
            'restore_builtin_rules' { Set-BuiltInRules $state.builtin_rules; $done += 'Put the built-in WinRM firewall rules back as they were.' }
            'restore_token_filter' { Set-TokenFilterPolicy $state.token_filter_policy; $done += 'Put LocalAccountTokenFilterPolicy back as it was.' }
            'restore_service' {
                if (-not $state.winrm_running) { Stop-Service WinRM -Force }
                $mode = @{ Auto = 'Automatic'; Manual = 'Manual'; Disabled = 'Disabled' }[[string]$state.winrm_start_mode]
                if ($mode) { Set-Service WinRM -StartupType $mode }
                $done += "WinRM service back to $(if ($state.winrm_running) { 'running' } else { 'stopped' }), start type $($state.winrm_start_mode)."
            }
        }
    }
    Remove-Item $StatePath -Force
    return $done + 'The server is back to how it was before the helper first changed it.'
}

function Get-RemoteReport {
    # What the dashboard reads over WinRM: who this server is, and which laptops are paired.
    $me = Get-ServerIdentity
    $helperEnabled = $false
    if (Test-Path $StatePath) { $helperEnabled = [bool](Get-Content $StatePath -Raw | ConvertFrom-Json).helper_enabled_remoting }
    return [ordered]@{ hostname = $me.hostname; machine_uuid = $me.machine_uuid; pairings = @(Get-Pairings)
                       helper_enabled_remoting = $helperEnabled }
}

function Invoke-RemoteAction([string]$Name, [string]$Id) {
    # Run by the dashboard over WinRM (the fixed text of this file, typed parameters). Always answers one JSON line.
    if (-not (Test-Administrator)) { throw 'An administrator token is needed.' }
    switch ($Name) {
        'ListPairings' { }
        'RemovePairing' {
            if ($Id -cnotmatch '^[0-9a-f]{32}$') { throw 'Invalid pairing id.' }
            Save-Pairings (Remove-PairingEntry @(Get-Pairings) $Id)
        }
        'CloseAccess' {
            # Every laptop loses access; the established session that sent this keeps running until it ends.
            # Turning Remoting itself off is left to Revert on the server, because it would cut this session midway.
            Save-Pairings @()
            if (Get-NetFirewallRule -Name $PairingRuleName -ErrorAction SilentlyContinue) { Remove-NetFirewallRule -Name $PairingRuleName }
        }
    }
    return (Get-RemoteReport | ConvertTo-Json -Depth 4 -Compress)
}

# ---------------------------------------------------------------------------------------------------------------
# The window.
# ---------------------------------------------------------------------------------------------------------------
$Remarks = @(
    'Run this on the server you want checked, not on the laptop.',
    'Start pairing shows a one-time code. Type it into the dashboard on the laptop (Servers > Add a server).',
    'Only laptops that typed the right code can reach WinRM here; the dashboard lists them and can disconnect them.',
    'This helper never changes a CIS setting, never enables Basic login or unencrypted WinRM, never sees a password.',
    'Click Revert changes when you have finished checking this server.'
) -join "`r`n"

function New-HelperForm {
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    $form = New-Object Windows.Forms.Form -Property @{
        Text = 'FYP Server Access Helper'; Size = New-Object Drawing.Size(760, 640); StartPosition = 'CenterScreen'
        Font = New-Object Drawing.Font('Segoe UI', 9.5); MinimumSize = New-Object Drawing.Size(640, 560)
    }
    $intro = New-Object Windows.Forms.Label -Property @{
        Text = $Remarks; Location = New-Object Drawing.Point(12, 10); Size = New-Object Drawing.Size(720, 92)
        Anchor = 'Top, Left, Right'
    }
    $script:CodeLabel = New-Object Windows.Forms.Label -Property @{
        Text = ''; Location = New-Object Drawing.Point(12, 150); Size = New-Object Drawing.Size(720, 56)
        Font = New-Object Drawing.Font('Consolas', 28, [Drawing.FontStyle]::Bold); Anchor = 'Top, Left, Right'
    }
    $script:LogBox = New-Object Windows.Forms.TextBox -Property @{
        Multiline = $true; ReadOnly = $true; ScrollBars = 'Vertical'; Location = New-Object Drawing.Point(12, 215)
        Size = New-Object Drawing.Size(720, 370); Anchor = 'Top, Bottom, Left, Right'; Font = New-Object Drawing.Font('Consolas', 9.5)
    }
    $script:Listener = $null
    $script:PairButton = $null
    # Script scope: these are used by the button and timer handlers after this function has returned.
    $script:Timer = New-Object Windows.Forms.Timer -Property @{ Interval = 250 }
    $script:Log = { param([string[]]$Lines) if ($Lines.Count) {
        $script:LogBox.AppendText((@("[$(Get-Date -Format 'HH:mm:ss')]") + $Lines + '') -join "`r`n") } }
    $script:StopPairing = {
        $script:Timer.Stop(); Stop-PairingListener $script:Listener; $script:Listener = $null; $script:CodeLabel.Text = ''
        if ($script:PairButton) { $script:PairButton.Text = 'Start pairing' }  # The same button starts it again.
    }
    $script:Timer.Add_Tick({
        if (-not $script:Listener) { $script:Timer.Stop(); return }  # Pairing was stopped; nothing to listen to.
        try {
            & $script:Log @(Receive-PairPackets $script:Listener)
            $left = [int]($script:Listener.session.expires - [DateTimeOffset]::UtcNow).TotalSeconds
            if (-not $script:Listener.session.done) {
                $script:CodeLabel.Text = 'Code: ' + (($script:Listener.session.code -replace '(\d{3})(\d{3})(\d{3})', '$1-$2-$3')) +
                    "   ($([Math]::Max(0, [int]($left / 60))) min left)"
            }
            if (Test-ListenerFinished $script:Listener) { & $script:StopPairing; & $script:Log @('Pairing closed.') }
        } catch { & $script:StopPairing; & $script:Log @('ERROR: ' + $_.Exception.Message) }
    })
    $buttons = @(
        @{ Text = 'Check status'; X = 12; Run = { Get-StatusLines } },
        @{ Text = 'Start pairing'; X = 170; Run = {
            if ($script:Listener) { & $script:StopPairing; return @('Pairing stopped. The code no longer works.') }
            $script:Listener = Start-PairingListener
            $script:Timer.Start()
            $script:PairButton.Text = 'Stop pairing'  # While a code is shown, this button withdraws it.
            return @($script:Listener.done) + "Waiting for a laptop on UDP $PairingPort (local network only). The code works once, for $CodeMinutes minutes." } },
        @{ Text = 'Revert changes'; X = 328; Run = {
            $answer = [Windows.Forms.MessageBox]::Show('Undo everything this helper changed on this server, and disconnect every paired laptop?',
                'Revert', 'YesNo', 'Question')
            if ($answer -eq 'Yes') { if ($script:Listener) { & $script:StopPairing }; Invoke-Revert } } })
    $form.Controls.AddRange(@($intro, $script:CodeLabel, $script:LogBox))
    foreach ($spec in $buttons) {
        # The action travels in Tag: a GetNewClosure handler could not see this script's functions.
        $button = New-Object Windows.Forms.Button -Property @{
            Text = $spec.Text; Tag = $spec.Run; Location = New-Object Drawing.Point($spec.X, 108); Size = New-Object Drawing.Size(150, 32)
        }
        $button.Add_Click({
            $owner = $this.FindForm()
            $owner.Cursor = [Windows.Forms.Cursors]::WaitCursor
            try { $lines = @(& $this.Tag) } catch { $lines = @('ERROR: ' + $_.Exception.Message) }
            finally { $owner.Cursor = [Windows.Forms.Cursors]::Default }
            & $script:Log $lines
        })
        if ($spec.Text -eq 'Start pairing') { $script:PairButton = $button }
        $form.Controls.Add($button)
    }
    $form.Add_Shown({ & $script:Log @(Get-StatusLines) })
    $form.Add_FormClosing({ if ($script:Listener) { & $script:StopPairing } })
    return $form
}

function Invoke-ConsolePairing {
    # The same pairing without a window (for example on Server Core). Ctrl+C stops it.
    $listener = Start-PairingListener
    try {
        $listener.done | ForEach-Object { Write-Host $_ }
        Write-Host ("Pairing code: " + ($listener.session.code -replace '(\d{3})(\d{3})(\d{3})', '$1-$2-$3') +
                    "  (valid $CodeMinutes minutes, works once). Type it into the dashboard on the laptop.")
        while (-not (Test-ListenerFinished $listener)) {
            Receive-PairPackets $listener | ForEach-Object { Write-Host $_ }
            Start-Sleep -Milliseconds 250
        }
    } finally { Stop-PairingListener $listener }
}

if ($FunctionsOnly) { return }
switch ($Action) {
    'Status' { Get-StatusLines }
    'Pair' { Invoke-ConsolePairing }
    'Revert' { Invoke-Revert }
    'ListPairings' { Invoke-RemoteAction 'ListPairings' '' }
    'RemovePairing' { Invoke-RemoteAction 'RemovePairing' $PairingId }
    'CloseAccess' { Invoke-RemoteAction 'CloseAccess' '' }
    default { $form = New-HelperForm; [void]$form.ShowDialog(); $form.Dispose() }
}
