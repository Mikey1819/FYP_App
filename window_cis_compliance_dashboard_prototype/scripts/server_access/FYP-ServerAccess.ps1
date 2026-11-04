<#
Server access helper for the FYP hardening dashboard. Run it ON the Windows server to be scanned, as an
administrator. Allow lets one scanner (laptop) address reach WinRM (TCP 5985) through one narrow firewall
rule, and turns PowerShell Remoting on only if it was off. Revert undoes exactly what Allow changed, from
the state Allow saved first: anything that was already on stays on. It never changes a CIS setting, never
enables Basic login or unencrypted WinRM traffic, and never handles a password.
Optional: only for scanning by network address. The lab VM through the port forward needs none of this.

  .\FYP-ServerAccess.ps1                                     window with three buttons
  .\FYP-ServerAccess.ps1 -Action Status
  .\FYP-ServerAccess.ps1 -Action Allow -ScannerAddress 192.168.56.1
  .\FYP-ServerAccess.ps1 -Action Revert
FunctionsOnly loads the helpers for test_server_access.ps1 (same folder).
#>
[CmdletBinding()]
param(
    [ValidateSet('Window', 'Status', 'Allow', 'Revert')][string]$Action = 'Window',
    [string]$ScannerAddress,
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
                       [string]$PairingId, [string]$NonceS) {
    # The answer to one checked question: who this server is, and the proof that it knows the code too.
    $uuid = ([guid]$MachineUuid).ToString()
    $message = [ordered]@{ v = $PairingVersion; type = 'found'; nonce_l = $NonceL; nonce_s = $NonceS
        hostname = $HostName; machine_uuid = $uuid; port = $Port; pairing_id = $PairingId }
    $message.mac = Get-PairingMac $Code @('found', $PairingVersion, $NonceL, $NonceS, $HostName, $uuid, $Port, $PairingId)
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
    # Read-only snapshot of everything Allow may change, so Revert can put back exactly this.
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
    # Only what Allow changed. If remoting was already on, the helper added one rule and nothing else.
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

function Get-StatusLines {
    $os = Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 15
    $uuid = ([guid](Get-CimInstance Win32_ComputerSystemProduct -OperationTimeoutSec 15).UUID).ToString()
    $addresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
        ForEach-Object { "$($_.IPAddress) ($($_.InterfaceAlias))" })
    $lines = @('THIS SERVER (type these into the dashboard connection form)',
        "  Computer name : $env:COMPUTERNAME", "  Machine UUID  : $uuid",
        "  WinRM host    : one of $($addresses -join ', ')", "  Port          : $WinRmPort",
        '  Account       : the built-in Administrator', "  System        : $($os.Caption)", '', 'ACCESS')
    if (-not (Test-Administrator)) { return $lines + '  Run as administrator to see the WinRM and firewall state.' }
    $state = Get-ServerState
    $lines += "  WinRM service : $(if ($state.winrm_running) { 'running' } else { 'stopped' }) ($($state.winrm_start_mode))"
    $lines += "  HTTP listener : $(if ($state.http_listener) { 'yes' } else { 'no' })"
    $rule = Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue
    if ($rule) {
        $from = ($rule | Get-NetFirewallAddressFilter).RemoteAddress -join ', '
        $lines += "  Scanner rule  : allows TCP $WinRmPort from $from"
    } else { $lines += '  Scanner rule  : none' }
    if (Test-Path $StatePath) {
        $saved = Get-Content $StatePath -Raw | ConvertFrom-Json
        $lines += "  Allowed since : $($saved.created_at) (use Revert when scanning is finished)"
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

function Invoke-Allow([string]$Address) {
    if (-not (Test-Administrator)) { throw 'Run the helper as administrator.' }
    Assert-ServerOs (Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 15)
    if (-not (Test-ScannerAddress $Address)) { throw "'$Address' is not a single IPv4 address of the scanning laptop." }
    if (Test-Path $StatePath) { throw 'Access is already allowed. Use Revert first, then Allow again.' }
    $Address = $Address.Trim()
    $before = Get-ServerState
    $state = New-AccessState $before $Address ([DateTimeOffset]::UtcNow)
    # Saved before any change, so Revert works even if a later step fails.
    [void][IO.Directory]::CreateDirectory($StateDir)
    Set-Content -Path $StatePath -Value ($state | ConvertTo-Json -Depth 4) -Encoding UTF8
    $done = @("Saved the current state to $StatePath.")
    if ($state.helper_enabled_remoting) {
        Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null
        # Enable-PSRemoting opens the built-in WinRM rules to wide ranges; put them back so only the
        # scanner rule below lets traffic in.
        Set-BuiltInRules ([pscustomobject]$state.builtin_rules)
        Set-TokenFilterPolicy $state.token_filter_policy
        $done += 'Turned on PowerShell Remoting (WinRM service and HTTP listener), keeping the built-in WinRM firewall rules as they were.'
    } else { $done += 'PowerShell Remoting was already on; left it as it was.' }
    if (Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue) { Remove-NetFirewallRule -Name $RuleName }
    New-NetFirewallRule -Name $RuleName -DisplayName "FYP scanner access: WinRM from $Address" -Group 'FYP Server Access' `
        -Direction Inbound -Protocol TCP -LocalPort $WinRmPort -RemoteAddress $Address -Profile Any -Action Allow | Out-Null
    $done += "Added firewall rule '$RuleName': only $Address may reach TCP $WinRmPort."
    return $done + 'You can now connect from the dashboard. Click Revert when scanning is finished.'
}

function Invoke-Revert {
    if (-not (Test-Administrator)) { throw 'Run the helper as administrator.' }
    if (-not (Test-Path $StatePath)) {
        if (Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue) {
            Remove-NetFirewallRule -Name $RuleName
            return @("No saved state; removed the leftover rule '$RuleName'.")
        }
        return @('Nothing to revert: the helper has not changed this server.')
    }
    $state = Get-Content $StatePath -Raw | ConvertFrom-Json
    $done = @()
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
    return $done + 'The server is back to how it was before Allow.'
}

function New-HelperForm {
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    $form = New-Object Windows.Forms.Form -Property @{
        Text = 'FYP Server Access Helper'; Size = New-Object Drawing.Size(720, 560); StartPosition = 'CenterScreen'
        Font = New-Object Drawing.Font('Segoe UI', 9.5); MinimumSize = New-Object Drawing.Size(600, 460)
    }
    $intro = New-Object Windows.Forms.Label -Property @{
        Text = "Lets the scanning laptop reach this server over WinRM, and undoes it afterwards.`r`n" +
               "1. Type the laptop's address and click Allow.  2. Scan from the dashboard.  3. Click Revert."
        Location = New-Object Drawing.Point(12, 10); Size = New-Object Drawing.Size(680, 40); Anchor = 'Top, Left, Right'
    }
    $label = New-Object Windows.Forms.Label -Property @{ Text = 'Laptop (scanner) IPv4 address:'; Location = New-Object Drawing.Point(12, 60); AutoSize = $true }
    $script:AddressBox = New-Object Windows.Forms.TextBox -Property @{ Location = New-Object Drawing.Point(220, 57); Width = 180 }
    $buttons = @(
        @{ Text = 'Check status'; X = 12; Run = { Get-StatusLines } },
        @{ Text = 'Allow scanning'; X = 170; Run = {
            $answer = [Windows.Forms.MessageBox]::Show("Allow $($script:AddressBox.Text) to reach WinRM on this server?",
                'Allow scanning', 'YesNo', 'Question')
            if ($answer -eq 'Yes') { Invoke-Allow $script:AddressBox.Text } } },
        @{ Text = 'Revert changes'; X = 328; Run = {
            $answer = [Windows.Forms.MessageBox]::Show('Undo everything Allow changed on this server?', 'Revert', 'YesNo', 'Question')
            if ($answer -eq 'Yes') { Invoke-Revert } } })
    $script:LogBox = New-Object Windows.Forms.TextBox -Property @{
        Multiline = $true; ReadOnly = $true; ScrollBars = 'Vertical'; Location = New-Object Drawing.Point(12, 135)
        Size = New-Object Drawing.Size(680, 370); Anchor = 'Top, Bottom, Left, Right'; Font = New-Object Drawing.Font('Consolas', 9.5)
    }
    $form.Controls.AddRange(@($intro, $label, $script:AddressBox, $script:LogBox))
    foreach ($spec in $buttons) {
        # The action travels in Tag: a GetNewClosure handler could not see this script's functions.
        $button = New-Object Windows.Forms.Button -Property @{
            Text = $spec.Text; Tag = $spec.Run; Location = New-Object Drawing.Point($spec.X, 92); Size = New-Object Drawing.Size(150, 32)
        }
        $button.Add_Click({
            $owner = $this.FindForm()
            $owner.Cursor = [Windows.Forms.Cursors]::WaitCursor
            try { $lines = @(& $this.Tag) } catch { $lines = @('ERROR: ' + $_.Exception.Message) }
            finally { $owner.Cursor = [Windows.Forms.Cursors]::Default }
            if ($lines.Count) { $script:LogBox.AppendText((@("[$(Get-Date -Format 'HH:mm:ss')]") + $lines + '') -join "`r`n") }
        })
        $form.Controls.Add($button)
    }
    $form.Add_Shown({ $script:LogBox.AppendText(((@(Get-StatusLines)) + '') -join "`r`n") })
    return $form
}

if ($FunctionsOnly) { return }
switch ($Action) {
    'Status' { Get-StatusLines }
    'Allow' { Invoke-Allow $ScannerAddress }
    'Revert' { Invoke-Revert }
    default { $form = New-HelperForm; [void]$form.ShowDialog(); $form.Dispose() }
}
