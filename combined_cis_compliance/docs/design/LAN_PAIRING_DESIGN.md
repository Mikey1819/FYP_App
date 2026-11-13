# Plan: pairing the main program with a server by code (built)

> **Status, 5 November 2026 (night): built in six steps on branch `lan-pairing`, tested on this laptop, not yet on a real server.** The delivered design is summarised in [ARCHITECTURE.md](ARCHITECTURE.md#which-server-the-agents-reach-decision-d7). How to use it is in [VM_CONNECTION_SETUP.md](../vm/VM_CONNECTION_SETUP.md). This page stays as the proposal. Differences from it:
>
> - **Close all access** removes every paired laptop and both rules, but does **not** turn PowerShell Remoting off. Doing that over the same WinRM session would cut the session midway and could leave the revert half-done. The page says to click **Revert changes** on the server when the helper had turned Remoting on.
> - **Adding by address was built, then removed (5 November 2026).** It was a second tab for the lab VM's NAT port forward and for networks that block pairing, with `-Action Allow -ScannerAddress` on the server. The administrator asked for the pairing code to be the only way to connect, so both went. The lab VM now needs a host-only or bridged adapter. Servers saved before then still connect, and Re-pair turns them into paired ones.
> - **The server says which system it runs (5 November 2026).** The `found` answer carries three more signed fields, `os`, `os_name` and `os_version` (for example `windows`, `Microsoft Windows Server 2022 Standard`, `10.0.20348`). `hardening/system_detect.py` sorts them into Windows Server 2022 (supported), another Windows Server, a Windows desktop, Ubuntu, other or unknown, and the page shows a note before the login. Only a supported system is offered the login; the identity probe after login still decides. Ubuntu is recognised but not linked yet: an Ubuntu helper would answer with `os` = the `ID` from `/etc/os-release`.
> - **A lost answer is answered again** for 10 seconds after pairing (same question from the same address); nothing new is recorded.
> - **Pairing without a window:** `-Action Pair` (for Server Core).
> - **Packaging:** `Start.cmd` calls a small launcher (`launch.py`) instead of Streamlit directly. Streamlit asks for an e-mail address on first use when it opens the browser itself, which would block a client. The launcher runs it headless, picks a free port and opens the browser when the dashboard answers. The package ships the venv's Python 3.15 and libraries, pinned in `requirements-lock.txt`.

## Idea in one paragraph

Today the dashboard only reaches the lab VM, and the person connecting must type its computer name, machine UUID, address and port. The goal is a program a client can download and use alone: on the same Wi-Fi as their Windows Server, with nothing to type except a pairing code and the Administrator password. It works like AnyDesk, but only inside the local network. The server shows a one-time code, the client types it into the main program, and the two find each other. The server then opens WinRM to the laptop's **current** address, whatever it is. After pairing, everything runs as it does now: the same agents, WinRM channel, approvals and verification.

## The two programs

| | **Main program** (client's laptop) | **Server helper** (each server to be checked) |
| --- | --- | --- |
| What it is | The current dashboard and agents, shipped as a zip with portable Python and `Start.cmd` | The current `FYP-ServerAccess.ps1` and `Start-ServerAccess.cmd`, extended with pairing |
| Runs | Whenever the client works | Only while pairing or reverting; the window is closed afterwards |
| Network role | Asks on the local network, then connects to the server over WinRM | Answers one correct code, then accepts WinRM from that one laptop |
| AI | Ollama with `qwen3:8b` on this laptop, loopback only (unchanged) | None |
| Stores | Saved servers and all assessment records, in `%LOCALAPPDATA%\FYP-Hardening\` | Its saved state and the pairing record, in `C:\ProgramData\FYP-ServerAccess\`, readable by administrators only |

The AI never talks to a server. The model only chooses the next step; the main program checks it and carries it out over WinRM on the paired server (decision D6).

## What the client does

```text
SERVER (helper window open)                       MAIN PROGRAM (client laptop)
1. Start pairing
   shows code: 482-913-075 (valid 10 min)
   listens on the local network
                                                  2. Add server → type 482-913-075 → Find
                                  ◀── broadcast ── "is there a server with this code?" + proof
3. Proof correct → firewall rule for this
   laptop's address only → reply + proof ──────▶  4. Card: WIN-ABC · Server 2022 · 192.168.1.50
   window: "Paired with DESKTOP-KHOO                 Type the Administrator password → Connect
   (192.168.0.105)", listener closed              5. Identity and pairing record checked over WinRM
                                                     → saved in My servers
                                                  6. Agentic rounds as now
7. Revert when finished
```

**Coming back later:**

| Situation | Client does | Server visit |
| --- | --- | --- |
| Same addresses, not reverted | Pick the server in **My servers**, type the password | No |
| Laptop or server address changed | **Start pairing** on the server and type the new code in **My servers → Re-pair**. The saved UUID must match, so it can only refresh the same machine | Yes, read one code |
| Reverted last time | Same as above | Yes |

When a saved server does not answer, the main program says so, along with the likely reason: the address changed or the server reverted. It does not just say `unreachable`.

## Server helper: what changes

The window keeps **Check status** and **Revert changes**. **Allow scanning**, which needed the laptop's address typed in, becomes **Start pairing**:

1. Same guards as today: administrator only, server OS only, current state saved first so Revert can undo exactly what changed.
2. Turns PowerShell Remoting on if it was off (the existing Allow logic).
3. Makes a 9-digit code from a cryptographic random generator, valid for 10 minutes and usable **once**.
4. Opens a temporary firewall rule for the pairing port (UDP, proposed **47815**, local subnet only), then listens.
5. On a request with a correct proof:
   - adds that request's source address to the WinRM rule `FYP-ServerAccess-WinRM`. The rule lists only paired laptops; a main program can remove a laptop again with **Disconnect** (see below);
   - adds a pairing record (random `pairing_id`, laptop address and name, time) to the server's list of paired laptops;
   - replies;
   - closes the listener and removes the UDP rule.
6. Wrong proofs are counted per sender address. After 5 wrong attempts from one address, or 20 in total, it stops and asks for a new code. When the 10 minutes run out, it stops too.
7. Pairing again while already allowed only updates the rule's address list. When a laptop that is already paired pairs again from a new address, its old address is replaced. The originally saved state is kept, so Revert still returns the server to how it was before the first pairing.
8. **Revert** removes every paired laptop and deletes all pairing records, so an old pairing can no longer be checked.

**Remarks shown in the window:** which laptop it is paired with and since when, what it changed, that it never changes a CIS setting, and to click Revert when finished.

The script stays the same file for everyone. Nothing per-client is written into it, so the SHA-256 published in the main program stays checkable.

## Main program: what changes

1. **My servers** (new page, or the top of Agentic hardening): saved servers with name, OS, last address, last connected and an optional note from the client. Actions: Connect, Re-pair, Remove, and **Download server helper** with its SHA-256.
2. **Add server:** a code field and a **Find** button. The program broadcasts on every network interface, because a laptop often has Wi-Fi plus VirtualBox adapters, and retries for about 6 seconds. It accepts the first reply with a correct proof, shows the server card and asks for the password.
3. **Connection form:** the computer name, UUID, host and port fields go. The target is built from the verified reply and checked again by the identity probe, so `WinRmTarget` and the `wrong_target` / `not_admin` checks stay as they are.
4. **Disconnect**, so access can be closed from the main program without visiting the server:
   - **Paired laptops** on the server card lists every laptop the server currently admits (name, address, paired at), read from the pairing records over WinRM. This laptop is marked "this laptop", so a pairing made by someone else is visible.
   - **Disconnect a laptop** removes that laptop's address from the WinRM rule and deletes its pairing record. Any laptop can be removed, for example one paired with an overheard code.
   - **Disconnect this laptop** removes this laptop's own access and ends the session. The server stays saved in My servers, so reconnecting later only needs a new code.
   - **Close all access** runs the helper's Revert remotely, putting the server back to how it was before the first pairing. It runs as the last command of the session, because it ends the WinRM connection.
   - These are three fixed scripts sent with typed parameters, like the collector and runner. The current session-only **Disconnect** button stays and changes nothing on the server.
5. **Saved server record** (new `servers` table): machine UUID (the key), hostname, last address, port, laptop address at pairing, `pairing_id`, paired at, last connected, note. **The password is never stored.**
6. **Wording:** "server" instead of "VM"; defaults no longer point at `127.0.0.1:55985`. The lab VM can still be added by pairing.
7. **Packaging:** a zip with portable Python, libraries, the app and `Start.cmd`. The dashboard listens on `127.0.0.1` only, data is kept in `%LOCALAPPDATA%`, and no lab data, tests or `.venv` are included. A build script is run by the developer only.

## Pairing messages

Small JSON messages over UDP, version 1. Both proofs are HMAC-SHA256 keyed with the code, so **the code itself never travels on the network**.

| Message | Sent by | Fields | Proof covers |
| --- | --- | --- | --- |
| `find` | Main program (broadcast) | `v`, `nonce_l` (random), `laptop_name`, `mac` | `find`, `nonce_l`, `laptop_name` |
| `found` | Server helper (reply to sender) | `v`, `nonce_l`, `nonce_s`, `hostname`, `machine_uuid`, `port`, `pairing_id`, `os`, `os_name`, `os_version`, `mac` | `found` and every other field |

The server takes the laptop's address from the packet's source, never from a field. The main program takes the server's address from the reply's source. The echoed `nonce_l` stops an old reply being replayed. Windows Firewall on the laptop already lets a reply to its own broadcast in for a few seconds, so the laptop needs no firewall change.

## Checks in order (each must pass, or nothing is saved)

1. The reply's proof is correct, so the server knows the code.
2. WinRM login with the Administrator password works (NTLM, encryption always, as now).
3. The identity probe returns the same hostname and UUID as the reply, a stand-alone Server 2022, and an administrator token.
4. The pairing record read over WinRM holds the same `pairing_id` and this laptop's address. This step cannot be faked without the Administrator password.
5. When re-pairing a saved server, the UUID must equal the saved one. Otherwise the program refuses: "a different machine answered".

## Security summary

| Risk | Protection |
| --- | --- |
| Guessing the code over the network | 9 digits, 10 minutes, one use, attempt limits per sender and in total |
| Overhearing the exchange | The code is never sent, only proofs; it is used once and is gone after the first correct request |
| A fake device answering | It must prove the code; then checks 3 and 4 need the real Administrator login |
| A door left open | The helper listens only while its window shows a code. **Disconnect** in the main program removes any paired laptop; Revert (on the server, or **Close all access** remotely) closes everything |
| Someone pairs with an overheard code | Accepted risk (decided 5 November). The firewall opening alone gives them nothing without the Administrator password, and the main program shows every paired laptop and can disconnect it |
| Someone else on the Wi-Fi opening the dashboard | The main program listens on `127.0.0.1` only |

**Known limits, for the report:**

- Someone who captures a `find` message could try all 10⁹ codes offline. By then the code has been used, so it cannot pair them. Their only use for it is a fake `found` reply sent before the real server answers, which normally takes milliseconds. If that race were won, the laptop would send an NTLM login to the impostor before check 4 fails. This risk is accepted for this project, and **Disconnect** is the remedy for unwanted pairings. A password-authenticated key exchange (for example SPAKE2) or WinRM over HTTPS with a pinned certificate would close it. It is future work.
- WinRM itself is still HTTP on port 5985 with NTLM message encryption, as now.
- Networks that stop devices talking to each other (many guest and campus Wi-Fi networks) block both pairing and WinRM. The program then says that the server could not be found on this network.

## Unchanged

- Agents, reason codes, risk engine (D2), action library, approval binding and expiry, verification.
- Only the two fixed scripts are sent to the server, with typed parameters.
- Ollama on the main laptop, loopback only.
- Scope: CIS Windows Server 2022 Stand-alone v2.0.0 Level 1. Other systems are refused before anything runs, with a plain message.

## Testing set-up

The lab VM's NAT port forward does not carry broadcasts. For pairing tests, give the VM a **Host-only** adapter (laptop `192.168.56.1`), or a **Bridged** adapter on the Wi-Fi to test the real client situation. The existing NAT forward can stay for regression runs.

## Build order

Each step ends with its tests passing before the next starts.

1. **Saved servers in the main program:** `servers` table, My servers page, connect by saved address with the UUID check, still adding servers by typing the address. Existing rounds keep working.
2. **Pairing protocol:** a Python module and PowerShell functions for `find` and `found`, sharing one set of test vectors so both sides compute identical proofs. No network yet.
3. **Server helper:** Start pairing (code, listener, rule, record, limits, remarks), re-pair and Revert. Fixture tests first, then the **first real run of Allow and Revert on the VM**.
4. **Add server by code** in the main program: broadcast, verify, checks 1 to 5, save. Then **Paired laptops** and the three Disconnect actions. End-to-end test with the VM on a host-only adapter, including disconnecting a second paired laptop.
5. **Packaging:** build script, `Start.cmd`, data in `%LOCALAPPDATA%`, a clean-machine test from the zip.
6. **Documents:** README, VM_CONNECTION_SETUP, ARCHITECTURE, report sections, and decision **D7** in AGENTS.md.

## Proposed decision D7

> Servers are paired by a one-time code over the local network. The server helper shows the code and opens WinRM to paired laptops only. The main program lists them and can disconnect any of them. Identity is fixed by the machine UUID saved at pairing. No internet relay and no permanent remote-access service: pairing works only while the helper window is open.

## Ubuntu 22.04 (unified system, 8 November 2026)

The unified Windows and Ubuntu system pairs Ubuntu servers by code too, so no server detail is typed for either system.

- **Helper:** `scripts/server_access/fyp-pair-ubuntu.py`, Python 3.10 standard library, run with `sudo` on the server. It answers the same `find` message with a `found` message whose fields are those of the Windows answer plus `host_key`, the SHA256 fingerprint of the SSH host key the dashboard will meet (the first key type in the SSH library's preference that `sshd -T` offers). `machine_uuid` carries `/etc/machine-id` written as a dashed UUID. The MAC covers `host_key`, appended after the Windows fields, so Windows messages and `pairing_vectors.json` are unchanged.
- **Laptop check:** an answer with `os = ubuntu` must carry a well-formed `host_key`, and a Windows answer must not. The connection passes the signed fingerprint as the confirmed host key: the SSH login is refused before any password is sent if the server shows another key. Hostname and machine ID are checked after login.
- **Trust argument:** reading the code on the server's own console and typing it here proves the answer came from that console's machine, which stands for reading the fingerprint from the console as the earlier manual form required. The residual risk is the one already accepted for Windows in D7 (an overheard question could let an attacker on the same network try codes offline within the 10-minute window); the first login also needs the server's own password, and later logins use the pinned key.
- **No server-side record or access control:** SSH is already the server's own access path, so the Ubuntu helper keeps no pairing file and the Servers page shows no paired-laptops list for Ubuntu. Its only change is the temporary UFW rule for UDP 47815 from private networks, deleted when it stops.
- **Address changes:** the integration ledger's registrations are append-only, so a re-pair at a new address adds an `endpoint_moves` row (proof `pairing_code`) for the same machine, hostname and host key; a changed host key is still refused.
- **Supported systems:** `system_detect.py` supports only Windows Server 2022 (stand-alone) and Ubuntu 22.04 (built and tested on 22.04.5 LTS; every 22.04 point release reports VERSION_ID 22.04 and has the same benchmark).
