# Agentic AI Framework for Windows Systems Hardening and CIS Compliance Assessment

Final Year Project by Khoo Teng Yi & Teoh Kai Hong (TAR UMT).

This program checks a server's security settings against the **CIS Benchmark** (a widely used security checklist), shows which problems matter most, and fixes them, but only the ones you approve. An AI model coordinates the work.

It works with **Windows Server 2022** (stand-alone, not joined to a domain) and **Ubuntu 22.04 LTS**.

## How it works

1. **Scan.** The program reads the server's settings. It does not change anything.
2. **Rank.** Every failed setting gets a risk score, so you see the most important ones first.
3. **Propose.** The AI suggests which fixes to apply, chosen from a fixed list of safe, tested changes.
4. **You decide.** You approve or reject each fix. Nothing is changed without your approval.
5. **Fix and check.** The approved fixes are applied, then the server is scanned again to confirm they worked.

Four AI helpers ("agents") share this work: the **Orchestrator** plans each step, the **Scanner** reads the server, the **Analysis** agent studies the results, and the **Remediation** agent applies approved fixes. Every choice they make is checked by the program before anything happens, and they can never approve a change themselves.

## What you need

- **A Windows laptop** with [Python](https://www.python.org/downloads/) (version 3.13 or newer, free). When you install it, tick **"Add python.exe to PATH"**.
- **A server to check:** Windows Server 2022 or Ubuntu 22.04, on the same network as the laptop. A virtual machine works too (see [Testing on a virtual machine or a real server](#testing-on-a-virtual-machine-or-a-real-server)).
- **An administrator account** on that server.
- **Ollama with the `qwen3:8b` AI model** on the same laptop. The program needs it to work; see [Install the AI model](#install-the-ai-model).

## Install the AI model

The program's AI runs through **Ollama**, using the **qwen3:8b** model. Without it, the program still opens and shows earlier results, but it cannot start a new check of a server.

1. Download and install Ollama from [ollama.com/download](https://ollama.com/download).
2. Open **Command Prompt**, type `ollama pull qwen3:8b` and press **Enter**. This downloads the model (about 5 GB, once).

Ollama then keeps running in the background, so there is nothing else to do.

## Start the program

1. Download this project and unzip it.
2. Open the `combined_cis_compliance` folder and double-click **`Run-Dashboard.cmd`**.

The first time, it prepares itself. This takes a few minutes and needs an internet connection. After that it starts straight away. The program opens in your web browser; to stop it, close the black window.

## Connect a server

The program finds a server by a one-time **pairing code**, so you never type an address.

**Before you start (Windows and Ubuntu):** the laptop and the server must be on the **same network**, for example the same Wi-Fi or office network. If the server is not found, see the network tips under [On a real server](#on-a-real-server).

**Windows Server**

1. In the program, open **Servers** and click **Download helper (.zip)**. Copy the files to the server.
2. On the server, double-click **`Start-ServerAccess.cmd`**, then click **Start pairing**. A code such as `482-913-075` appears.
3. In the program, under **Add a server**, type the code and click **Find**. Then enter the Administrator password.

When you have finished with the server, click **Revert changes** in the helper. This removes the access it opened.

**Ubuntu Server**

1. In the program, open **Servers** and click **Download pairing helper (.py)**. Copy it to the server.
2. On the server, run `sudo python3 fyp-pair-ubuntu.py`. A code appears.
3. In the program, type the code, click **Find**, then enter the server's account and password.
4. The first time only: click **Set up this server** and run the one command it shows on the server.

The server is then saved under **My servers**. Next time, pick it there and enter the password (passwords are never stored).

## Harden a server

1. Open **Agentic hardening** and click **Start agentic round**. After a few minutes the proposed fixes appear.
2. In **Fixes**, type your name and press **Enter**, then **Approve** or **Reject** each fix.
3. Click **Execute approved fixes**, check the list of changes, and confirm.
4. See the outcome in **Results**, and the server's current state in **Controls**.
5. Click **Run next round** to check again and fix what is left.
6. When you are done, **Complete hardening** runs a final check, and **Round report** saves a printable record.

A few Windows firewall settings are never changed by the program, because changing them remotely could cut its own connection. The **Fixes** tab shows how to set them yourself, or you can accept them as an exception.

**Overview** shows a summary of the server, and **History** shows how its settings changed over time.

## Testing on a virtual machine or a real server

### On a virtual machine (best for trying it out)

1. Install Windows Server 2022 or Ubuntu 22.04 in VirtualBox (or another virtualisation program).
2. Set the virtual machine's network adapter to **Host-only**. The laptop and the virtual machine can then always reach each other, and the address does not change. (**Bridged** also works, but the address may change when the laptop joins another network; then simply pair again.)
3. **Take a snapshot before you start.** Hardening really changes the settings, so the snapshot is your way back.
4. Pair and harden the virtual machine as described above.
5. To start again from a clean state, restore the snapshot.

After restoring a snapshot the virtual machine's clock is often wrong. The program notices this and offers **Sync server clock**: one click fixes it.

### On a real server

- **Back up the server first.** The fixes are real changes and are not all undone automatically.
- Try it on a test server before an important one, and at a quiet time.
- The laptop and the server must be on the same network. Some guest or campus Wi-Fi stops devices from seeing each other; if the server is not found, use another network.
- Log in with an administrator account: on Windows the built-in **Administrator**, on Ubuntu an account that can use `sudo`.
- The program only accepts a stand-alone Windows Server 2022 or Ubuntu 22.04, and refuses anything else.
- When you have finished, click **Revert changes** in the Windows helper.

Never use the program on the laptop it runs on: it is meant for servers only.

## Good to know

- **Nothing changes without your approval,** and every approval expires after one hour.
- **Your results and history stay on your laptop.** Passwords are kept only while you are connected.
- **If the AI is not available,** you can still view all earlier results, and the program says so on screen.

## More information

- [Architecture](combined_cis_compliance/docs/design/ARCHITECTURE.md): how the agents and their checks work
- [Connecting a server](combined_cis_compliance/docs/vm/VM_CONNECTION_SETUP.md): pairing and connection problems in more detail
- [Ubuntu operations](combined_cis_compliance/cis_compliance_dashboard_prototype/docs/OPERATIONS.md): Ubuntu setup, backup and recovery

**For developers:** to run the automated tests, open PowerShell in `combined_cis_compliance\cis_compliance_dashboard_prototype` and run `..\.venv-integration\Scripts\python.exe -m unittest discover -s tests`.
