# Agentic AI CIS hardening for Windows Server 2022 and Ubuntu 22.04

Final Year Project, TAR UMT. One application in which local-LLM agents assess a server against selected CIS Benchmark controls, rank the findings with a deterministic risk engine, propose fixes from a fixed library, apply only the fixes an administrator approves, and verify each result with a fresh scan.

**Supported systems:** Windows Server 2022 (stand-alone, CIS Stand-alone Benchmark v2.0.0, 32 controls) and Ubuntu 22.04.5 LTS (CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0, 30 controls). Servers are added by a one-time pairing code shown on the server; no server name, identity or address is typed or built into the program.

The whole project is in **[combined_cis_compliance/](combined_cis_compliance/README.md)**: setup, how to run it, the design and the progress record.

## Quick start (Windows laptop, PowerShell)

```powershell
cd combined_cis_compliance
python -m venv .venv-integration
.\.venv-integration\Scripts\python.exe -m pip install -r cis_compliance_dashboard_prototype\requirements.integration.lock.txt
.\Run-Dashboard.cmd
```

The dashboard opens on **Servers**. Run the pairing helper on the server (Windows: the server access helper; Ubuntu: `sudo python3 fyp-pair-ubuntu.py`), type the code it shows, then log in. The AI agents need [Ollama](https://ollama.com) with `qwen3:8b` on the same laptop.

The earlier standalone Windows and Ubuntu prototypes are in this repository's history; their work continues in the combined system.
