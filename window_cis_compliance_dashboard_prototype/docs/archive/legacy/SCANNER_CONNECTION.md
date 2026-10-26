# Scanner connection to the lab VM

> **Archived 26 October 2026.** Describes the legacy **Evidence upload** page (manual file exchange and the earlier agent team), not the current agentic framework. Current design: [ARCHITECTURE.md](../../../ARCHITECTURE.md); current status: [PROGRESS.md](../../../PROGRESS.md).

> **Fallback only (26 October 2026).** The Scanner Agent's primary channel is PowerShell Remoting: see [VM_CONNECTION.md](../../../VM_CONNECTION.md). This shared-folder worker needs a person to start it inside the VM, so by itself it does not make the Scanner an agent.

The dashboard can now queue a read-only scan and import the worker's response without a JSON upload. The AI Scanner can use the same connection when it finds missing/error readings and requests recollection. A running worker inside the selected VM is required. This connection has been tested with synthetic evidence and mocked collection; an actual VM worker trial is still pending.

## Start the connection

1. Copy **Watch-ScanRequests.ps1** and the current **Collect-Server2022Evidence.ps1** from `cis_compliance_dashboard_prototype/data/vm_exchange` into `C:\FYP` inside the VM. Keep these local VM scripts separate from the shared queue. The existing exchange share was previously mapped as `Z:`; use its actual mapping if different.
2. In the dashboard, enter the selected hostname/UUID and expand **Scanner connection — request fresh VM evidence**. Set **VM script directory** and **Shared scan queue inside the VM** to their actual VM paths. Copy the generated startup command into Windows PowerShell as Administrator **inside Windows Server**. The example below uses the previously confirmed lab identity; verify it still matches. The dashboard command uses the current collector hash.
3. In the dashboard, enter the same hostname/UUID and expand **Scanner connection — request fresh VM evidence**. Click **Request fresh VM scan**, then **Check scan response** after the worker reports a response. A successful response opens a new 16-control assessment. No manual JSON upload is needed.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\FYP\Watch-ScanRequests.ps1' -ExchangeDirectory 'Z:\scan_queue' -ExpectedComputerName 'WIN-VFT30DUDRHQ' -ExpectedMachineUuid 'e5d10741-f200-4292-a099-e6be76032f4e' -ExpectedCollectorSha256 '126f95f7543849f056d309d03f6c3c7e3cf8371c04f40cd917fe519ed65bd43f' -WatchSeconds 900 -MaxRequests 5
```

The packaged host queue is `cis_compliance_dashboard_prototype/data/vm_exchange/scan_queue`. It must be the same shared directory visible as `Z:\scan_queue` inside the VM. The host application can use a different explicit folder through `CIS_SCAN_EXCHANGE`. No network discovery, stored VM password, WinRM/firewall configuration or service installation is involved. The execution-policy argument is process-local.

The worker stops after the watch interval or request limit; a collection already started has its own 120-second timeout. Stop it earlier with Ctrl+C. Restart it for another test session. A pending request expires after ten minutes; the VM and host clocks must agree. Start the worker first, then request a scan, or request a new scan if setup took longer than ten minutes.

Click **Refresh worker status** to see its latest report. The updated worker publishes `ready`, `busy` or `stopped` for the selected identity and collector. Ready/stopped reports expire after 15 seconds; busy reports after 150 seconds to allow the bounded collection to finish. The dashboard distinguishes absent, stale, malformed, mismatched-target/hash and clock-mismatch reports. Copy the updated worker script into the VM to enable reporting; older copies produce no report. Status is refreshed on dashboard interaction, not continuously.

These reports are advisory shared-folder messages, not authenticated attestation or collected evidence. A ready report cannot create an assessment, satisfy the Scanner's evidence checks or permit remediation. A stale/stopped report requires checking or restarting the VM worker; a pending request remains subject to its own expiry.

## Agent responsibility and workflow

The AI Scanner decides whether the selected readings need recollection. Its `request_recollection` tool queues only the fixed collection operation for the framework's exact target. The team stops at `awaiting_evidence`; it cannot treat a queued request as a successful scan or continue to remediation using that request as evidence. The returned assessment is a new framework run, with fresh operational context and approval requirements. Earlier snapshots/proposals remain unchanged. Start a new team review on the returned assessment when ready; model execution does not start automatically on response import.

Only the Scanner has the read-only `get_collection_status` tool. It can inspect the worker report to inform its collection decision, but must still read scan coverage before handing evidence to Analysis. Other roles cannot use worker readiness as an alternate evidence source.

The worker can only invoke its adjacent, hash-matched read-only collector. It refuses a different target, unexpected fields/operation, wrong collector hash and expired request. It creates an exclusive persistent claim before collection. Duplicate/claimed requests are not replayed. No arbitrary command or remediation action is accepted by this worker.

The host checks response/request digests, target identity, schema/catalogue, collection timestamps and typed observations. Failed, invalid, expired and awaiting-worker states stay distinct. Repeated response import resumes the same framework run, including after an interruption between saving the response and completing assessment. Recover a pending request after a browser restart using its saved request ID and the matching hostname/UUID. If a worker was interrupted after claiming a request, let it expire and create a new request; do not delete claims to force replay.

This is a trusted shared-folder lab transport, not authenticated remote attestation. Folder permissions and trusted local script copies remain the boundary. Digests detect mismatched bytes; they do not authenticate a malicious writer to the share. Evidence remains labelled Imported. Remediation approval/execution continues through the separate approved-action workflow.

## Tests

`tests/test_scan_exchange.py` covers request/response binding, expiry, missing worker, failed collection, concurrency, replay, immutable records, old evidence, schema mismatch, and interrupted import recovery. It includes a Python → mocked PowerShell → Python assessment round trip. `scripts/test_scan_worker.ps1` checks operation/type/target/hash/time guards and claim failures without reading machine configuration. Scanner-team and dashboard tests cover queued recollection and the no-upload assessment path.

`tests/test_worker_readiness.py` checks status freshness/identity/hash/schema, bounded file parsing, literal-quoted setup commands and a pure PowerShell-report-to-Python-validation contract. Team/UI checks confirm that worker status alone cannot create an assessment or replace required evidence.
