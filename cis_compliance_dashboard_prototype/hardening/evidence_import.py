"""Strict, offline imported-evidence validation; no OS commands, model or writes.

These files are user-supplied observations, not authenticated remote attestation.
Risk is scored separately, by the deterministic engine in risk.py.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from uuid import UUID

from .domain import Evidence, EvidenceMode, assess
from .server2022_catalogue import (
    BENCHMARK_SHA256, PROFILE, evidence_contract,
)

MAX_BYTES = 65536
CONTEXT_SOURCES = {
    "firewall_public_enabled": "Get-NetFirewallProfile:ActiveStore/Public/Enabled",
    "nla_required": "Win32_TSGeneralSetting:RDP-tcp/UserAuthenticationRequired",
    "nla_policy_source": "Win32_TSGeneralSetting:RDP-tcp/PolicySourceUserAuthenticationRequired",
}
# Schema 5 also reads the effective state behind the other firewall policy checks, so a policy that is
# merely not configured is not mistaken for disabled protection (risk Exposure only; never compliance).
CONTEXT_SOURCES_V5 = {
    **CONTEXT_SOURCES,
    "firewall_private_enabled": "Get-NetFirewallProfile:ActiveStore/Private/Enabled",
    "firewall_private_inbound_blocked": "Get-NetFirewallProfile:ActiveStore/Private/DefaultInboundAction",
    "firewall_public_inbound_blocked": "Get-NetFirewallProfile:ActiveStore/Public/DefaultInboundAction",
}
BOOLEAN_CONTEXT = {"firewall_public_enabled", "firewall_private_enabled", "firewall_private_inbound_blocked",
                   "firewall_public_inbound_blocked"}


def effective_context(raw):
    """Read validated supplementary observations; legacy files have none."""
    data = json.loads(raw.decode("utf-8-sig"))
    return data.get("effective_context", [])


def _validate_context(rows, started, completed, version=4):
    sources = CONTEXT_SOURCES_V5 if version >= 5 else CONTEXT_SOURCES
    if type(rows) is not list or len(rows) != len(sources):
        raise ValueError(f"All {len(sources)} effective context observations are required")
    seen = set()
    for row in rows:
        _object(row, "control_id source state value error collected_at", "effective context")
        key = row["control_id"]
        if type(key) is not str or key not in sources or key in seen:
            raise ValueError("Unknown or duplicate effective context")
        seen.add(key)
        if row["source"] != sources[key] or not started <= _time(row["collected_at"]) <= completed:
            raise ValueError("Invalid effective context provenance")
        state, value, error = row["state"], row["value"], row["error"]
        if state == "ok":
            scalar = bool if key in BOOLEAN_CONTEXT else int
            allowed = (0, 1, 2) if key == "nla_policy_source" else (0, 1)
            if error is not None or type(value) is not scalar or value not in allowed:
                raise ValueError("Invalid effective context value")
        elif state == "missing":
            if value is not None or error is not None:
                raise ValueError("Invalid missing effective context")
        elif state == "error":
            if value is not None or error not in ("collection_failed", "invalid_value", "timeout"):
                raise ValueError("Invalid effective context error")
        else:
            raise ValueError("Invalid effective context state")


def _object(value, keys, label):
    if type(value) is not dict or set(value) != set(keys.split()):
        raise ValueError(f"Unexpected or missing fields in {label}")


def _string(value, label, maximum=256):
    if (type(value) is not str or not value.strip() or len(value) > maximum
            or any(ord(c) < 32 for c in value)):
        raise ValueError(f"Invalid {label}")
    return value


def _uuid(value):
    _string(value, "machine UUID", 36)
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError("Invalid machine UUID") from exc
    if str(parsed) != value.lower() or parsed.int in (0, (1 << 128) - 1):
        raise ValueError("Machine UUID must be canonical and non-placeholder")
    return str(parsed)


def _time(value):
    _string(value, "timestamp", 48)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Invalid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Timestamp must include timezone")
    return parsed


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def encode(data):
    """Canonical JSON bytes, so equal records always hash and compare equal."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


@dataclass(frozen=True)
class ImportedAssessment:
    results: tuple
    target_id: str
    hostname: str
    source_sha256: str
    collected_at: datetime


def load_evidence(raw: bytes, *, expected_hostname: str, expected_machine_uuid: str,
                  now: datetime | None = None, mode: EvidenceMode = EvidenceMode.IMPORTED) -> ImportedAssessment:
    """`mode` records how the export arrived: Imported (file) or Live (the Scanner Agent's own WinRM channel).
    The export itself is the same collector contract either way, so its own `evidence_mode` field stays Imported."""
    if mode not in (EvidenceMode.IMPORTED, EvidenceMode.LIVE):
        raise ValueError("Evidence mode must be Imported or Live")
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_BYTES:
        raise ValueError("Evidence file must contain at most 64 KiB")
    try:
        data = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_no_duplicates,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Non-finite JSON")))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Invalid UTF-8 JSON evidence") from exc
    if type(data) is not dict:
        raise ValueError("Evidence must be an object")
    version = data.get("schema_version")
    if type(version) is not int or version not in (1, 2, 3, 4, 5):
        raise ValueError("Unsupported evidence schema")
    _object(data, "schema_version collector_id catalogue_id benchmark_sha256 profile "
            "evidence_mode started_at completed_at target observations" +
            (" effective_context" if version >= 2 else ""), "export")
    collector, catalogue_id, catalogue, sources = evidence_contract(version)
    for key, expected in (("collector_id", collector), ("catalogue_id", catalogue_id),
                          ("benchmark_sha256", BENCHMARK_SHA256), ("profile", PROFILE),
                          ("evidence_mode", EvidenceMode.IMPORTED.value)):
        if data[key] != expected:
            raise ValueError(f"Unsupported {key}")
    target = data["target"]
    _object(target, "hostname machine_uuid os_caption os_version build_number os_architecture "
            "product_type part_of_domain domain_role", "target")
    hostname = _string(target["hostname"], "hostname", 63)
    _string(expected_hostname, "expected hostname", 63)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,62}", hostname):
        raise ValueError("Invalid hostname")
    uuid = _uuid(target["machine_uuid"])
    if hostname.casefold() != expected_hostname.casefold() or uuid != _uuid(expected_machine_uuid):
        raise ValueError("Evidence does not match the explicitly selected target")
    _string(target["os_caption"], "OS caption")
    if ("Windows Server 2022" not in target["os_caption"]
            or target["os_version"] != "10.0.20348" or target["build_number"] != "20348"
            or target["os_architecture"] != "64-bit"
            or type(target["product_type"]) is not int or target["product_type"] != 3
            or target["part_of_domain"] is not False
            or type(target["domain_role"]) is not int or target["domain_role"] != 2):
        raise ValueError("Only standalone Windows Server 2022 x64 is supported")
    started, completed = _time(data["started_at"]), _time(data["completed_at"])
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("Validation clock must include timezone")
    if not timedelta(0) <= completed - started <= timedelta(minutes=5):
        raise ValueError("Invalid collection interval")
    if completed > now + timedelta(minutes=5):
        raise ValueError("Evidence timestamp is in the future; check the VM clock")
    if version >= 2:
        _validate_context(data["effective_context"], started, completed, version)
    observations = data["observations"]
    if type(observations) is not list or len(observations) != len(catalogue):
        raise ValueError(f"Export must include all {len(catalogue)} selected controls, including failures")
    by_id = {}
    for row in observations:
        _object(row, "control_id source state value error collected_at", "observation")
        identifier = _string(row["control_id"], "control ID", 64)
        if identifier not in sources or identifier in by_id:
            raise ValueError("Unknown or duplicate control")
        if row["source"] != sources[identifier]:
            raise ValueError("Evidence source does not match the registered collector")
        timestamp = _time(row["collected_at"])
        if not started <= timestamp <= completed:
            raise ValueError("Observation outside collection interval")
        state, value, error = row["state"], row["value"], row["error"]
        if state == "ok":
            if error is not None:
                raise ValueError("Successful observation cannot contain a collection error")
            expected_type = bool if identifier == "2.3.1.1" else int
            if type(value) is not expected_type:
                raise ValueError("Evidence has incorrect scalar type")
            # Preserve the INF never-expire/admin-unlock sentinel as evidence.
            minimum = -1 if identifier in ("1.1.2", "1.2.1") else 0
            if expected_type is int and not minimum <= value <= 4294967295:
                raise ValueError("Evidence integer outside collector range")
        elif state == "missing":
            if value is not None or error is not None:
                raise ValueError("Missing observation must contain null value/error")
        elif state == "error":
            if value is not None or type(error) is not str or error not in {
                "collection_failed", "invalid_value", "timeout", "ambiguous_account"}:
                raise ValueError("Invalid collection error record")
        else:
            raise ValueError("Invalid observation state")
        by_id[identifier] = row
    digest = hashlib.sha256(raw).hexdigest()
    assessment_id, target_id = "import-" + digest, "windows:" + uuid
    results = []
    for control in catalogue:
        row = by_id[control.control_id]
        error = f"Collector reported {row['error']}" if row["state"] == "error" else None
        evidence = Evidence(target_id, control.control_id, row["value"], _time(row["collected_at"]),
                            mode, row["source"], error)
        results.append(assess(assessment_id, control, evidence))
    return ImportedAssessment(tuple(results), target_id, hostname, digest, completed)
