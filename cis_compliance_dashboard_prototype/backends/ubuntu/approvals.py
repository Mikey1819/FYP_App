"""Exact approval bytes for one action plan. Never amended after approval; the hash binds the bytes.

The local operator/session is the authority boundary; the hash is not independent human authentication.
"""
from dataclasses import dataclass
from datetime import timedelta, timezone
import hashlib
from uuid import uuid4
from vm.ubuntu.remediation_schema import (MAX_APPROVAL_SECONDS, MAX_BEFORE_STATE_AGE, REQUEST_NAMESPACE, canonical,
                                          parse_request, utc)
from .actions import CATALOGUE_VERSION


@dataclass(frozen=True)
class ApprovedRequest:
    raw: bytes
    sha256: str
    request: dict


def _aware(now):
    if now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise ValueError('UTC approval time required')
    return now.astimezone(timezone.utc)


def approve(plan, operator, now):
    now = _aware(now)
    if type(operator) is not str or not 0 < len(operator.strip()) <= 128:
        raise ValueError('A named operator is required to approve')
    age = now - utc(plan.fields['before_state_collected_at'])
    if not timedelta(0) <= age <= timedelta(seconds=MAX_BEFORE_STATE_AGE):
        raise ValueError('Before-state evidence is older than five minutes; collect fresh evidence and plan again')
    doc = dict(plan.fields, namespace=REQUEST_NAMESPACE, schema_version=1, request_id=uuid4().hex,
               proposal_id=plan.proposal_id, platform='ubuntu', catalogue_version=CATALOGUE_VERSION,
               action={'action_id': plan.spec.action_id, 'version': plan.spec.version,
                       'implementation_sha256': plan.spec.implementation_sha256},
               approver=operator.strip(), approved_at=now.isoformat(),
               expires_at=(now + timedelta(seconds=MAX_APPROVAL_SECONDS)).isoformat())
    raw = canonical(doc)
    return ApprovedRequest(raw, hashlib.sha256(raw).hexdigest(), parse_request(raw))


def verify(approved, now):
    """The exact approved bytes, unexpired; returns the parsed request."""
    now = _aware(now)
    if type(approved.raw) is not bytes or hashlib.sha256(approved.raw).hexdigest() != approved.sha256:
        raise ValueError('Approved request bytes do not match their hash')
    request = parse_request(approved.raw)
    if request != approved.request:
        raise ValueError('Approved request fields do not match their bytes')
    if now >= utc(request['expires_at']):
        raise ValueError('Approval has expired; a fresh plan and approval are required')
    return request
