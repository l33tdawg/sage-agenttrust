"""Attested SAGE client (C-2, per-agent TRACE path).

Builds a SAGE memory-submit that carries a TRACE record bound to the exact request:
one Ed25519 key signs the SAGE request AND is the record's cnf key. The record's
tool_transcript.hash == sha256(body), so the attestation authorizes this write only.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from bridge.identity import AgentKey
from bridge.trace_record import mint_record

SUBMIT_PATH = "/v1/memory/submit"


def build_submit(
    key: AgentKey,
    *,
    content: str,
    domain_tag: str,
    memory_type: str = "observation",
    confidence_score: float = 0.9,
    platform: str = "software-only",
) -> tuple[dict[str, str], bytes]:
    """Return (headers, body) for an attested POST /v1/memory/submit.

    Body bytes are produced exactly as the SAGE SDK does
    (json.dumps(..., separators=(",",":"))) so the signature the node verifies matches.
    """
    payload: dict[str, Any] = {
        "content": content,
        "memory_type": memory_type,
        "domain_tag": domain_tag,
        "confidence_score": confidence_score,
    }
    body = json.dumps(payload, separators=(",", ":")).encode()

    record = mint_record(key, submit_body=body, data_class=domain_tag, platform=platform)
    headers = key.sign_sage_request("POST", SUBMIT_PATH, body)
    headers["Content-Type"] = "application/json"
    headers["X-Attestation"] = base64.b64encode(
        json.dumps(record, separators=(",", ":")).encode()
    ).decode()
    return headers, body
