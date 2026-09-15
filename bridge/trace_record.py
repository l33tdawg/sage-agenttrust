"""Mint a standalone TRACE Trust Record (per-agent path, C-2).

The record's `cnf` is the agent's own SAGE key, and `tool_transcript.hash` is set to
SHA-256 of the exact SAGE submit body, binding the record 1:1 to the write it
authorizes. This uses agentrust-trace's `sign_record` so the signature binding is a
real TRACE signature (CONTRIBUTING rule 4), not a look-alike.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any

from agentrust_trace import TRACE_PROFILE_V0_2, TrustRecord, sign_record, validate_json

from bridge.identity import AgentKey

# Taken from the library rather than hardcoded: the schema pins eat_profile to a `const`, so a
# literal here silently rots at every spec revision. It did: this read
# "tag:agentrust.io,2026:trace-v0.1" and stopped validating against agentrust-trace 0.10.0,
# which requires "tag:agentrust-io.com,2026:trace-v0.2".
TRACE_PROFILE = TRACE_PROFILE_V0_2


def body_digest(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()


def mint_record(
    key: AgentKey,
    *,
    submit_body: bytes,
    model_provider: str = "anthropic",
    model_id: str = "claude-opus-4-8",
    data_class: str = "agent-memory",
    policy_bundle_hash: str | None = None,
    enforcement_mode: str | None = None,
    platform: str = "software-only",
) -> dict[str, Any]:
    """Return a signed TRACE record bound to *submit_body* via tool_transcript.hash.

    platform defaults to "software-only": honest dev mode, NOT hardware-backed. We never
    fabricate positive evidence: appraisal.status is always "none" (the bridge performs no
    independent appraisal), SLSA is the schema minimum (1) with a self-evident placeholder
    digest, and a record without a real policy bundle declares enforcement "advisory".
    """
    if enforcement_mode is None:
        enforcement_mode = "enforce" if policy_bundle_hash else "advisory"
    record: dict[str, Any] = {
        "eat_profile": TRACE_PROFILE,
        "iat": int(time.time()),
        "subject": f"spiffe://sage.local/agent/{key.agent_id[:16]}",
        "model": {"provider": model_provider, "model_id": model_id},
        "runtime": {
            "platform": platform,
            # The sha256:0…0 measurement is cMCP's documented software-only sentinel.
            "measurement": "sha256:" + "0" * 64,
            "firmware_version": "software-only-dev-mode",
        },
        "policy": {
            "bundle_hash": policy_bundle_hash or ("sha256:" + "0" * 64),
            "enforcement_mode": enforcement_mode,
        },
        "data_class": data_class,
        # Bind this record to the specific SAGE submit it authorizes.
        "tool_transcript": {"hash": body_digest(submit_body), "call_count": 1},
        "build_provenance": {"slsa_level": 1, "digest": "sha256:" + "0" * 64},
        # The bridge performs no independent RATS appraisal of a self-minted record, so status
        # is always "none" (never "affirming"). verifier must be a URI (schema format:uri §3.1).
        "appraisal": {"status": "none",
                      "verifier": "https://github.com/l33tdawg/sage-agenttrust"},
        "transparency": "https://sage.local/scitt/none",
    }
    signed = sign_record(record, key.crypto_signing_key())
    validate_json(signed)            # JSON-Schema conformance
    TrustRecord.model_validate(signed)  # structural conformance
    return signed
