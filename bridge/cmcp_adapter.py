"""cMCP RuntimeClaim verification path (C-1).

When an agent runs behind a cMCP gateway, the attestation it presents is a cMCP
RuntimeClaim envelope (cmcp_version + trace + gateway + signature). We verify it with
the *published* `cmcp_verify.verify_trace_claim` — we do not reimplement it — then bind
it to the SAGE author.

Identity binding differs from the per-agent (C-2) path:
  * C-2: cnf key IS the SAGE author key  (cryptographic equality).
  * C-1: the RuntimeClaim's cnf is the *gateway* TEE key; the agent is named in
         gateway.agent_identity (SPIFFE + agent-manifest binding). So here we bind by
         checking gateway.agent_identity.agent_id == the SAGE X-Agent-ID the gateway
         asserts for this session. Weaker than C-2 (gateway-asserted, not key-equal),
         and documented as such.

Software-only claims pass signature/policy/freshness but carry NO hardware root; we record
hardware_backed=False and never claim otherwise.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cmcp_verify import ApprovedHashes, verify_trace_claim

from bridge.trace_verify import Verdict

# Fields that must be in verify_trace_claim's verified set for the bridge to accept.
_REQUIRED = {"signature", "attestation_freshness", "policy_bundle.hash", "tool_catalog.hash"}


def _canonical(claim: dict[str, Any]) -> bytes:
    body = {k: v for k, v in claim.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def verify_cmcp_claim(
    claim: dict[str, Any],
    *,
    agent_id_hex: str,
    approved_policy_hash: str,
    approved_catalog_hash: str,
    max_age_seconds: int = 86400,
) -> Verdict:
    checks: dict[str, bool] = {}
    # Defensive: a malformed claim may have non-dict sub-objects; never let field access crash.
    trace = claim.get("trace") if isinstance(claim.get("trace"), dict) else {}
    runtime = trace.get("runtime") if isinstance(trace.get("runtime"), dict) else {}
    platform = runtime.get("platform")
    digest = "sha256:" + hashlib.sha256(_canonical(claim)).hexdigest()
    thumb = None
    try:
        x = trace["cnf"]["jwk"]["x"]
        from bridge.identity import jwk_thumbprint_sha256
        thumb = jwk_thumbprint_sha256(x)
    except Exception:
        pass

    # CRITICAL HONESTY CONSTRAINT: the bridge NEVER asserts hardware. The published cmcp_verify
    # (v0.2.x, Phase 1) checks only the measurement format/parse + structure; the hardware ROOT
    # OF TRUST (TPM EK cert chains, AMD VCEK, Intel DCAP quote signatures) is explicitly deferred
    # ("out of scope for Phase 1"). So a claim whose forgeable format/parse checks pass lands
    # 'hardware_attestation' in *verified_fields* with no real silicon check — forgeable by anyone
    # who controls the gateway key. We never trust it: a claim's platform is recorded as
    # CLAIMED-not-verified and hardware_backed is always False. (Pinned by tests/test_hardening C3.)
    hardware_backed = False

    def out(ok: bool, reason: str | None = None) -> Verdict:
        return Verdict(ok=ok, checks=checks, reason=reason, cnf_thumbprint=thumb,
                       attestation_digest=digest, platform=platform,
                       hardware_backed=hardware_backed)

    # F2: a malformed claim can raise inside the published cmcp_verify — never 500; reject it.
    try:
        res = verify_trace_claim(
            claim,
            ApprovedHashes(policy_bundle_hash=approved_policy_hash,
                           tool_catalog_hash=approved_catalog_hash),
            max_attestation_age_seconds=max_age_seconds,
        )
    except Exception as exc:  # noqa: BLE001 — convert any verifier crash into a clean reject
        return out(False, f"cmcp claim could not be verified: {type(exc).__name__}")
    verified = set(res.verified_fields)
    for f in _REQUIRED:
        checks[f] = f in verified
    if not _REQUIRED.issubset(verified):
        missing = sorted(_REQUIRED - verified)
        return out(False, f"cmcp claim missing verified fields: {missing} "
                          f"(status={res.status.value}, reason={res.failure_reason})")

    # Identity binding (C-1, advisory): gateway-ASSERTED, exact match against agent_id or its
    # last SPIFFE path segment. NOT cryptographically bound to a manifest (no trusted issuer
    # keys are plumbed into cmcp_verify Step 5), and the SPIFFE trust domain is not pinned.
    # C-1 is session PROVENANCE, not per-write authorization; see README.
    gateway = claim.get("gateway") if isinstance(claim.get("gateway"), dict) else {}
    ident = gateway.get("agent_identity") if isinstance(gateway.get("agent_identity"), dict) else {}
    asserted = ident.get("agent_id", "")
    # F3: require a non-empty author AND non-empty asserted id, so an empty X-Agent-ID can't
    # match the empty last segment of a trailing-slash SPIFFE id.
    checks["identity_binding"] = (
        bool(agent_id_hex) and isinstance(asserted, str) and bool(asserted)
        and agent_id_hex in (asserted, asserted.rsplit("/", 1)[-1])
    )
    if not checks["identity_binding"]:
        return out(False, "gateway.agent_identity.agent_id does not name the SAGE author "
                          f"(asserted={asserted!r}, author={agent_id_hex[:16]}…)")

    return out(True, None)
