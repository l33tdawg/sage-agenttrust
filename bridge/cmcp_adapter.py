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

Identity anchoring is opt-in. With no anchors configured (`trust=None`, the default) the
gateway key is taken on trust and no silicon root is checked, so the binding stays
"gateway-asserted" and hardware_backed is always False. Supplying `CmcpTrust` pins the
gateway key and/or a silicon root, and only then can this path report an anchored identity or
a hardware root — each only when the library actually verified the corresponding check.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

import rfc8785
from cmcp_verify import ApprovedHashes, verify_trace_claim

from bridge.trace_verify import Verdict

# Fields that must be in verify_trace_claim's verified set for the bridge to accept.
_REQUIRED = {"signature", "attestation_freshness", "policy_bundle.hash", "tool_catalog.hash"}


@dataclass(frozen=True)
class CmcpTrust:
    """Operator-pinned anchors for the C-1 path. Every field is optional.

    These are exactly the out-of-band inputs `cmcp_verify.verify_trace_claim` accepts, named
    for what they pin. Nothing here is self-declared: an anchor only means something because
    the verifier holds it independently of the claim.
    """

    # Pin the gateway signing key. This is the one that changes the security story: with it,
    # a signature-valid claim naming any agent_id is no longer enough — the claim must carry
    # the pinned key, so "anyone can mint a claim" becomes "the pinned issuer can".
    trusted_gateway_key_hex: str | None = None
    # Bind gateway.agent_identity to an Agent Manifest signed by a key we trust.
    agent_manifest: dict[str, Any] | None = None
    trusted_agent_manifest_keys: dict[str, bytes] | None = None
    # Silicon roots. Supply the one for your platform; each lets cmcp_verify check a real
    # chain instead of only the measurement's format.
    trusted_ark_pem: bytes | None = None
    trusted_intel_root_pem: bytes | None = None
    trusted_tpm_ca_pem: bytes | None = None
    # Bind the gateway's measurement to a value the verifier chose.
    expected_gateway_measurement: str | None = None

    @property
    def silicon_root_pinned(self) -> bool:
        return any((self.trusted_ark_pem, self.trusted_intel_root_pem, self.trusted_tpm_ca_pem))

    def kwargs(self) -> dict[str, Any]:
        """Only what was configured, so the library's own defaults stay in charge otherwise."""
        return {k: v for k, v in {
            "trusted_public_key_hex": self.trusted_gateway_key_hex,
            "agent_manifest": self.agent_manifest,
            "trusted_agent_manifest_keys": self.trusted_agent_manifest_keys,
            "trusted_ark_pem": self.trusted_ark_pem,
            "trusted_intel_root_pem": self.trusted_intel_root_pem,
            "trusted_tpm_ca_pem": self.trusted_tpm_ca_pem,
            "expected_gateway_measurement": self.expected_gateway_measurement,
        }.items() if v is not None}


def _canonical(claim: dict[str, Any]) -> bytes:
    # Same recipe as bridge.trace_verify._canonical (RFC 8785 / JCS). This digest is the
    # bridge's own replay key and badge value, so it must not drift from the TRACE path.
    body = {k: v for k, v in claim.items() if k != "signature"}
    return rfc8785.dumps(body)


def verify_cmcp_claim(
    claim: dict[str, Any],
    *,
    agent_id_hex: str,
    approved_policy_hash: str,
    approved_catalog_hash: str,
    max_age_seconds: int = 86400,
    trust: CmcpTrust | None = None,
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

    # HONESTY CONSTRAINT: this is computed after verification, from what the library actually
    # checked. cmcp_verify 0.5.0 can verify a silicon root (TPM AK/EK chain to a pinned
    # manufacturer CA, AMD VCEK/VLEK, Intel DCAP quotes) but ONLY when the caller pins one. With
    # no anchor configured, 'hardware_attestation' in verified_fields means nothing more than
    # "the blob parsed", which is forgeable by anyone holding the gateway key — so hardware_backed
    # stays False unless we pinned a root AND the library reported the check as verified.
    # (Pinned by tests/test_hardening C3 and C13.)
    hardware_backed = False
    identity_anchored = False

    def out(ok: bool, reason: str | None = None) -> Verdict:
        return Verdict(ok=ok, checks=checks, reason=reason, cnf_thumbprint=thumb,
                       attestation_digest=digest, platform=platform,
                       hardware_backed=hardware_backed, identity_anchored=identity_anchored)

    # F2: a malformed claim can raise inside the published cmcp_verify — never 500; reject it.
    try:
        res = verify_trace_claim(
            claim,
            ApprovedHashes(policy_bundle_hash=approved_policy_hash,
                           tool_catalog_hash=approved_catalog_hash),
            max_attestation_age_seconds=max_age_seconds,
            **(trust.kwargs() if trust else {}),
        )
    except Exception as exc:  # noqa: BLE001 — convert any verifier crash into a clean reject
        return out(False, f"cmcp claim could not be verified: {type(exc).__name__}")
    verified = set(res.verified_fields)
    # A configured anchor is REQUIRED, never a bonus. Without this, pinning the gateway key would
    # only add a verified field, and a claim carrying a DIFFERENT key would still satisfy the
    # four required checks below — exactly the substitution the pin exists to catch.
    required = set(_REQUIRED)
    if trust and trust.trusted_gateway_key_hex:
        required.add("trusted_public_key")
    for f in required:
        checks[f] = f in verified
    if not required.issubset(verified):
        missing = sorted(required - verified)
        return out(False, f"cmcp claim missing verified fields: {missing} "
                          f"(status={res.status.value}, reason={res.failure_reason})")
    # The library's own failure signal must reject on its own. _REQUIRED names only the fields
    # this integration needs; cmcp_verify fails claims on other checks too — a TEE key-binding
    # mismatch ('a substituted key means the signing key itself cannot be trusted'), an
    # unverifiable silicon chain, a stale report. Accepting a claim the library flagged would
    # take the verdict it computed and discard the part that says no.
    if res.failure_reason is not None:
        details = getattr(res, "details", None) or {}
        detail = details.get("trusted_public_key") or details.get("public_key_binding")
        return out(False, f"cmcp claim failed verification: {res.failure_reason}"
                          + (f" — {detail}" if detail else ""))

    # Anchoring and hardware are reported from the library's own field list, and only then.
    identity_anchored = "trusted_public_key" in verified
    checks["identity_anchored"] = identity_anchored
    checks["hardware_attestation"] = "hardware_attestation" in verified
    hardware_backed = bool(trust and trust.silicon_root_pinned
                           and "hardware_attestation" in verified)

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
