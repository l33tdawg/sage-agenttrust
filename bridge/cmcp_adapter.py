"""cMCP RuntimeClaim verification path (C-1).

When an agent runs behind a cMCP gateway, the attestation it presents is a cMCP
RuntimeClaim envelope (cmcp_version + trace + gateway + signature). We verify it with
the *published* `cmcp_verify.verify_trace_claim` — we do not reimplement it — then bind
it to the SAGE author.

Identity binding differs from the per-agent (C-2) path:
  * C-2: cnf key IS the SAGE author key  (cryptographic equality).
  * C-1: the RuntimeClaim's cnf is the *gateway* signing key; the agent is named in
         gateway.agent_identity (SPIFFE + agent-manifest binding). So here we bind by
         checking gateway.agent_identity.agent_id == the SAGE X-Agent-ID the gateway
         asserts for this session. Weaker than C-2 (gateway-asserted, not key-equal),
         and documented as such.

Identity anchoring is opt-in: `CmcpTrust` can pin a software gateway key and Agent Manifest
issuer keys. Hardware verification is unsupported on the pinned cmcp-runtime 0.5 series:
silicon-root/measurement configuration and non-software C-1 claims fail closed. The bridge
never reports hardware_backed=True.
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
    """Software C-1 identity anchors. Hardware options are retained only to reject them.

    The pinned cmcp-runtime 0.5 series predates the 0.7 TPM binding/measurement security fixes.
    An explicitly requested hardware check must never silently become a software check.
    """

    # Pin the gateway signing key. This is the one that changes the security story: with it,
    # a signature-valid claim naming any agent_id is no longer enough — the claim must carry
    # the pinned key, so "anyone can mint a claim" becomes "the pinned issuer can".
    trusted_gateway_key_hex: str | None = None
    # Bind gateway.agent_identity to an Agent Manifest signed by a key we trust.
    agent_manifest: dict[str, Any] | None = None
    trusted_agent_manifest_keys: dict[str, bytes] | None = None
    # Unsupported under the current dependency pin, including empty configured values.
    trusted_ark_pem: bytes | None = None
    trusted_intel_root_pem: bytes | None = None
    trusted_tpm_ca_pem: bytes | None = None
    expected_gateway_measurement: str | None = None

    def __post_init__(self) -> None:
        self.require_supported_config()

    def require_supported_config(self) -> None:
        configured = [name for name in (
            "trusted_ark_pem", "trusted_intel_root_pem", "trusted_tpm_ca_pem",
            "expected_gateway_measurement",
        ) if getattr(self, name) is not None]
        if configured:
            raise ValueError("hardware verification is unsupported with pinned cmcp-runtime 0.5: "
                             + ", ".join(configured))

    def kwargs(self) -> dict[str, Any]:
        """Only what was configured, so the library's own defaults stay in charge otherwise."""
        # Repeat at the verifier boundary, including objects restored outside __init__.
        self.require_supported_config()
        return {k: v for k, v in {
            "trusted_public_key_hex": self.trusted_gateway_key_hex,
            "agent_manifest": self.agent_manifest,
            "trusted_agent_manifest_keys": self.trusted_agent_manifest_keys,
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
    # Same JCS number-domain restriction as the C-2 path: a claim carrying 2**53+1, NaN or Inf
    # cannot be canonicalized, so reject it explicitly instead of letting rfc8785 raise through
    # the request (which reaches the client as a 500).
    try:
        canonical = _canonical(claim)
    except (ValueError, TypeError) as exc:
        checks["canonical_form"] = False
        return Verdict(ok=False, checks=checks,
                       reason=f"claim is not canonically encodable (RFC 8785): {exc}")
    digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
    thumb = None
    try:
        x = trace["cnf"]["jwk"]["x"]
        from bridge.identity import jwk_thumbprint_sha256
        thumb = jwk_thumbprint_sha256(x)
    except Exception:
        pass

    # Hardware verification is withdrawn until a newer verifier is separately qualified.
    hardware_backed = False
    identity_anchored = False

    def out(ok: bool, reason: str | None = None) -> Verdict:
        return Verdict(ok=ok, checks=checks, reason=reason, cnf_thumbprint=thumb,
                       attestation_digest=digest, platform=platform,
                       hardware_backed=hardware_backed, identity_anchored=identity_anchored)

    try:
        trust_kwargs = trust.kwargs() if trust else {}
    except ValueError as exc:
        checks["supported_configuration"] = False
        return out(False, str(exc))
    # Preserve the old producer's explicitly non-attested development shape as software.
    # Its platform label alone grants no hardware credit; evidence is refused below.
    checks["supported_runtime"] = platform == "software-only" or (
        platform == "tpm2" and runtime.get("firmware_version") == "software-only-dev-mode"
    )
    if not checks["supported_runtime"]:
        return out(False, "C-1 hardware/non-software runtime claims are unsupported with pinned "
                          "cmcp-runtime 0.5; use software-only or the legacy TPM software-dev shape")
    gateway = claim.get("gateway") if isinstance(claim.get("gateway"), dict) else {}
    # Published envelopes carry evidence under gateway.attestation_evidence; the old verifier
    # also reads legacy fields under runtime. A software label must not hide a hardware request.
    hardware_evidence = gateway.get("attestation_evidence") is not None or any(
        runtime.get(name) is not None for name in
        ("raw_evidence", "quote_signature", "cert_chain", "ek_cert_chain")
    )
    checks["supported_evidence"] = not hardware_evidence
    if hardware_evidence:
        return out(False, "C-1 hardware evidence is unsupported with pinned cmcp-runtime 0.5")

    # F2: a malformed claim can raise inside the published cmcp_verify — never 500; reject it.
    try:
        res = verify_trace_claim(
            claim,
            ApprovedHashes(policy_bundle_hash=approved_policy_hash,
                           tool_catalog_hash=approved_catalog_hash),
            max_attestation_age_seconds=max_age_seconds,
            **trust_kwargs,
        )
    except Exception as exc:  # noqa: BLE001 — convert any verifier crash into a clean reject
        return out(False, f"cmcp claim could not be verified: {type(exc).__name__}")
    verified = set(res.verified_fields)
    checks["hardware_attestation"] = False
    if "hardware_attestation" in verified:
        return out(False, "cmcp-runtime reported unsupported hardware verification for a software claim")
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

    # Only the supported gateway-key anchoring check can contribute identity strength.
    identity_anchored = "trusted_public_key" in verified
    checks["identity_anchored"] = identity_anchored

    # Identity binding (C-1, advisory): exact match against agent_id or its last SPIFFE segment.
    # Optional manifest issuer inputs are forwarded to cmcp_verify, whose failures reject above.
    # The bridge does not independently pin the SPIFFE trust domain.
    # C-1 is session PROVENANCE, not per-write authorization; see README.
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
