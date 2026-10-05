"""ASGI entrypoint: attestation-verifying proxy in front of a stock SAGE node.

Run:  uvicorn bridge.app:app --port 19090

Env:
  SAGE_UPSTREAM            stock SAGE node base URL (default http://127.0.0.1:18080)
  BRIDGE_ENFORCEMENT       enforcing | advisory (default enforcing; invalid -> refuses to start)
  ATTESTATION_DB           evidence sqlite path (default attestations.db, per-instance/local)
  BRIDGE_MAX_AGE           C-2 record freshness window, seconds (default 300)
  CMCP_APPROVED_POLICY_HASH, CMCP_APPROVED_CATALOG_HASH
                           REQUIRED to ENABLE the C-1 cMCP path. If unset, the bridge cannot
                           check a RuntimeClaim's policy/catalog hashes, so every cMCP
                           attestation is rejected (422) under enforcing mode and only the C-2
                           per-agent path is active. Set both to your gateway's known-good
                           sha256:<hex> hashes to accept cMCP claims.

  Optional software C-1 identity anchoring (unset = the gateway key is taken on trust):
    CMCP_TRUSTED_GATEWAY_KEY_HEX   pin the gateway signing key (hex, 0x optional). With this,
                                   the trusted_public_key check becomes REQUIRED, so a claim
                                   carrying any other key is rejected.
  Unsupported hardware options: CMCP_TRUSTED_TPM_CA_PEM, CMCP_TRUSTED_ARK_PEM,
  CMCP_TRUSTED_INTEL_ROOT_PEM, CMCP_EXPECTED_GATEWAY_MEASUREMENT. Setting any of these,
  even to an empty value, refuses startup under pinned cmcp-runtime 0.5.
"""
import os

from bridge.cmcp_adapter import CmcpTrust
from bridge.proxy import build_app
from bridge.evidence_store import EvidenceStore


_hardware_env = [name for name in (
    "CMCP_TRUSTED_TPM_CA_PEM", "CMCP_TRUSTED_ARK_PEM", "CMCP_TRUSTED_INTEL_ROOT_PEM",
    "CMCP_EXPECTED_GATEWAY_MEASUREMENT",
) if name in os.environ]
if _hardware_env:
    raise SystemExit("hardware verification is unsupported with pinned cmcp-runtime 0.5: "
                     + ", ".join(_hardware_env))


_trust = CmcpTrust(
    trusted_gateway_key_hex=os.environ.get("CMCP_TRUSTED_GATEWAY_KEY_HEX") or None,
)
# No anchors configured at all is the documented default; pass None so the adapter's unanchored
# path is provably the one in play rather than an empty object that happens to behave the same.
_trust = _trust if _trust.kwargs() else None

app = build_app(
    upstream=os.environ.get("SAGE_UPSTREAM", "http://127.0.0.1:18080"),
    store=EvidenceStore(os.environ.get("ATTESTATION_DB", "attestations.db")),
    enforcement=os.environ.get("BRIDGE_ENFORCEMENT", "enforcing"),
    max_age_seconds=int(os.environ.get("BRIDGE_MAX_AGE", "300")),
    # Explicit (also read inside build_app as a fallback) so the C-1 enable/disable is visible.
    cmcp_approved_policy_hash=os.environ.get("CMCP_APPROVED_POLICY_HASH"),
    cmcp_approved_catalog_hash=os.environ.get("CMCP_APPROVED_CATALOG_HASH"),
    cmcp_trust=_trust,
)
