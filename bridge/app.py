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
"""
import os
from bridge.proxy import build_app
from bridge.evidence_store import EvidenceStore

app = build_app(
    upstream=os.environ.get("SAGE_UPSTREAM", "http://127.0.0.1:18080"),
    store=EvidenceStore(os.environ.get("ATTESTATION_DB", "attestations.db")),
    enforcement=os.environ.get("BRIDGE_ENFORCEMENT", "enforcing"),
    max_age_seconds=int(os.environ.get("BRIDGE_MAX_AGE", "300")),
    # Explicit (also read inside build_app as a fallback) so the C-1 enable/disable is visible.
    cmcp_approved_policy_hash=os.environ.get("CMCP_APPROVED_POLICY_HASH"),
    cmcp_approved_catalog_hash=os.environ.get("CMCP_APPROVED_CATALOG_HASH"),
)
