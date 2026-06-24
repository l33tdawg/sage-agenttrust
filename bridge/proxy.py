"""Attestation-verifying reverse proxy in front of a STOCK SAGE node.

Flow for POST /v1/memory/submit:
  1. read raw body + the SAGE signing headers + the X-Attestation header (base64 TRACE record)
  2. verify the TRACE record at the edge (signature, freshness, identity-binding, request-binding)
  3. enforcing + fail  -> 422, never reaches SAGE
     enforcing + pass  -> forward the *byte-identical* signed request to SAGE
     advisory          -> forward regardless, annotate
  4. on a 2xx commit, store the evidence keyed by the returned memory_id

Everything else is a transparent passthrough, so recall/query still work through the proxy.
The bridge adds GET /v1/attestation/{memory_id} for the provenance badge.

The proxy never rewrites the signed body — SAGE's Ed25519 signature stays valid because the
exact bytes are forwarded. X-Attestation is an extra header, outside the signed material.
"""

from __future__ import annotations

import base64
import json
import os
import threading
import time
from typing import Any

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from bridge.evidence_store import Evidence, EvidenceStore, now
from bridge.trace_verify import verify_record

_HOP = {"host", "content-length", "x-attestation", "connection", "keep-alive",
        "transfer-encoding"}


def _extract_memory_id(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    for k in ("memory_id", "memoryId", "id"):
        v = payload.get(k)
        if isinstance(v, str) and v:
            return v
    return None


class ReplayCache:
    """De-duplicates byte-identical attestations: a digest admits one write within its
    freshness window. This stops naive replay of a CAPTURED attestation by a third party.

    It does NOT make an attestation single-use against the agent that minted it. On the C-1
    cMCP path the agent controls the gateway key and can re-mint claims differing only in
    verifier-ignored fields (a fresh digest each time), and a cMCP RuntimeClaim is
    session-scoped with NO binding to a specific SAGE body — so C-1 is session *provenance*,
    not per-write authorization. C-2's real per-write protection is the body binding
    (tool_transcript.hash == sha256(body)) in trace_verify, not this cache. In-memory +
    process-local; a multi-instance deployment needs a shared store.
    """

    def __init__(self) -> None:
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    _SWEEP_AT = 10000  # bound memory without an O(n) sweep on every request (F2 perf)

    def check_and_mark(self, digest: str, ttl: float) -> bool:
        """Reserve *digest*: return True if a live reservation exists (a replay), else record it.
        Expiry is lazy (per-digest); a full sweep runs only when the map grows past a cap, so
        the per-call cost is amortized O(1) rather than O(n)."""
        now = time.time()
        with self._lock:
            exp = self._seen.get(digest)
            if exp is not None and exp > now:
                return True
            self._seen[digest] = now + ttl
            if len(self._seen) > self._SWEEP_AT:
                for d in [d for d, e in self._seen.items() if e <= now]:
                    del self._seen[d]
            return False

    def release(self, digest: str) -> None:
        """Release a reservation taken by check_and_mark (e.g. the upstream write failed)."""
        with self._lock:
            self._seen.pop(digest, None)


def build_app(
    *,
    upstream: str | None = None,
    store: EvidenceStore | None = None,
    enforcement: str | None = None,
    max_age_seconds: int = 300,
    cmcp_approved_policy_hash: str | None = None,
    cmcp_approved_catalog_hash: str | None = None,
    cmcp_max_age_seconds: int = 86400,
    client: httpx.AsyncClient | None = None,
) -> Starlette:
    upstream = (upstream or os.environ.get("SAGE_UPSTREAM", "http://127.0.0.1:18080")).rstrip("/")
    # F1: enforcement is a CLOSED ENUM, parsed once and fail-fast. A free-form `== "enforcing"`
    # check fails OPEN on any typo (e.g. "enforce", the token SAGE itself uses) — silently
    # disabling the gate. Refuse to start on an unrecognized value; default is the safe "enforcing".
    enforcement = (enforcement or os.environ.get("BRIDGE_ENFORCEMENT", "enforcing")).strip().lower()
    if enforcement not in ("enforcing", "advisory"):
        raise ValueError(
            f"BRIDGE_ENFORCEMENT must be 'enforcing' or 'advisory', got {enforcement!r}. "
            f"Refusing to start (a wrong value would fail open).")
    store = store or EvidenceStore(os.environ.get("ATTESTATION_DB", "attestations.db"))
    replay = ReplayCache()
    cmcp_approved_policy_hash = cmcp_approved_policy_hash or os.environ.get("CMCP_APPROVED_POLICY_HASH")
    cmcp_approved_catalog_hash = cmcp_approved_catalog_hash or os.environ.get("CMCP_APPROVED_CATALOG_HASH")
    owns_client = client is None
    client = client or httpx.AsyncClient(base_url=upstream, timeout=30.0)

    async def _forward(request: Request, body: bytes) -> httpx.Response:
        fwd = {k: v for k, v in request.headers.items() if k.lower() not in _HOP}
        return await client.request(
            request.method, request.url.path, content=body,
            headers=fwd, params=dict(request.query_params),
        )

    def _passthrough_response(up: httpx.Response) -> Response:
        skip = {"content-length", "content-encoding", "transfer-encoding", "connection"}
        headers = {k: v for k, v in up.headers.items() if k.lower() not in skip}
        return Response(content=up.content, status_code=up.status_code,
                        headers=headers, media_type=up.headers.get("content-type"))

    async def submit(request: Request) -> Response:
        body = await request.body()
        agent_id = request.headers.get("X-Agent-ID", "")
        att_b64 = request.headers.get("X-Attestation")

        verdict = None
        ttl = max_age_seconds
        is_cmcp = False
        if att_b64:
            try:
                record = json.loads(base64.b64decode(att_b64))
            except Exception:
                record = None
            # F2: only a JSON object can be a record/claim. A list/str/number that happens to
            # contain "cmcp_version" (substring/membership) would otherwise reach .get() and 500.
            if not isinstance(record, dict):
                record = None
            if record is not None and "cmcp_version" in record:
                # C-1: cMCP RuntimeClaim envelope, verified via published cmcp_verify.
                is_cmcp = True
                ttl = cmcp_max_age_seconds
                if cmcp_approved_policy_hash and cmcp_approved_catalog_hash:
                    from bridge.cmcp_adapter import verify_cmcp_claim
                    verdict = verify_cmcp_claim(
                        record, agent_id_hex=agent_id,
                        approved_policy_hash=cmcp_approved_policy_hash,
                        approved_catalog_hash=cmcp_approved_catalog_hash,
                        max_age_seconds=cmcp_max_age_seconds,
                    )
                # else: no approved hashes configured -> verdict stays None (rejected under enforcing)
            elif record is not None:
                # C-2: standalone per-agent TRACE record (cnf == SAGE author key).
                verdict = verify_record(
                    record, agent_id_hex=agent_id, submit_body=body,
                    max_age_seconds=max_age_seconds,
                )

        # Policy gate
        if enforcement == "enforcing":
            if verdict is None:
                return JSONResponse(
                    {"error": "attestation_required",
                     "detail": "X-Attestation missing or unparseable; enforcing mode"},
                    status_code=422)
            if not verdict.ok:
                return JSONResponse(
                    {"error": "attestation_rejected", "detail": verdict.reason,
                     "checks": verdict.checks}, status_code=422)
            # De-dup byte-identical attestations within the freshness window (stops naive
            # third-party replay). NOT a per-write authorization control — see ReplayCache.
            # C-1 (cMCP) is SESSION provenance: the same session claim is legitimately reused
            # across writes, so it is NOT deduped (doing so would block normal reuse). Only the
            # body-bound C-2 record is single-use.
            if not is_cmcp and replay.check_and_mark(verdict.attestation_digest, ttl):
                return JSONResponse(
                    {"error": "attestation_replayed",
                     "detail": "byte-identical attestation already used within its freshness "
                               "window (de-dup only — not per-write authorization)"},
                    status_code=422)

        def _release_if_reserved() -> None:
            # F4: the C-2 replay reservation was taken before forwarding (to close the TOCTOU
            # race). Release it on ANY non-commit outcome so the attestation can be retried.
            # (C-1 is never reserved, so this is a no-op for it.)
            if enforcement == "enforcing" and not is_cmcp and verdict is not None and verdict.ok:
                replay.release(verdict.attestation_digest)

        # Forward the byte-identical signed request to SAGE. If the upstream is unreachable, the
        # forward RAISES — release the reservation (else a transient outage burns the attestation)
        # and return a clean 502 rather than a 500.
        try:
            up = await _forward(request, body)
        except httpx.HTTPError as exc:
            _release_if_reserved()
            return JSONResponse(
                {"error": "upstream_unreachable", "detail": str(exc)}, status_code=502)

        if up.status_code >= 300:
            _release_if_reserved()

        # On commit, persist evidence keyed by memory_id
        if up.status_code < 300 and verdict is not None and verdict.ok:
            try:
                mid = _extract_memory_id(up.json())
            except Exception:
                mid = None
            if mid:
                # The write already committed upstream. A persistence failure here must NOT turn
                # a committed write into a 500 — degrade to the passthrough 2xx (badge absent).
                try:
                    record = json.loads(base64.b64decode(att_b64))
                    store.put(Evidence(
                        memory_id=mid, agent_id=agent_id,
                        attestation_digest=verdict.attestation_digest,
                        cnf_thumbprint=verdict.cnf_thumbprint,
                        platform=verdict.platform or "unknown",
                        hardware_backed=verdict.hardware_backed,
                        record=record, verified_at=now(),
                    ))
                except Exception:  # noqa: BLE001 — evidence is best-effort; the write stands
                    return _passthrough_response(up)
                # Surface the bridge verdict back to the caller (additive header).
                resp = _passthrough_response(up)
                resp.headers["X-Attestation-Status"] = "verified"
                resp.headers["X-Attestation-Digest"] = verdict.attestation_digest
                return resp
        return _passthrough_response(up)

    async def attestation(request: Request) -> Response:
        badge = store.badge(request.path_params["memory_id"])
        if badge is None:
            return JSONResponse({"attested": False}, status_code=404)
        return JSONResponse(badge)

    async def passthrough(request: Request) -> Response:
        up = await _forward(request, await request.body())
        return _passthrough_response(up)

    import contextlib

    @contextlib.asynccontextmanager
    async def lifespan(app):
        try:
            yield
        finally:
            if owns_client:
                await client.aclose()

    routes = [
        # Gate the canonical submit path AND its trailing-slash variant, so a request to
        # /v1/memory/submit/ can't slip past the gate via the catch-all passthrough (F4).
        Route("/v1/memory/submit", submit, methods=["POST"]),
        Route("/v1/memory/submit/", submit, methods=["POST"]),
        Route("/v1/attestation/{memory_id}", attestation, methods=["GET"]),
        Route("/{path:path}", passthrough,
              methods=["GET", "POST", "PUT", "DELETE", "PATCH"]),
    ]
    return Starlette(routes=routes, lifespan=lifespan)
