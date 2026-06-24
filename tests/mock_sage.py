"""Minimal mock of a STOCK SAGE node for in-process testing.

It verifies the SAGE Ed25519 request signature *exactly* the way the real node does
(SHA256(method+" "+path+"\\n"+body) || BE int64 ts || nonce). If the proxy ever mutated
the body, this signature check would fail — so a green test proves byte-identical
forwarding. On a valid submit it returns a deterministic memory_id, like the real node.
"""

from __future__ import annotations

import hashlib
import json
import struct

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

_committed: dict[str, dict] = {}


def _verify_sage_sig(method: str, path: str, body: bytes, headers) -> bool:
    try:
        pub = bytes.fromhex(headers["x-agent-id"])
        sig = bytes.fromhex(headers["x-signature"])
        ts = int(headers["x-timestamp"])
        nonce = bytes.fromhex(headers["x-nonce"])
    except (KeyError, ValueError):
        return False
    canonical = method.encode() + b" " + path.encode() + b"\n" + body
    body_hash = hashlib.sha256(canonical).digest()
    message = body_hash + struct.pack(">q", ts) + nonce
    try:
        VerifyKey(pub).verify(message, sig)
        return True
    except BadSignatureError:
        return False


async def submit(request: Request) -> JSONResponse:
    body = await request.body()
    if not _verify_sage_sig("POST", "/v1/memory/submit", body, request.headers):
        return JSONResponse({"error": "bad_signature"}, status_code=401)
    payload = json.loads(body)
    mid = "mem-" + hashlib.sha256(body).hexdigest()[:24]
    _committed[mid] = payload
    return JSONResponse(
        {"memory_id": mid, "tx_hash": "tx-" + mid, "status": "committed"}
    )


async def query(request: Request) -> JSONResponse:
    return JSONResponse({"results": [
        {"memory_id": mid, **{k: rec.get(k) for k in ("content", "domain_tag")}}
        for mid, rec in _committed.items()
    ]})


def build_mock_sage() -> Starlette:
    return Starlette(routes=[
        Route("/v1/memory/submit", submit, methods=["POST"]),
        Route("/v1/memory/query", query, methods=["POST"]),
    ])


# ── Realistic mock: models the real node's 201/proposed -> async commit lifecycle and an
#    auth-checked recall, so the offline suite can exercise the demo's poll-to-committed path. ──
_lifecycle: dict[str, dict] = {}


async def submit_realistic(request: Request) -> JSONResponse:
    body = await request.body()
    if not _verify_sage_sig("POST", "/v1/memory/submit", body, request.headers):
        return JSONResponse({"error": "bad_signature"}, status_code=401)
    mid = "mem-" + hashlib.sha256(body).hexdigest()[:24]
    _lifecycle[mid] = {"status": "proposed", "polls": 0, "payload": json.loads(body)}
    return JSONResponse({"memory_id": mid, "tx_hash": "tx-" + mid, "status": "proposed"},
                        status_code=201)  # like the real node: accepted as proposed


async def get_memory_realistic(request: Request) -> JSONResponse:
    mid = request.path_params["memory_id"]
    if not _verify_sage_sig("GET", f"/v1/memory/{mid}", b"", request.headers):
        return JSONResponse({"error": "bad_signature"}, status_code=401)  # reads are authed too
    rec = _lifecycle.get(mid)
    if not rec:
        return JSONResponse({"error": "not_found"}, status_code=404)
    rec["polls"] += 1
    if rec["polls"] >= 1:  # auto-validator commits asynchronously
        rec["status"] = "committed"
    return JSONResponse({"memory_id": mid, "status": rec["status"]})


async def query_realistic(request: Request) -> JSONResponse:
    body = await request.body()
    if not _verify_sage_sig("POST", "/v1/memory/query", body, request.headers):
        return JSONResponse({"error": "bad_signature"}, status_code=401)  # recall is authed
    return JSONResponse({"results": [{"memory_id": m} for m in _lifecycle]})


def build_realistic_mock_sage() -> Starlette:
    return Starlette(routes=[
        Route("/v1/memory/submit", submit_realistic, methods=["POST"]),
        Route("/v1/memory/{memory_id}", get_memory_realistic, methods=["GET"]),
        Route("/v1/memory/query", query_realistic, methods=["POST"]),
    ])
