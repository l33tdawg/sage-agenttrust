"""Verify a standalone TRACE Trust Record at the SAGE edge.

Four checks, in order:
  1. signature   — Ed25519 over the canonical record (signature field absent),
                   against the key in cnf.jwk.x. (Same recipe agentrust-trace signs with.)
  2. freshness   — iat within max_age_seconds.
  3. identity    — cnf key == the SAGE author key (X-Agent-ID). "The author IS the attested."
  4. request     — tool_transcript.hash == sha256 of the exact submit body being forwarded.

The verdict is *edge-trust*: it proves the authoring identity, the runtime/policy the
record asserts, freshness, and that this record authorizes THIS write. It does NOT prove
hardware (software-only records carry no silicon root) and is not re-checked in SAGE
consensus — that is deferred, on-chain pinning work. See README "What this does not claim".
"""

from __future__ import annotations

import base64
import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any

_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")  # urlsafe, no padding (TrustRecord.signature pattern)

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import rfc8785

from bridge.identity import agent_id_matches_cnf, jwk_thumbprint_sha256
from bridge.trace_record import body_digest


@dataclass
class Verdict:
    ok: bool
    checks: dict[str, bool] = field(default_factory=dict)
    reason: str | None = None
    cnf_thumbprint: str | None = None
    attestation_digest: str | None = None  # sha256 of canonical record (the on-chain pin)
    platform: str | None = None
    hardware_backed: bool = False
    # C-1 only: True when the gateway signing key was checked against a key the operator pinned
    # (cmcp_verify's `trusted_public_key`). C-2 is key-equal by construction and leaves this False.
    identity_anchored: bool = False


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _canonical(record: dict[str, Any]) -> bytes:
    # RFC 8785 (JCS) — the signature pre-image mandated by spec §3.2.2, and what
    # agentrust_trace.sign._canonical_bytes does from 0.10.0 onward. Before that the library
    # used a plain json.dumps(sort_keys=True, ensure_ascii=True), which is not JCS: it escapes
    # non-ASCII where JCS keeps raw UTF-8, and it formats numbers the Python way instead of the
    # ES shortest-round-trip way. The bridge follows the library so that the signature it
    # accepts, the digest it pins, and the bytes a spec-conformant third-party verifier
    # computes are the same.
    body = {k: v for k, v in record.items() if k != "signature"}
    return rfc8785.dumps(body)


def verify_record(
    record: dict[str, Any],
    *,
    agent_id_hex: str,
    submit_body: bytes,
    max_age_seconds: int = 300,
    now: int | None = None,
) -> Verdict:
    checks: dict[str, bool] = {}
    now = now or int(time.time())

    # cnf + platform (needed for reporting even on failure). Be defensive: a malformed record
    # may have non-dict sub-objects — never let field access raise (F1 DoS).
    cnf = record.get("cnf") if isinstance(record.get("cnf"), dict) else {}
    jwk = cnf.get("jwk") if isinstance(cnf.get("jwk"), dict) else {}
    x_b64u = jwk.get("x")
    if not isinstance(x_b64u, str) or not x_b64u:
        return Verdict(ok=False, checks=checks, reason="record has no string cnf.jwk.x")
    rt = record.get("runtime")
    platform = rt.get("platform") if isinstance(rt, dict) else None
    # The bridge does NOT verify hardware roots. A C-2 record's runtime.platform is
    # self-asserted by the agent (the whole record is self-signed), so it is never trusted as
    # evidence of hardware. hardware is ALWAYS unverified here; platform is recorded as claimed.
    hardware_backed = False
    digest = "sha256:" + hashlib.sha256(_canonical(record)).hexdigest()
    thumb = jwk_thumbprint_sha256(x_b64u)

    def out(ok: bool, reason: str | None = None) -> Verdict:
        return Verdict(
            ok=ok, checks=checks, reason=reason,
            cnf_thumbprint=thumb, attestation_digest=digest,
            platform=platform, hardware_backed=hardware_backed,
        )

    # 0. canonical encoding (IDB-1): cnf.jwk.x must be the canonical urlsafe-no-pad encoding
    # of its own decoded bytes. urlsafe_b64decode silently accepts std-base64 ('+'/'/'),
    # which would make our thumbprint/digest diverge from the RFC7638 on-chain pin. Reject any
    # non-canonical encoding so the accepted 'x', the thumbprint, and the pin are identical.
    try:
        pub_raw = _b64u_decode(x_b64u)
        if x_b64u != base64.urlsafe_b64encode(pub_raw).rstrip(b"=").decode():
            checks["canonical_encoding"] = False
            return out(False, "cnf.jwk.x is not canonical base64url (would diverge from the pin)")
        checks["canonical_encoding"] = True
    except (ValueError, TypeError):
        checks["canonical_encoding"] = False
        return out(False, "cnf.jwk.x is not decodable base64url")

    # 1. signature — require canonical urlsafe-no-pad encoding (TRACE-4), then Ed25519-verify
    sig_b64 = record.get("signature", "")
    if not isinstance(sig_b64, str) or not _B64URL.fullmatch(sig_b64):
        checks["signature"] = False
        return out(False, "signature is not canonical base64url (urlsafe, no padding)")
    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_raw)
        sig = _b64u_decode(sig_b64)
        pub.verify(sig, _canonical(record))
        checks["signature"] = True
    except (InvalidSignature, ValueError, TypeError):
        checks["signature"] = False
        return out(False, "signature verification failed")

    # 2. freshness
    try:
        iat = int(record.get("iat", 0))
    except (ValueError, TypeError):
        checks["freshness"] = False
        return out(False, "iat is not an integer")
    checks["freshness"] = 0 < iat <= now + 5 and (now - iat) <= max_age_seconds
    if not checks["freshness"]:
        return out(False, f"record stale or future-dated (iat={iat}, now={now})")

    # 3. identity binding: cnf key == SAGE author key
    checks["identity_binding"] = agent_id_matches_cnf(agent_id_hex, x_b64u)
    if not checks["identity_binding"]:
        return out(False, "cnf key does not match X-Agent-ID (author != attested key)")

    # 4. request binding: this record authorizes THIS submit body
    expected = body_digest(submit_body)
    tt = record.get("tool_transcript")
    actual = tt.get("hash") if isinstance(tt, dict) else None
    checks["request_binding"] = actual == expected
    if not checks["request_binding"]:
        return out(False, "tool_transcript.hash does not match submit body (replay/mismatch)")

    return out(True, None)
