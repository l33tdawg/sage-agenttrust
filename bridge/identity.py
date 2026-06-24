"""Shared agent identity: one Ed25519 key drives both the SAGE request signature
and the TRACE record's confirmation (`cnf`) key.

This is the whole point of the bridge's binding model: the key that authors a SAGE
memory IS the key the TRACE Trust Record proves possession of. There is no identity
to reconcile — `X-Agent-ID` (SAGE) and `cnf.jwk.x` (TRACE) are two encodings of the
same 32-byte Ed25519 public key.

SAGE's SDK signs with PyNaCl; agentrust-trace signs with `cryptography`. Both are raw
Ed25519, so a single 32-byte seed produces an identical public key under either library.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import struct
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def cnf_jwk(pub_raw: bytes) -> dict[str, str]:
    """Public JWK (OKP/Ed25519) for a raw 32-byte Ed25519 public key."""
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64u(pub_raw)}


def jwk_thumbprint_sha256(x_b64u: str) -> str:
    """RFC 7638 JWK thumbprint as **hex**. Shares the exact RFC 7638 preimage/construction
    `cmcp_verify._jwk_thumbprint_sha256` uses (which returns the raw digest), so the underlying
    value matches; this returns the hex encoding for display/audit. Used as a provenance/pin
    identifier, not compared byte-for-byte against cmcp_verify's raw output."""
    canonical = json.dumps(
        {"crv": "Ed25519", "kty": "OKP", "x": x_b64u},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


@dataclass
class AgentKey:
    """A single Ed25519 key, usable for SAGE signing and TRACE minting."""

    seed: bytes  # 32-byte Ed25519 seed

    @classmethod
    def generate(cls) -> "AgentKey":
        return cls(secrets.token_bytes(32))

    @classmethod
    def from_seed_file(cls, path: str) -> "AgentKey":
        if os.path.exists(path):
            with open(path, "rb") as f:
                return cls(f.read(32))
        key = cls.generate()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "wb") as f:
            f.write(key.seed)
        return key

    @property
    def _sk(self) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(self.seed)

    @property
    def public_raw(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return self._sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def agent_id(self) -> str:
        """SAGE agent_id == hex of the 32-byte Ed25519 public key."""
        return self.public_raw.hex()

    @property
    def cnf(self) -> dict[str, str]:
        return cnf_jwk(self.public_raw)

    @property
    def thumbprint(self) -> str:
        return jwk_thumbprint_sha256(self.cnf["x"])

    # ── TRACE minting key (cryptography) ──────────────────────────────────────
    def crypto_signing_key(self) -> Ed25519PrivateKey:
        return self._sk

    # ── SAGE request signing (mirrors sdk/python/.../auth.py exactly) ─────────
    def sign_sage_request(
        self, method: str, path: str, body: bytes, timestamp: int | None = None
    ) -> dict[str, str]:
        """Reproduce SAGE's AgentIdentity.sign_request:
        message = SHA256(method+" "+path+"\\n"+body) || big-endian int64(ts) || nonce(8)

        NOTE: *path* must already include any query string. SAGE signs method+path?query+body;
        the SAGE SDK appends the urlencoded params to the signed path. This helper signs exactly
        the `path` it is given — pass the full path-with-query for endpoints that use query
        params (the submit/recall paths used here are query-less, so a bare path is correct).
        """
        ts = timestamp or int(time.time())
        nonce = secrets.token_bytes(8)
        canonical = method.encode() + b" " + path.encode() + b"\n" + body
        body_hash = hashlib.sha256(canonical).digest()
        message = body_hash + struct.pack(">q", ts) + nonce
        sig = self._sk.sign(message)
        return {
            "X-Agent-ID": self.agent_id,
            "X-Signature": sig.hex(),
            "X-Timestamp": str(ts),
            "X-Nonce": nonce.hex(),
        }


def agent_id_matches_cnf(agent_id_hex: str, cnf_x_b64u: str) -> bool:
    """The binding check: SAGE author key == TRACE cnf key (raw-pubkey equality).

    Requires X-Agent-ID to be CANONICAL lowercase hex of exactly the pubkey bytes. SAGE stores
    the agent_id verbatim, so an upper/mixed-case hex would author a *different* on-chain string
    for the same key — we reject it (mirrors the canonical cnf.jwk.x check).
    """
    try:
        raw = bytes.fromhex(agent_id_hex)
        if agent_id_hex != raw.hex():  # canonical: lowercase, no stray chars
            return False
        return raw == _b64u_decode(cnf_x_b64u)
    except (ValueError, TypeError):
        return False
