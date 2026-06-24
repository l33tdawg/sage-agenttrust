# sage-agenttrust

An attestation-verifying reverse proxy that gates **`POST /v1/memory/submit`** on a **stock,
unmodified SAGE consensus-memory node** with a verified AgentTrust attestation, binding the
attested **identity** to the on-chain memory author. Runs entirely against released PyPI
packages (`cmcp-runtime`, `agentrust-trace`); SAGE core needs no changes.

[SAGE](https://github.com/l33tdawg/sage) is consensus-validated agent memory (memories go
through BFT consensus, carry confidence, decay). [AgentTrust](https://github.com/agentrust-io)
provides agent execution attestation (cMCP gateway + the TRACE evidence format). This bridge
lets a SAGE memory submission be committed **with** its attestation evidence, retrievable by
`memory_id` as a provenance badge — *which attested identity authored it under which policy* —
provenance, not a truth claim.

> **Scope (read this first).** Two things this bridge does **not** do:
> 1. **No hardware attestation.** Against the **published** AgentTrust packages (v0.2.x) it
>    verifies an **edge-verified cryptographic identity** (C-2's `cnf == author` key equality)
>    **plus policy/catalog-hash provenance** — *not* hardware. The published `cmcp_verify`
>    defers all silicon-root checks (TPM EK chains, AMD VCEK, Intel DCAP quote signatures) as
>    "out of scope for Phase 1," so the bridge **never** asserts `hardware_backed` and treats a
>    claimed TEE platform as self‑declared.
> 2. **Only the submit endpoint is gated.** It attestation-gates `POST /v1/memory/submit` only.
>    Other SAGE writes (`/forget`, `/vote`, `/corroborate`, `/challenge`, governance, access)
>    **pass through ungated** to SAGE's own Ed25519 auth + RBAC — they are out of scope for this
>    submission-provenance integration.
>
> See [What this does NOT claim](#what-this-does-not-claim).

## How it works

```
 agent ── signs SAGE submit (Ed25519) ─┐
        └ presents TRACE attestation ──┤  X-Attestation header
                                       ▼
        attestation-verifying proxy  (this repo)
          1. verify the attestation at the edge
          2. bind it to the SAGE author key (X-Agent-ID)
          3. forward the BYTE-IDENTICAL signed request to stock SAGE
          4. on commit, store the evidence keyed by memory_id
                                       ▼
                stock SAGE node ── BFT consensus commit
                                       ▼
        GET /v1/attestation/{memory_id} ── provenance badge
```

The proxy never rewrites the signed body, so SAGE's Ed25519 signature stays valid — that is
why the node needs no changes.

### Two attestation paths

| Path | Role | Attestation | Binding to SAGE author |
|---|---|---|---|
| **C-2 per-agent** (`bridge/trace_verify.py`) | **enforcing — the security path** | a standalone TRACE record whose `cnf` **is** the agent's SAGE Ed25519 key | **cryptographic key equality** (`cnf.jwk.x` decodes to `X-Agent-ID`, canonical-encoding enforced) **+ per-write body binding** (`tool_transcript.hash == sha256(body)`). This is the strong, write-scoped guarantee. |
| **C-1 cMCP** (`bridge/cmcp_adapter.py`) | **advisory — session provenance** | a cMCP RuntimeClaim, signature/policy/catalog verified via published `cmcp_verify.verify_trace_claim`; passes `agentrust-trace-tests` **0.1.0 Level 0** | **gateway-asserted** identity (exact match on `gateway.agent_identity.agent_id`). A RuntimeClaim is **session-scoped with no per-write binding**, and the controlling agent can re-mint claims — so C-1 is *provenance that an agent ran behind an attested gateway*, **not** per-write authorization. |

Both paths **gate** the write in `enforcing` mode — a valid attestation of *either* kind admits
the write; a missing/invalid one returns 422. "advisory" vs "the security path" describe the
*evidence strength*, **not** whether the path gates: C-2 yields a write-scoped cryptographic
guarantee, C-1 only session provenance. (C-1 is disabled — every cMCP claim 422s — unless
`CMCP_APPROVED_POLICY_HASH` / `CMCP_APPROVED_CATALOG_HASH` are configured; see `bridge/app.py`.)

The proxy de-duplicates byte-identical attestations within their freshness window
(`bridge/proxy.py` `ReplayCache`) to stop naive third-party replay — this is **not** a per-write
authorization control (C-2's body binding is). `agentrust-trace-tests` cryptographically grades
only the cMCP-envelope form; it **rejects** a bare C-2 record (`LoadError`: a `signature` field
without `cmcp_version`), so we make **no** conformance-level claim for C-2 — its binding is
bridge-verified.

## What this does NOT claim

Per [agentrust-io/integrations CONTRIBUTING rule 4](https://github.com/agentrust-io/integrations/blob/main/CONTRIBUTING.md):

- **No hardware attestation.** With the published AgentTrust stack, the bridge does **not**
  verify any hardware root of trust. `cmcp_verify`'s per-platform verifiers check the
  measurement **format/parse** but **defer the silicon root of trust** — TPM EK cert chains, AMD
  VCEK/VLEK, and Intel DCAP quote signatures are placed in *unverified_fields* ("out of scope
  for Phase 1") — and a C-2 record's `runtime.platform` is self-asserted. So the bridge
  **never** reports `hardware_backed: true`, `verification` is always `edge-only`, and a claimed
  TEE platform is surfaced only as `platform_claimed` (self-declared, unverified). Real hardware
  verification is gated on
  AgentTrust completing those deferred silicon-root checks.
- **Attestation ≠ content truth.** It authenticates the *author and policy* of a write, not
  whether the content is correct. SAGE's `ContentHash` and `confidence_score` remain
  client-asserted; a legitimately-attested agent can still write a wrong memory.
- **C-1 (cMCP) is session provenance, not per-write authorization, with no trust root.** A cMCP
  RuntimeClaim has no field binding it to a particular SAGE body, and the agent controls the
  gateway key, so it can re-mint claims at will. In this configuration the gateway signing key is
  **not anchored to any trusted issuer** — a valid C-1 signature authenticates only the claim's
  structure and that its policy/catalog hashes match the configured approved set; anyone can mint
  a signature-valid claim naming any `agent_id`. C-1 therefore attests *that an agent operated
  behind an attested gateway during a session*, not the truth or authorization of any write. The
  write-scoped, key-equal guarantee is **C-2**'s.
- **Canonicalization follows the published library, not RFC 8785.** The bridge signs/verifies
  TRACE records with the exact recipe `agentrust_trace.sign` uses (sorted-keys compact JSON,
  `ensure_ascii=True`) so it interoperates with the library. That recipe equals RFC 8785 / JCS
  only for ASCII string content with integer numbers; for non-ASCII string fields (e.g. a
  Unicode `domain_tag`) **and for IEEE 754 number serialization** the bytes diverge from a
  spec-conformant verifier. This is an upstream `agentrust_trace` gap; use ASCII string fields
  (and integer numerics) for cross-verifier interop.
- **The provenance badge endpoint is unauthenticated.** `GET /v1/attestation/{memory_id}` is
  public read-only and returns no secrets, but it does disclose the attestation digest, `cnf`
  thumbprint, and SPIFFE subject for any known `memory_id`. Gate it behind SAGE's auth if that
  metadata is sensitive in your deployment.
- **The badge reflects submit-time edge verification, not consensus state.** SAGE returns a
  submit as `proposed` (HTTP 201) and commits asynchronously; the bridge stamps
  `X-Attestation-Status: verified` and stores the badge at that point. The badge attests *the
  attestation was edge-verified when the write was admitted*, not that the memory is committed
  (poll `GET /v1/memory/{id}` for consensus status).
- **Edge-trust, not in-consensus.** Verification happens at the proxy. The attestation digest
  is **not** re-checked inside SAGE consensus today. Pinning the digest on-chain + a
  deterministic in-consensus author-binding check is proposed upstream as future work, not
  shipped here (and would require SAGE core changes, which this integration deliberately avoids).
- **Replay protection is best-effort.** The `ReplayCache` is process-local (a multi-instance
  deployment needs a shared store) and only blocks in `enforcing` mode. A byte-identical C-2
  attestation is de-duped for the **full freshness window** (`BRIDGE_MAX_AGE`, default 300 s);
  the only re-admit gap is a worst-case ~5 s sliver when `iat` is maximally future-dated within
  the skew tolerance. C-2's body binding keeps replays low-impact (a replay can only re-write the
  same body).

## Run it

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"     # runtime: agentrust-trace, cmcp-runtime, cryptography, httpx, starlette, uvicorn · dev: agentrust-trace-tests + pynacl (offline mock only)

# 1) a stock SAGE node, isolated in Docker (no host mount = ephemeral)
docker run -d --name sage-demo -p 127.0.0.1:18080:8080 \
  -e SAGE_PASSPHRASE=demo-passphrase ghcr.io/l33tdawg/sage:latest serve

# 2) the bridge proxy in front of it
SAGE_UPSTREAM=http://127.0.0.1:18080 uvicorn bridge.app:app --port 19090

# 3) the end-to-end demo (attested submit -> consensus commit -> provenance-badge fetch)
BRIDGE_URL=http://127.0.0.1:19090 python demo/run_demo.py
```

SAGE accepts a submit as `proposed` (HTTP 201) and commits it **asynchronously** via its
auto-validator — so the demo polls `GET /v1/memory/{id}` until the status flips to `committed`.
The demo writes to the reserved `general` domain (a fresh agent can't claim an owned domain on a
warm node); on a fresh container any domain works.

## Tests

```bash
./run_tests.sh   # offline: crypto core, proxy vs a signature-verifying mock SAGE, cMCP verify, conformance
```

The offline suite needs no node (it uses a mock SAGE that verifies the real Ed25519 signature,
so byte-identical forwarding is still proven). `demo/run_demo.py` is the live end-to-end run
against a stock SAGE container.

## Layout

```
bridge/identity.py        one Ed25519 key -> SAGE agent_id AND TRACE cnf; the binding check
bridge/trace_record.py    mint a per-agent TRACE record bound to a submit body
bridge/trace_verify.py    edge verify: signature, freshness, identity-binding, request-binding
bridge/cmcp_adapter.py    verify a cMCP RuntimeClaim via published cmcp_verify; gateway binding
bridge/proxy.py           the reverse proxy (closed-enum enforcement, replay de-dup, routes C-1/C-2)
bridge/evidence_store.py  off-chain evidence keyed by memory_id; the recall badge
bridge/app.py             ASGI entrypoint (env config)
client/attested_client.py builds an attested SAGE submit
demo/run_demo.py          live end-to-end demo
tests/                    offline suite: core, proxy e2e, cmcp, hardening, conformance (./run_tests.sh)
```

## License

Apache-2.0. Maintainer: [@l33tdawg](https://github.com/l33tdawg).
