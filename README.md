# sage-agenttrust

An attestation-verifying reverse proxy that gates **`POST /v1/memory/submit`** on a **stock,
unmodified SAGE consensus-memory node** with a verified AgentTrust attestation, binding the
attested **identity** to the on-chain memory author. Runs entirely against released PyPI
packages (`cmcp-runtime`, `agentrust-trace`); SAGE core needs no changes.

**Verified against** (2026-09-15): SAGE `v11.19.22`
(`ghcr.io/l33tdawg/sage@sha256:380fcae7…`, stock and unmodified), `agentrust-trace` 0.10.0,
`cmcp-runtime` 0.5.0, `agentrust-trace-tests` 0.5.1. The offline suite and the live end-to-end
demo (attested submit → consensus commit → provenance badge) were both run against exactly
those versions.

[SAGE](https://github.com/l33tdawg/sage) is consensus-validated agent memory (memories go
through BFT consensus, carry confidence, decay). [AgentTrust](https://github.com/agentrust-io)
provides agent execution attestation (cMCP gateway + the TRACE evidence format). This bridge
lets a SAGE memory submission be committed **with** its attestation evidence, retrievable by
`memory_id` as a provenance badge — *which attested identity authored it under which policy* —
provenance, not a truth claim.

> **Scope (read this first).** Two things this bridge does **not** do:
> 1. **Hardware attestation is opt-in, and off by default.** Out of the box the bridge verifies an
>    **edge-verified cryptographic identity** (C-2's `cnf == author` key equality) **plus
>    policy/catalog-hash provenance** — *not* hardware. `cmcp_verify` 0.5.0 can verify a silicon
>    root (TPM AK/EK chain to a pinned manufacturer CA, AMD VCEK/VLEK, Intel DCAP quotes), but only
>    against a root the caller pins, and the bridge ships pinning none — so it reports
>    `hardware_backed: false` and surfaces a claimed TEE platform as self-declared
>    (`platform_claimed`). [Anchoring the C-1 path](#anchoring-the-c-1-path-optional) changes that,
>    and the badge says which state you are in.
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
| **C-1 cMCP** (`bridge/cmcp_adapter.py`) | **advisory — session provenance** | a cMCP RuntimeClaim, signature/policy/catalog verified via published `cmcp_verify.verify_trace_claim`; passes `agentrust-trace-tests` **0.5.1 Level 0** | **gateway-asserted** identity (exact match on `gateway.agent_identity.agent_id`). A RuntimeClaim is **session-scoped with no per-write binding**, and the controlling agent can re-mint claims — so C-1 is *provenance that an agent ran behind an attested gateway*, **not** per-write authorization. |

Both paths **gate** the write in `enforcing` mode — a valid attestation of *either* kind admits
the write; a missing/invalid one returns 422. "advisory" vs "the security path" describe the
*evidence strength*, **not** whether the path gates: C-2 yields a write-scoped cryptographic
guarantee, C-1 only session provenance. (C-1 is disabled — every cMCP claim 422s — unless
`CMCP_APPROVED_POLICY_HASH` / `CMCP_APPROVED_CATALOG_HASH` are configured; see `bridge/app.py`.)

The proxy de-duplicates byte-identical attestations within their freshness window
(`bridge/proxy.py` `ReplayCache`) to stop naive third-party replay — this is **not** a per-write
authorization control (C-2's body binding is).

**Both paths are graded by `agentrust-trace-tests` 0.5.1, and both pass Level 0.** That is an
upgrade on the first release of this bridge: `agentrust-trace-tests` 0.1.0 raised `LoadError` on
a standalone TRACE record (a `signature` field with no `cmcp_version`), so the C-2 path carried
**no** conformance claim at all and its binding rested entirely on bridge-side verification. The
0.5.1 loader accepts the bare record as `fmt="trace"`, which lets the bridge assert the stronger
and still-honest pair for both paths: Level 0 **passes** with 0 failing findings, and Level 1
**fails** — software-only has no hardware root. `tests/test_conformance.py` fails if either half
of that stops being true.

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
- **C-1 (cMCP) is session provenance, not per-write authorization — anchored only if you anchor
  it.** A cMCP RuntimeClaim has no field binding it to a particular SAGE body, and the agent
  controls the gateway key, so it can re-mint claims at will. With no anchor configured (the
  default) the gateway signing key is **not checked against anything** — a valid C-1 signature
  authenticates only the claim's structure and that its policy/catalog hashes match the configured
  approved set, so anyone can mint a signature-valid claim naming any `agent_id`. C-1 therefore
  attests *that an agent operated behind an attested gateway during a session*, not the truth or
  authorization of any write. Pinning the gateway key closes the substitution — see below — but it
  does not create a per-write binding, which stays **C-2**'s guarantee.
- **Canonicalization is RFC 8785 (JCS), and the bridge follows the library.** From
  `agentrust-trace` 0.10.0, `sign_record` canonicalizes with `rfc8785.dumps`, as spec §3.2.2
  requires, and the bridge uses the same recipe for its signature check and for the attestation
  digest it pins — so the bytes it accepts are the bytes a spec-conformant third-party verifier
  computes. Earlier releases of the library used `json.dumps(sort_keys=True, ensure_ascii=True)`,
  which diverges from JCS for non-ASCII strings and for number formatting; the bridge tracked that
  older recipe deliberately to stay interoperable with the library, and this refresh moved both
  forward together.
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

## Anchoring the C-1 path (optional)

The cMCP path is the one with a trust root to configure. Every anchor below is off unless you set
it, and each only ever *adds* a check — an unanchored bridge behaves exactly as it did before.

| Variable | What it pins | What it buys |
|---|---|---|
| `CMCP_TRUSTED_GATEWAY_KEY_HEX` | the gateway signing key (hex, `0x` optional) | the pinned-key check becomes **required**: a claim carrying any other key is rejected. Without it, "anyone can mint a claim" is literally true. |
| `CMCP_TRUSTED_TPM_CA_PEM` | PEM of the manufacturer CA for TPM | `cmcp_verify` verifies the AK/EK chain, not just the quote's format |
| `CMCP_TRUSTED_ARK_PEM` | PEM for the AMD ARK | the same, for SEV-SNP VCEK chains |
| `CMCP_TRUSTED_INTEL_ROOT_PEM` | PEM for the Intel SGX root CA | the same, for DCAP quotes |
| `CMCP_EXPECTED_GATEWAY_MEASUREMENT` | the gateway measurement you expect | binds `report_data` to a value *you* chose rather than one the claim supplied |

```bash
CMCP_APPROVED_POLICY_HASH=sha256:... CMCP_APPROVED_CATALOG_HASH=sha256:... \
CMCP_TRUSTED_GATEWAY_KEY_HEX=<hex> CMCP_TRUSTED_TPM_CA_PEM=/etc/sage/trusted-tpm-ca.pem \
SAGE_UPSTREAM=http://127.0.0.1:18080 uvicorn bridge.app:app --port 19090
```

A root that cannot be read, or that does not look like a PEM, stops startup rather than leaving the
bridge looking anchored while checking nothing. `hardware_verified` turns true only when you pinned
a per-platform root *and* the library reported that chain verified, and the badge's `binding` field
reads `pinned-issuer ...` instead of `gateway-asserted (no trust root)` once the key check passes.
Programmatic users get the same surface through `bridge.cmcp_adapter.CmcpTrust`, which also exposes
`agent_manifest` / `trusted_agent_manifest_keys` (not wired to environment variables here).

## Run it

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"     # runtime: agentrust-trace, cmcp-runtime, cryptography, httpx, rfc8785, starlette, uvicorn · dev: agentrust-trace-tests + pynacl (offline mock only)

# 1) a stock SAGE node, isolated in Docker (no host mount = ephemeral). Pinned by digest to the
#    v11.19.22 release this bridge is verified against, so :latest moving cannot invalidate it.
docker run -d --name sage-demo -p 127.0.0.1:18080:8080 -e SAGE_PASSPHRASE=demo-passphrase \
  ghcr.io/l33tdawg/sage@sha256:380fcae7b86712d5882a8c3676265d976d7a96a3eeed74559079994cd63f6b0a serve

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
