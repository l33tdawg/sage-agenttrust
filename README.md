# sage-agenttrust

An attestation-verifying reverse proxy that gates **`POST /v1/memory/submit`** on a **stock,
unmodified SAGE consensus-memory node** with a verified AgentTrust attestation, binding the
attested **identity** to the on-chain memory author. Runs entirely against released PyPI
packages (`cmcp-runtime`, `agentrust-trace`); SAGE core needs no changes.

**Historical test baseline** (2026-09-15): SAGE `v11.19.22`
(`ghcr.io/l33tdawg/sage@sha256:380fcae7…`, stock and unmodified), `agentrust-trace` 0.10.0,
`cmcp-runtime` 0.5.0, `agentrust-trace-tests` 0.5.1. The offline suite and the live end-to-end
demo (attested submit → consensus commit → provenance badge) were both run against exactly
those versions. The hardware withdrawal below is validated by offline tests; it is not a
new live acceptance run or a hardware qualification.

[SAGE](https://github.com/l33tdawg/sage) is consensus-validated agent memory (memories go
through BFT consensus, carry confidence, decay). [AgentTrust](https://github.com/agentrust-io)
provides agent execution attestation (cMCP gateway + the TRACE evidence format). This bridge
stores off-chain attestation evidence after a successful SAGE submit response containing a
`memory_id`, retrievable as a provenance badge — *which attested identity authored it under
which policy*. A badge does not establish that consensus committed the memory or that its
content is true.

> **Scope (read this first).** Two things this bridge does **not** do:
> 1. **Hardware verification is unsupported under the current dependency pin.** The bridge
>    retains software C-1 session provenance and C-2's cryptographic author/body binding.
>    Silicon roots, expected hardware measurements, and hardware-shaped C-1 claims fail closed
>    under `cmcp-runtime` 0.5. Badges always report `hardware_verified: false`; C-2 platform
>    names remain self-declared. [Software C-1 identity anchoring](#anchoring-the-c-1-path-optional)
>    can pin a gateway key without claiming hardware verification.
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
          4. on 2xx with memory_id, store off-chain evidence
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
| **C-1 cMCP** (`bridge/cmcp_adapter.py`) | **advisory — session provenance** | a software-only cMCP RuntimeClaim, signature/policy/catalog verified via published `cmcp_verify.verify_trace_claim`; passes `agentrust-trace-tests` **0.5.1 Level 0** | **gateway-asserted** identity (exact match on `gateway.agent_identity.agent_id`). A RuntimeClaim is **session-scoped with no per-write binding**, and the controlling agent can re-mint claims — so C-1 is *provenance that an agent ran behind an attested gateway*, **not** per-write authorization. |

Both paths **gate** the write in `enforcing` mode — a valid attestation of *either* kind admits
the write; a missing/invalid one returns 422. "advisory" vs "the security path" describe the
*evidence strength*, **not** whether the path gates: C-2 yields a write-scoped cryptographic
guarantee, C-1 only session provenance. (C-1 is disabled — every cMCP claim 422s — unless
`CMCP_APPROVED_POLICY_HASH` / `CMCP_APPROVED_CATALOG_HASH` are configured; see `bridge/app.py`.)

The proxy de-duplicates byte-identical **C-2** attestations within their freshness window
(`bridge/proxy.py` `ReplayCache`). C-1 session claims remain reusable across writes; C-2's
body binding supplies the per-write authorization control.

**Both paths are graded by `agentrust-trace-tests` 0.5.1, and both pass Level 0.** That is an
upgrade on the first release of this bridge: `agentrust-trace-tests` 0.1.0 raised `LoadError` on
a standalone TRACE record (a `signature` field with no `cmcp_version`), so the C-2 path carried
**no** conformance claim at all and its binding rested entirely on bridge-side verification. The
0.5.1 loader accepts the bare record as `fmt="trace"`, which lets the bridge assert the stronger
and still-honest pair for both paths: Level 0 **passes** with 0 failing findings, and Level 1
**fails** — software-only has no hardware root. `tests/test_conformance.py` fails if either half
of that stops being true.

## What this does NOT claim

Per [agentrust-io/integrations contribution rules](https://github.com/agentrust-io/integrations/blob/main/CONTRIBUTING.md):

- **No qualified hardware verification.** The pinned `cmcp-runtime` 0.5 series predates
  the TPM key-binding and PCR measurement corrections documented in the upstream
  [0.7.0 security release](https://github.com/agentrust-io/cmcp/releases/tag/v0.7.0).
  The bridge therefore refuses silicon-root/measurement configuration and rejects every C-1
  hardware runtime claim before calling the old verifier. The supported software shapes are
  `trace.runtime.platform: software-only` and the legacy `tpm2` platform with
  `firmware_version: software-only-dev-mode`; the latter is explicitly non-attested software,
  and its platform label gives no hardware credit.
  Hardware evidence under `gateway.attestation_evidence` or legacy runtime evidence fields
  also rejects, even when a software platform is declared.
  An unexpected library `hardware_attestation` success also rejects. C-2 platform names remain
  self-declared, with no hardware credit. No dependency upgrade or hardware qualification is
  claimed here. Public badges always set `hardware_verified: false`. Previously stored true
  flags are retained as audit evidence, exposed only as `historical_hardware_backed: true`
  with `hardware_verification: legacy-unqualified`; badge reads do not rewrite stored records.
- **Attestation ≠ content truth.** It authenticates the *author and policy* of a write, not
  whether the content is correct. Content and confidence remain agent claims; content hashing
  and per-write body binding do not prove truth. A legitimately-attested agent can still
  write a wrong memory.
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
  is **not** re-checked inside SAGE consensus today. On-chain digest pinning and a
  deterministic consensus author-binding check would require SAGE core changes. This bridge
  implements neither and makes no claim of an accepted upstream commitment to add them.
- **Replay protection is best-effort.** The `ReplayCache` is process-local (a multi-instance
  deployment needs a shared store) and only blocks in `enforcing` mode. A byte-identical C-2
  attestation is de-duped for the **full freshness window** (`BRIDGE_MAX_AGE`, default 300 s);
  the only re-admit gap is a worst-case ~5 s sliver when `iat` is maximally future-dated within
  the skew tolerance. C-2's body binding keeps replays low-impact (a replay can only re-write the
  same body).

## Anchoring the C-1 path (optional)

Software C-1 claims can pin the gateway signing key with `CMCP_TRUSTED_GATEWAY_KEY_HEX`
(hex, `0x` optional). The `trusted_public_key` check then becomes **required**: a claim
carrying another key rejects. Without that pin, any holder of a signing key can mint a
signature-valid claim naming an agent. Pinning the issuer does not add a per-write body binding.

```bash
CMCP_APPROVED_POLICY_HASH=sha256:... CMCP_APPROVED_CATALOG_HASH=sha256:... \
CMCP_TRUSTED_GATEWAY_KEY_HEX=<hex> \
SAGE_UPSTREAM=http://127.0.0.1:18080 uvicorn bridge.app:app --port 19090
```

When the key check passes, the badge's `binding` reads `pinned-issuer ...` instead of
`gateway-asserted (no trust root)`. Programmatic `CmcpTrust` users can also supply
`agent_manifest` / `trusted_agent_manifest_keys` for the library's software identity checks;
these have no environment variables in this entrypoint.

The hardware options below are **unsupported**, rather than silently ignored. Setting any
listed environment variable, even to an empty value, refuses startup before creating the
store. Supplying any non-`None` corresponding `CmcpTrust` field, including empty bytes/strings,
raises `ValueError`; verification also checks restored objects before calling the library.

| Unsupported environment variable | Programmatic field |
|---|---|
| `CMCP_TRUSTED_TPM_CA_PEM` | `trusted_tpm_ca_pem` |
| `CMCP_TRUSTED_ARK_PEM` | `trusted_ark_pem` |
| `CMCP_TRUSTED_INTEL_ROOT_PEM` | `trusted_intel_root_pem` |
| `CMCP_EXPECTED_GATEWAY_MEASUREMENT` | `expected_gateway_measurement` |

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
auto-validator — so the demo polls `GET /v1/memory/{id}` up to 20 times. It fails unless it
actually observes `committed` before fetching the badge and reporting success.
The demo writes to the reserved `general` domain (a fresh agent can't claim an owned domain on a
warm node); on a fresh container any domain works.

## Tests

```bash
./run_tests.sh   # offline: crypto, proxy mock, cMCP, hardening, conformance, evidence gates
```

The offline suite needs no node (it uses a mock SAGE that verifies the real Ed25519 signature,
so byte-identical forwarding is still proven). `demo/run_demo.py` is the live end-to-end run
against a stock SAGE container. The offline suite requires the complete `.[dev]` dependencies;
missing conformance tooling is a failure. Entry-point regressions prove the demo cannot pass a
pending/unreadable memory and that historical hardware flags never become qualified badges.

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
tests/                    offline suite: core, proxy e2e, cmcp, hardening, conformance, evidence gates
```

## License

Apache-2.0. Maintainer: [@l33tdawg](https://github.com/l33tdawg).
