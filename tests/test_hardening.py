import sys, os, asyncio, base64, json, tempfile, threading
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import httpx
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from bridge.identity import AgentKey
from bridge.proxy import build_app
from bridge.evidence_store import EvidenceStore, Evidence, now
from bridge.trace_record import mint_record
from bridge.trace_verify import verify_record
from client.attested_client import build_submit
from tests.mock_sage import build_mock_sage

def mk(enforcement="enforcing", upstream_app=None):
    up = httpx.AsyncClient(transport=httpx.ASGITransport(app=upstream_app or build_mock_sage()), base_url="http://mock")
    app = build_app(upstream="http://mock", store=EvidenceStore(tempfile.mktemp(suffix=".db")),
                    enforcement=enforcement, client=up)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy")

def failing_mock():
    async def submit(request): return JSONResponse({"error":"upstream_down"}, status_code=503)
    return Starlette(routes=[Route("/v1/memory/submit", submit, methods=["POST"])])

def test_F1_enforcement_fail_fast():
    for bad in ["enforce","strict","on","true","1","enforcing "]:
        try:
            build_app(upstream="http://x", store=EvidenceStore(tempfile.mktemp(suffix=".db")), enforcement=bad)
        except ValueError:
            continue
        # "enforcing " strips to "enforcing" (valid) — allowed; others must raise
        assert bad == "enforcing ", f"bad enforcement {bad!r} did NOT fail fast"
    print("  [F1] unrecognized BRIDGE_ENFORCEMENT fails fast (no silent fail-open)  OK")

async def amain():
    k = AgentKey.generate()

    # F2: wrong-type X-Attestation must 422, never 500
    proxy = mk()
    for bad in [json.dumps(["cmcp_version"]), json.dumps("cmcp_version-string"), json.dumps(123)]:
        h, b = build_submit(k, content="x", domain_tag="d"); h["X-Attestation"]=base64.b64encode(bad.encode()).decode()
        r = await proxy.post("/v1/memory/submit", content=b, headers=h)
        assert r.status_code == 422, (bad, r.status_code, r.text)
    print("  [F2] wrong-JSON-type X-Attestation -> 422 (no 500 DoS)  OK")

    # C5: malformed base64 / valid-b64 non-JSON / empty body
    h, b = build_submit(k, content="x", domain_tag="d"); h["X-Attestation"]="!!!not base64!!!"
    assert (await proxy.post("/v1/memory/submit", content=b, headers=h)).status_code == 422
    h, b = build_submit(k, content="x", domain_tag="d"); h["X-Attestation"]=base64.b64encode(b"not json").decode()
    assert (await proxy.post("/v1/memory/submit", content=b, headers=h)).status_code == 422
    print("  [C5] malformed base64 / non-JSON attestation -> 422  OK")

    # F7: uppercase X-Agent-ID rejected (SAGE stores verbatim -> different author)
    h, b = build_submit(k, content="x", domain_tag="d"); h["X-Agent-ID"]=k.agent_id.upper()
    rec = json.loads(base64.b64decode(h["X-Attestation"]))
    # rebuild attestation bound to the same body but verify against uppercase id
    r = await proxy.post("/v1/memory/submit", content=b, headers=h)
    assert r.status_code == 422 and r.json()["error"]=="attestation_rejected"
    print("  [F7] uppercase X-Agent-ID -> 422 (canonical lowercase hex required)  OK")

    # TRACE-4: non-canonical (padded/standard) signature rejected
    h, b = build_submit(k, content="x", domain_tag="d")
    rec = json.loads(base64.b64decode(h["X-Attestation"])); rec["signature"]=rec["signature"]+"=="
    h["X-Attestation"]=base64.b64encode(json.dumps(rec,separators=(",",":")).encode()).decode()
    r = await proxy.post("/v1/memory/submit", content=b, headers=h)
    assert r.status_code == 422, (r.status_code, r.text)
    print("  [TRACE-4] non-canonical signature encoding -> 422  OK")

    # C4: advisory mode forwards a TAMPERED attestation (documented behavior), stores no badge
    padv = mk("advisory")
    h, b = build_submit(k, content="adv", domain_tag="d")
    rec = json.loads(base64.b64decode(h["X-Attestation"])); rec["data_class"]="forged"
    h["X-Attestation"]=base64.b64encode(json.dumps(rec,separators=(",",":")).encode()).decode()
    r = await padv.post("/v1/memory/submit", content=b, headers=h)
    assert r.status_code == 200 and "X-Attestation-Status" not in r.headers
    print("  [C4] advisory mode forwards tampered attestation, no badge stored  OK")

    # F4: replay reservation RELEASED on upstream failure -> the same attestation can retry
    pfail = mk("enforcing", upstream_app=failing_mock())
    h, b = build_submit(k, content="retry", domain_tag="d")
    r1 = await pfail.post("/v1/memory/submit", content=b, headers=h)
    r2 = await pfail.post("/v1/memory/submit", content=b, headers=h)  # same attestation
    assert r1.status_code == 503 and r2.status_code == 503, (r1.status_code, r2.status_code)
    assert r2.json().get("error") != "attestation_replayed"  # not burned by the failed attempt
    print("  [F4] replay reservation released after upstream failure (retryable)  OK")

    # C10: unknown-attestation 404
    assert (await proxy.get("/v1/attestation/does-not-exist")).status_code == 404
    print("  [C10] unknown attestation -> 404  OK")

    # C1: ONLY /v1/memory/submit is gated — other writes pass through ungated (proxy forwards;
    # mock has no such route -> 404, proving it was NOT 422-gated by the bridge).
    fh = k.sign_sage_request("POST", "/v1/memory/abc/forget", b"{}"); fh["Content-Type"]="application/json"
    r = await proxy.post("/v1/memory/abc/forget", content=b"{}", headers=fh)
    assert r.status_code != 422, ("forget should pass through ungated, got", r.status_code)
    print(f"  [C1] non-submit write (/forget) passes through ungated -> {r.status_code} (not 422)  OK")

    # F4: the trailing-slash submit variant is ALSO gated (can't slip past via passthrough)
    th = k.sign_sage_request("POST", "/v1/memory/submit/", b"{}"); th["Content-Type"]="application/json"
    r = await proxy.post("/v1/memory/submit/", content=b"{}", headers=th)  # no attestation
    assert r.status_code == 422 and r.json()["error"]=="attestation_required", (r.status_code, r.text)
    print("  [F4] trailing-slash /v1/memory/submit/ is gated (not an ungated bypass)  OK")

    # C6: advisory + VALID attestation -> 200, badge stored + status header; replay NOT deduped
    padv = mk("advisory")
    h, b = build_submit(k, content="adv-valid", domain_tag="d")
    r1 = await padv.post("/v1/memory/submit", content=b, headers=h)
    r2 = await padv.post("/v1/memory/submit", content=b, headers=h)  # identical, advisory -> not deduped
    assert r1.status_code == 200 and r2.status_code == 200, (r1.status_code, r2.status_code)
    assert r1.headers.get("X-Attestation-Status") == "verified"
    print("  [C6] advisory + valid attestation: badge stored, replay NOT deduped (200/200)  OK")

    # F1b: non-dict nested field in a C-2 record must 422, never 500
    h, b = build_submit(k, content="dos", domain_tag="d")
    rec = json.loads(base64.b64decode(h["X-Attestation"])); rec["runtime"]=["not","a","dict"]
    h["X-Attestation"]=base64.b64encode(json.dumps(rec,separators=(",",":")).encode()).decode()
    r = await proxy.post("/v1/memory/submit", content=b, headers=h)
    assert r.status_code == 422, (r.status_code, r.text)
    print("  [F1b] C-2 record with non-dict runtime -> 422 (no 500 DoS)  OK")

def test_C6_tracetests_rejects_bare_c2():
    try:
        from trace_tests.loader import load_record, LoadError
    except ModuleNotFoundError:
        print("  [C6] (agentrust-trace-tests not installed; skipped)"); return
    k = AgentKey.generate()
    rec = mint_record(k, submit_body=b'{"x":1}')
    p = tempfile.mktemp(suffix=".json"); open(p,"w").write(json.dumps(rec))
    try:
        load_record(p); assert False, "trace-tests should reject a bare C-2 record"
    except LoadError:
        print("  [C6] agentrust-trace-tests LoadError-rejects a bare C-2 record (pins the doc claim)  OK")

def test_C10_evidence_concurrency():
    st = EvidenceStore(tempfile.mktemp(suffix=".db"))
    def worker(i):
        for j in range(50):
            st.put(Evidence(memory_id=f"m{i}-{j}", agent_id="a", attestation_digest="sha256:0",
                            cnf_thumbprint="t", platform="software-only", hardware_backed=False,
                            record={"eat_profile":"p"}, verified_at=now()))
            st.badge(f"m{i}-{j}")
    ts=[threading.Thread(target=worker, args=(i,)) for i in range(8)]
    [t.start() for t in ts]; [t.join() for t in ts]
    print("  [C10] EvidenceStore survives 8x50 concurrent put/badge under lock  OK")

def test_C12_c2_enforce_nonsw_roundtrip():
    k = AgentKey.generate()
    rec = mint_record(k, submit_body=b'{"y":2}', policy_bundle_hash="sha256:"+"a"*64, platform="amd-sev-snp")
    assert rec["policy"]["enforcement_mode"]=="enforce" and rec["runtime"]["platform"]=="amd-sev-snp"
    v = verify_record(rec, agent_id_hex=k.agent_id, submit_body=b'{"y":2}')
    assert v.ok and v.hardware_backed is False and v.platform=="amd-sev-snp"
    print("  [C12] C-2 enforce-mode + non-software-only platform verifies; hardware still NOT trusted  OK")

async def acmcp_not_deduped():
    # C3: a cMCP session claim is SESSION provenance and is legitimately reusable across writes
    # — it must NOT be replay-deduped (unlike the body-bound C-2 record).
    from datetime import datetime, UTC
    from cmcp_runtime.audit.keys import SigningKey
    from cmcp_runtime.audit.trace_claim import (generate_trace_claim, AttestationReportInfo,
        PolicyBundleInfo, ToolCatalogInfo, CallSummary, CallGraphSummary, AgentIdentityInfo)
    POL="sha256:"+"a"*64; CAT="sha256:"+"b"*64
    k = AgentKey.generate()
    up = httpx.AsyncClient(transport=httpx.ASGITransport(app=build_mock_sage()), base_url="http://mock")
    app = build_app(upstream="http://mock", store=EvidenceStore(tempfile.mktemp(suffix=".db")),
                    enforcement="enforcing", client=up, cmcp_approved_policy_hash=POL, cmcp_approved_catalog_hash=CAT)
    proxy = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy")
    claim = generate_trace_claim(session_id="s", signing_key=SigningKey(),
        attestation_report=AttestationReportInfo(provider="software-only", measurement="", report_data="",
            attestation_generated_at=datetime.now(UTC).isoformat(), attestation_validity_seconds=86400),
        policy_bundle=PolicyBundleInfo(hash=POL, enforcement_mode="enforcing", policy_version="1"),
        tool_catalog=ToolCatalogInfo(hash=CAT),
        call_summary=CallSummary(tool_calls_total=1, tool_calls_allowed=1, tool_calls_denied=0, tool_calls_faulted=0,
            tools_invoked=["sage_remember"], session_max_sensitivity="internal",
            call_graph_summary=CallGraphSummary(compliance_domains_touched=["d"], cross_boundary_events=[])),
        audit_chain_root="sha256:"+"c"*64, audit_chain_tip="sha256:"+"d"*64, audit_chain_length=1,
        agent_identity=AgentIdentityInfo(manifest_id="m", agent_id=f"spiffe://sage.local/agent/{k.agent_id}",
            authenticated_subject=f"spiffe://sage.local/agent/{k.agent_id}", subject_source="manifest-dev",
            issuer="spiffe://sage.local/i", issuer_key_id="k", policy_bundle_hash=POL, tool_catalog_hash=CAT)
    ).model_dump(exclude_none=True)
    att = base64.b64encode(json.dumps(claim, separators=(",",":")).encode()).decode()
    h1, b1 = build_submit(k, content="cmcp-1", domain_tag="d"); h1["X-Attestation"]=att
    h2, b2 = build_submit(k, content="cmcp-2", domain_tag="d"); h2["X-Attestation"]=att  # SAME claim, different write
    r1 = await proxy.post("/v1/memory/submit", content=b1, headers=h1)
    r2 = await proxy.post("/v1/memory/submit", content=b2, headers=h2)
    assert r1.status_code == 200 and r2.status_code == 200, (r1.status_code, r2.status_code, r2.text)
    print("  [C3] cMCP session claim reused across two writes -> both 200 (NOT deduped)  OK")

async def acmcp_disabled_without_approved_hashes():
    # C2: default deployment (CMCP_APPROVED_* unset) -> a valid cMCP claim yields verdict None
    # -> 422 attestation_required under enforcing (C-1 is off unless configured).
    from datetime import datetime, UTC
    from cmcp_runtime.audit.keys import SigningKey
    from cmcp_runtime.audit.trace_claim import (generate_trace_claim, AttestationReportInfo,
        PolicyBundleInfo, ToolCatalogInfo, CallSummary, CallGraphSummary)
    k = AgentKey.generate()
    up = httpx.AsyncClient(transport=httpx.ASGITransport(app=build_mock_sage()), base_url="http://mock")
    app = build_app(upstream="http://mock", store=EvidenceStore(tempfile.mktemp(suffix=".db")),
                    enforcement="enforcing", client=up)  # NO cmcp_approved_* -> C-1 disabled
    proxy = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy")
    claim = generate_trace_claim(session_id="s", signing_key=SigningKey(),
        attestation_report=AttestationReportInfo(provider="software-only", measurement="", report_data="",
            attestation_generated_at=datetime.now(UTC).isoformat(), attestation_validity_seconds=86400),
        policy_bundle=PolicyBundleInfo(hash="sha256:"+"a"*64, enforcement_mode="enforcing", policy_version="1"),
        tool_catalog=ToolCatalogInfo(hash="sha256:"+"b"*64),
        call_summary=CallSummary(tool_calls_total=1, tool_calls_allowed=1, tool_calls_denied=0, tool_calls_faulted=0,
            tools_invoked=["x"], session_max_sensitivity="internal",
            call_graph_summary=CallGraphSummary(compliance_domains_touched=["d"], cross_boundary_events=[])),
        audit_chain_root="sha256:"+"c"*64, audit_chain_tip="sha256:"+"d"*64, audit_chain_length=1).model_dump(exclude_none=True)
    h, b = build_submit(k, content="x", domain_tag="d")
    h["X-Attestation"] = base64.b64encode(json.dumps(claim, separators=(",",":")).encode()).decode()
    r = await proxy.post("/v1/memory/submit", content=b, headers=h)
    assert r.status_code == 422 and r.json()["error"] == "attestation_required", (r.status_code, r.text)
    print("  [C2] cMCP claim with CMCP_APPROVED_* unset -> 422 attestation_required (C-1 disabled by default)  OK")

def test_C3b_cmcp_stale_claim_rejected():
    # C-3: pin that a cMCP claim past its validity window is rejected (freshness not delegated
    # blindly — verify_cmcp_claim requires attestation_freshness in the verified set).
    from cmcp_runtime.audit.keys import SigningKey
    from cmcp_runtime.audit.trace_claim import (generate_trace_claim, AttestationReportInfo,
        PolicyBundleInfo, ToolCatalogInfo, CallSummary, CallGraphSummary, AgentIdentityInfo)
    from bridge.cmcp_adapter import verify_cmcp_claim
    POL="sha256:"+"a"*64; CAT="sha256:"+"b"*64
    k = AgentKey.generate()
    claim = generate_trace_claim(session_id="s", signing_key=SigningKey(),
        attestation_report=AttestationReportInfo(provider="software-only", measurement="", report_data="",
            attestation_generated_at="2020-01-01T00:00:00+00:00", attestation_validity_seconds=86400),  # ancient
        policy_bundle=PolicyBundleInfo(hash=POL, enforcement_mode="enforcing", policy_version="1"),
        tool_catalog=ToolCatalogInfo(hash=CAT),
        call_summary=CallSummary(tool_calls_total=1, tool_calls_allowed=1, tool_calls_denied=0, tool_calls_faulted=0,
            tools_invoked=["x"], session_max_sensitivity="internal",
            call_graph_summary=CallGraphSummary(compliance_domains_touched=["d"], cross_boundary_events=[])),
        audit_chain_root="sha256:"+"c"*64, audit_chain_tip="sha256:"+"d"*64, audit_chain_length=1,
        agent_identity=AgentIdentityInfo(manifest_id="m", agent_id=f"spiffe://x/agent/{k.agent_id}",
            authenticated_subject=f"spiffe://x/agent/{k.agent_id}", subject_source="manifest-dev",
            issuer="spiffe://x/i", issuer_key_id="k", policy_bundle_hash=POL, tool_catalog_hash=CAT)).model_dump(exclude_none=True)
    v = verify_cmcp_claim(claim, agent_id_hex=k.agent_id, approved_policy_hash=POL, approved_catalog_hash=CAT)
    assert v.ok is False and v.checks.get("attestation_freshness") is False, (v.ok, v.checks)
    print("  [C3b] stale cMCP claim (old attestation_generated_at) -> rejected (freshness)  OK")

def test_C3_hardware_never_branded_even_if_cmcp_verify_claims_it():
    # C3: even if the published cmcp_verify puts 'hardware_attestation' in verified_fields (its
    # Phase-1 verifiers don't check a silicon root), the bridge MUST still report hardware_backed=False.
    import bridge.cmcp_adapter as ca
    class _Res:
        verified_fields = ["signature","attestation_freshness","policy_bundle.hash",
                           "tool_catalog.hash","hardware_attestation"]
        class status: value = "verified"
        failure_reason = None
    orig = ca.verify_trace_claim
    ca.verify_trace_claim = lambda *a, **k: _Res()
    try:
        k = AgentKey.generate()
        claim = {"cmcp_version":"1.0",
                 "trace":{"cnf":{"jwk":{"x":k.cnf["x"]}}, "runtime":{"platform":"amd-sev-snp"}},
                 "gateway":{"agent_identity":{"agent_id":f"spiffe://x/agent/{k.agent_id}"}}}
        v = ca.verify_cmcp_claim(claim, agent_id_hex=k.agent_id,
                                 approved_policy_hash="sha256:"+"a"*64, approved_catalog_hash="sha256:"+"b"*64)
        assert v.ok is True, v.reason
        assert v.hardware_backed is False, "bridge must NOT trust cmcp_verify's hardware_attestation field"
        print("  [C3] cmcp_verify claims hardware_attestation -> bridge STILL reports hardware_backed=False  OK")
    finally:
        ca.verify_trace_claim = orig

async def alifecycle_and_authed_recall():
    # C4/C5: against a realistic mock (201 'proposed' -> async commit, auth-checked reads),
    # exercise the demo's submit -> poll-to-committed path AND that recall is signature-gated.
    from tests.mock_sage import build_realistic_mock_sage
    k = AgentKey.generate()
    up = httpx.AsyncClient(transport=httpx.ASGITransport(app=build_realistic_mock_sage()), base_url="http://mock")
    app = build_app(upstream="http://mock", store=EvidenceStore(tempfile.mktemp(suffix=".db")),
                    enforcement="enforcing", client=up)
    proxy = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy")
    h, b = build_submit(k, content="lifecycle", domain_tag="d")
    r = await proxy.post("/v1/memory/submit", content=b, headers=h)
    assert r.status_code == 201 and r.json()["status"] == "proposed", (r.status_code, r.text)
    mid = r.json()["memory_id"]
    gh = k.sign_sage_request("GET", f"/v1/memory/{mid}", b"")
    g = await proxy.get(f"/v1/memory/{mid}", headers=gh)
    assert g.status_code == 200 and g.json()["status"] == "committed", (g.status_code, g.text)
    print("  [C4] realistic node: 201 proposed -> signed poll -> committed  OK")
    # recall is signature-gated on a real node: unsigned -> 401, signed -> 200
    un = await proxy.post("/v1/memory/query", content=b"{}", headers={"Content-Type": "application/json"})
    qh = k.sign_sage_request("POST", "/v1/memory/query", b"{}"); qh["Content-Type"] = "application/json"
    sg = await proxy.post("/v1/memory/query", content=b"{}", headers=qh)
    assert un.status_code == 401 and sg.status_code == 200, (un.status_code, sg.status_code)
    print("  [C5] passthrough recall is signature-gated: unsigned 401, signed 200  OK")

async def astore_failure_degrades_not_500():
    # C-1 (completeness): a persistence failure AFTER the upstream commits must NOT 500 the
    # already-committed write — it degrades to the passthrough 2xx with no badge.
    class FailingStore(EvidenceStore):
        def put(self, ev): raise RuntimeError("disk full")
    k = AgentKey.generate()
    up = httpx.AsyncClient(transport=httpx.ASGITransport(app=build_mock_sage()), base_url="http://mock")
    app = build_app(upstream="http://mock", store=FailingStore(tempfile.mktemp(suffix=".db")),
                    enforcement="enforcing", client=up)
    proxy = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy")
    h, b = build_submit(k, content="store-fail", domain_tag="d")
    r = await proxy.post("/v1/memory/submit", content=b, headers=h)
    assert r.status_code == 200 and "X-Attestation-Status" not in r.headers, (r.status_code, r.text)
    print("  [C1] store.put failure on a committed write -> passthrough 200 (no 500, badge absent)  OK")

if __name__ == "__main__":
    test_F1_enforcement_fail_fast()
    asyncio.run(amain())
    asyncio.run(acmcp_not_deduped())
    asyncio.run(acmcp_disabled_without_approved_hashes())
    asyncio.run(alifecycle_and_authed_recall())
    asyncio.run(astore_failure_degrades_not_500())
    test_C3b_cmcp_stale_claim_rejected()
    test_C3_hardware_never_branded_even_if_cmcp_verify_claims_it()
    test_C6_tracetests_rejects_bare_c2()
    test_C10_evidence_concurrency()
    test_C12_c2_enforce_nonsw_roundtrip()
    print("ALL HARDENING TESTS PASSED")
