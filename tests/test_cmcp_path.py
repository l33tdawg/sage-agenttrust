import sys, os, asyncio, base64, json, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import httpx
from datetime import datetime, UTC
from cmcp_runtime.audit.keys import SigningKey
from cmcp_runtime.audit.trace_claim import (generate_trace_claim, AttestationReportInfo,
    PolicyBundleInfo, ToolCatalogInfo, CallSummary, CallGraphSummary, AgentIdentityInfo)
from bridge.identity import AgentKey
from bridge.proxy import build_app
from bridge.evidence_store import EvidenceStore
from client.attested_client import build_submit
from tests.mock_sage import build_mock_sage

POL="sha256:"+"a"*64; CAT="sha256:"+"b"*64

def mint_cmcp(sage_agent_id, *, bind_to=None):
    bind = bind_to or sage_agent_id
    claim = generate_trace_claim(
        session_id="s1", signing_key=SigningKey(),
        attestation_report=AttestationReportInfo(provider="software-only", measurement="", report_data="",
            attestation_generated_at=datetime.now(UTC).isoformat(), attestation_validity_seconds=86400),
        policy_bundle=PolicyBundleInfo(hash=POL, enforcement_mode="enforcing", policy_version="1"),
        tool_catalog=ToolCatalogInfo(hash=CAT),
        call_summary=CallSummary(tool_calls_total=1, tool_calls_allowed=1, tool_calls_denied=0,
            tool_calls_faulted=0, tools_invoked=["sage_remember"], session_max_sensitivity="internal",
            call_graph_summary=CallGraphSummary(compliance_domains_touched=["plant-ops"], cross_boundary_events=[])),
        audit_chain_root="sha256:"+"c"*64, audit_chain_tip="sha256:"+"d"*64, audit_chain_length=1,
        agent_identity=AgentIdentityInfo(
            manifest_id="m1", agent_id=f"spiffe://sage.local/agent/{bind}",
            authenticated_subject=f"spiffe://sage.local/agent/{bind}", subject_source="manifest-dev",
            issuer="spiffe://sage.local/issuer", issuer_key_id="k1",
            policy_bundle_hash=POL, tool_catalog_hash=CAT))
    return claim.model_dump(exclude_none=True)

def mk():
    up = httpx.AsyncClient(transport=httpx.ASGITransport(app=build_mock_sage()), base_url="http://mock")
    app = build_app(upstream="http://mock", store=EvidenceStore(tempfile.mktemp(suffix=".db")),
                    enforcement="enforcing", client=up,
                    cmcp_approved_policy_hash=POL, cmcp_approved_catalog_hash=CAT)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy")

async def main():
    k = AgentKey.generate()
    proxy = mk()

    # build a SAGE submit, then attach a cMCP RuntimeClaim bound to this agent
    headers, body = build_submit(k, content="cmcp-path memory", domain_tag="plant-ops")
    claim = mint_cmcp(k.agent_id)
    headers["X-Attestation"] = base64.b64encode(json.dumps(claim, separators=(",",":")).encode()).decode()
    r = await proxy.post("/v1/memory/submit", content=body, headers=headers)
    assert r.status_code == 200, (r.status_code, r.text)
    mid = r.json()["memory_id"]
    assert r.headers.get("X-Attestation-Status") == "verified"
    print(f"  [1] cMCP RuntimeClaim accepted (cmcp_verify) -> committed {mid}")

    b = (await proxy.get(f"/v1/attestation/{mid}")).json()
    assert b["edge_verified"] and b["verification"] == "edge-only" and b["hardware_verified"] is False
    print(f"  [2] badge: verification={b['verification']} hardware_verified={b['hardware_verified']} profile={b['eat_profile']}")

    # negative: claim binds a DIFFERENT agent
    headers, body = build_submit(k, content="cmcp wrong-bind", domain_tag="plant-ops")
    other = AgentKey.generate()
    claim = mint_cmcp(k.agent_id, bind_to=other.agent_id)
    headers["X-Attestation"] = base64.b64encode(json.dumps(claim, separators=(",",":")).encode()).decode()
    r = await proxy.post("/v1/memory/submit", content=body, headers=headers)
    assert r.status_code == 422 and r.json()["error"] == "attestation_rejected", (r.status_code, r.text)
    print(f"  [3] cMCP claim naming a different agent -> {r.status_code} {r.json()['error']}")

    # negative: wrong approved policy hash => signature ok but policy mismatch => rejected
    proxy2 = mk_wrong()
    headers, body = build_submit(k, content="cmcp wrong-policy", domain_tag="plant-ops")
    claim = mint_cmcp(k.agent_id)
    headers["X-Attestation"] = base64.b64encode(json.dumps(claim, separators=(",",":")).encode()).decode()
    r = await proxy2.post("/v1/memory/submit", content=body, headers=headers)
    assert r.status_code == 422, (r.status_code, r.text)
    print(f"  [4] cMCP claim with policy-hash mismatch -> {r.status_code} {r.json()['error']}")

    # HONESTY INVARIANT: a claim ASSERTING hardware (tpm2) is NEVER branded as verified
    # hardware. The bridge does not verify hardware roots with published tooling, so such a
    # claim is at most accepted as edge-only provenance — its badge must show
    # hardware_verified=False / verification=edge-only and surface the platform only as claimed.
    proxy3 = mk()
    headers, body = build_submit(k, content="cmcp fake-hardware", domain_tag="plant-ops")
    claim = generate_trace_claim(
        session_id="s2", signing_key=SigningKey(),
        attestation_report=AttestationReportInfo(provider="tpm", measurement="sha256:"+"f"*64,
            report_data="ab"*32, attestation_generated_at=datetime.now(UTC).isoformat(),
            attestation_validity_seconds=86400),
        policy_bundle=PolicyBundleInfo(hash=POL, enforcement_mode="enforcing", policy_version="1"),
        tool_catalog=ToolCatalogInfo(hash=CAT),
        call_summary=CallSummary(tool_calls_total=1, tool_calls_allowed=1, tool_calls_denied=0,
            tool_calls_faulted=0, tools_invoked=["sage_remember"], session_max_sensitivity="internal",
            call_graph_summary=CallGraphSummary(compliance_domains_touched=["plant-ops"], cross_boundary_events=[])),
        audit_chain_root="sha256:"+"c"*64, audit_chain_tip="sha256:"+"d"*64, audit_chain_length=1,
        agent_identity=AgentIdentityInfo(manifest_id="m1", agent_id=f"spiffe://sage.local/agent/{k.agent_id}",
            authenticated_subject=f"spiffe://sage.local/agent/{k.agent_id}", subject_source="manifest-dev",
            issuer="spiffe://sage.local/issuer", issuer_key_id="k1", policy_bundle_hash=POL, tool_catalog_hash=CAT)
    ).model_dump(exclude_none=True)
    headers["X-Attestation"] = base64.b64encode(json.dumps(claim, separators=(",",":")).encode()).decode()
    r = await proxy3.post("/v1/memory/submit", content=body, headers=headers)
    # Whatever the accept/reject outcome, the bridge must NEVER brand it hardware.
    if r.status_code == 200:
        bj = (await proxy3.get(f"/v1/attestation/{r.json()['memory_id']}")).json()
        assert bj["hardware_verified"] is False and bj["verification"] == "edge-only", bj
        assert "hardware_backed" not in bj
        print(f"  [5] tpm2-asserting claim accepted as edge-only; hardware_verified={bj['hardware_verified']} platform_claimed={bj['platform_claimed']}")
    else:
        assert r.status_code == 422, (r.status_code, r.text)
        print(f"  [5] tpm2-asserting claim -> {r.status_code} {r.json()['error']} (not branded hardware)")
    print("ALL CMCP PATH TESTS PASSED")

def mk_wrong():
    up = httpx.AsyncClient(transport=httpx.ASGITransport(app=build_mock_sage()), base_url="http://mock")
    app = build_app(upstream="http://mock", store=EvidenceStore(tempfile.mktemp(suffix=".db")),
                    enforcement="enforcing", client=up,
                    cmcp_approved_policy_hash="sha256:"+"e"*64, cmcp_approved_catalog_hash=CAT)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy")

asyncio.run(main())
