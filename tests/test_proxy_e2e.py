import sys, os, asyncio, base64, json, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import httpx
from bridge.identity import AgentKey
from bridge.proxy import build_app
from bridge.evidence_store import EvidenceStore
from client.attested_client import build_submit
from tests.mock_sage import build_mock_sage

def mk(enforcement):
    db = tempfile.mktemp(suffix=".db")
    upstream = httpx.AsyncClient(transport=httpx.ASGITransport(app=build_mock_sage()), base_url="http://mock")
    app = build_app(upstream="http://mock", store=EvidenceStore(db), enforcement=enforcement, client=upstream)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy")

async def main():
    k = AgentKey.generate()

    # 1. happy path (enforcing)
    proxy = mk("enforcing")
    headers, body = build_submit(k, content="reactor coolant pump P-2 cavitating at 1480rpm", domain_tag="plant-ops")
    r = await proxy.post("/v1/memory/submit", content=body, headers=headers)
    assert r.status_code == 200, (r.status_code, r.text)
    mid = r.json()["memory_id"]
    assert r.headers.get("X-Attestation-Status") == "verified"
    assert r.headers.get("X-Attestation-Digest", "").startswith("sha256:")
    print(f"  [1] attested submit committed: {mid}  status={r.headers['X-Attestation-Status']}")

    # 2. recall-enrichment badge — never claims hardware
    b = await proxy.get(f"/v1/attestation/{mid}")
    bj = b.json()
    assert b.status_code == 200 and bj["edge_verified"] is True
    assert bj["verification"] == "edge-only" and bj["hardware_verified"] is False
    assert bj["platform_claimed"] == "software-only"
    assert "attested" not in bj and "hardware_backed" not in bj  # removed: no always-true/hardware flags
    print(f"  [2] provenance badge: verification={bj['verification']} hardware_verified={bj['hardware_verified']}")

    # 3. tampered attestation rejected, never reaches SAGE
    headers, body = build_submit(k, content="legit", domain_tag="plant-ops")
    rec = json.loads(base64.b64decode(headers["X-Attestation"])); rec["data_class"]="forged"
    headers["X-Attestation"] = base64.b64encode(json.dumps(rec, separators=(",",":")).encode()).decode()
    r = await proxy.post("/v1/memory/submit", content=body, headers=headers)
    assert r.status_code == 422 and r.json()["error"]=="attestation_rejected", (r.status_code, r.text)
    print(f"  [3] tampered attestation -> {r.status_code} {r.json()['error']} (blocked at edge)")

    # 4. missing attestation rejected under enforcing
    headers, body = build_submit(k, content="legit2", domain_tag="plant-ops"); headers.pop("X-Attestation")
    r = await proxy.post("/v1/memory/submit", content=body, headers=headers)
    assert r.status_code == 422 and r.json()["error"]=="attestation_required"
    print(f"  [4] missing attestation (enforcing) -> {r.status_code} {r.json()['error']}")

    # 5. advisory mode forwards unattested writes (annotated, no evidence)
    proxy_adv = mk("advisory")
    headers, body = build_submit(k, content="advisory-write", domain_tag="plant-ops"); headers.pop("X-Attestation")
    r = await proxy_adv.post("/v1/memory/submit", content=body, headers=headers)
    assert r.status_code == 200 and "X-Attestation-Status" not in r.headers
    print(f"  [5] advisory mode: unattested write forwarded -> {r.status_code} (no badge)")

    # 6. recall passthrough still works through the proxy
    r = await proxy.post("/v1/memory/query", content=b'{"embedding":[]}', headers={"Content-Type":"application/json"})
    assert r.status_code == 200 and "results" in r.json()
    print(f"  [6] passthrough query -> {r.status_code} ({len(r.json()['results'])} result)")

    # 7. single-use: replaying the SAME attestation is rejected (BRIDGE-1/BRIDGE-2/IDB-2)
    proxy2 = mk("enforcing")
    headers, body = build_submit(k, content="replayable", domain_tag="plant-ops")
    r1 = await proxy2.post("/v1/memory/submit", content=body, headers=headers)
    r2 = await proxy2.post("/v1/memory/submit", content=body, headers=headers)
    assert r1.status_code == 200 and r2.status_code == 422 and r2.json()["error"] == "attestation_replayed", (r1.status_code, r2.status_code, r2.text)
    print(f"  [7] attestation replay -> first {r1.status_code}, replay {r2.status_code} {r2.json()['error']}")

    # 8. non-canonical cnf.jwk.x rejected (IDB-1)
    headers, body = build_submit(k, content="noncanon", domain_tag="plant-ops")
    rec = json.loads(base64.b64decode(headers["X-Attestation"]))
    x = rec["cnf"]["jwk"]["x"]; std = x.replace("-", "+").replace("_", "/")
    if std != x:
        rec["cnf"]["jwk"]["x"] = std
        headers["X-Attestation"] = base64.b64encode(json.dumps(rec, separators=(",",":")).encode()).decode()
        r = await proxy2.post("/v1/memory/submit", content=body, headers=headers)
        assert r.status_code == 422, (r.status_code, r.text)
        print(f"  [8] non-canonical cnf.jwk.x -> {r.status_code} {r.json()['error']}")
    else:
        print("  [8] (key has no +// sextet this run; canonical check covered in core tests)")
    print("ALL PROXY E2E TESTS PASSED")

asyncio.run(main())
