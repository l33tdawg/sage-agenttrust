"""End-to-end demo: attested agent -> bridge -> STOCK SAGE node.
Run with the bridge proxy on :19090 in front of a stock node on :18080."""
import sys, os, time, json, base64, uuid
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import httpx
from bridge.identity import AgentKey
from client.attested_client import build_submit

PROXY = os.environ.get("BRIDGE_URL", "http://127.0.0.1:19090")
KEY_PATH = os.environ.get("SAGE_DEMO_KEY", os.path.join(os.path.dirname(__file__), ".sage_demo_agent.key"))
c = httpx.Client(base_url=PROXY, timeout=15)
k = AgentKey.from_seed_file(KEY_PATH)
print(f"agent_id (SAGE author key) : {k.agent_id}")
print(f"cnf thumbprint (RFC7638)   : {k.thumbprint}")
print("-> same 32-byte Ed25519 key signs the SAGE request AND is the TRACE cnf key\n")

# 1) attested submit through the bridge to the real node
note = f"reactor coolant pump P-2 cavitating at 1480rpm; recommend manual trip [{uuid.uuid4().hex[:8]}]"
headers, body = build_submit(k, content=note, domain_tag="general")
r = c.post("/v1/memory/submit", content=body, headers=headers)
assert r.status_code in (200, 201), (r.status_code, r.text)
mid = r.json()["memory_id"]
print(f"[1] attested submit -> {r.status_code}  memory_id={mid}")
print(f"    X-Attestation-Status={r.headers.get('X-Attestation-Status')}  digest={r.headers.get('X-Attestation-Digest','')[:28]}…")

# 2) poll the real node (through the proxy) until consensus commits it.
# GET is behind the same Ed25519 auth, so sign the read too (empty body).
status = None
for _ in range(20):
    gh = k.sign_sage_request("GET", f"/v1/memory/{mid}", b"")
    g = c.get(f"/v1/memory/{mid}", headers=gh)
    if g.status_code == 200:
        status = g.json().get("status")
        if status == "committed":
            break
    time.sleep(1)
print(f"[2] consensus status on the real node: {status}")

# 3) provenance badge from the bridge, joined to the committed memory_id
b = c.get(f"/v1/attestation/{mid}").json()
print(f"[3] provenance badge: verification={b['verification']} hardware_verified={b['hardware_verified']} kind={b['attestation_kind']}")
print(f"    platform_claimed={b['platform_claimed']}  eat_profile={b['eat_profile']}  subject={b['subject']}")

# 4) tampered attestation must be blocked at the edge (never reaches the node)
headers, body = build_submit(k, content="forged note", domain_tag="general")
rec = json.loads(base64.b64decode(headers["X-Attestation"])); rec["data_class"] = "forged"
headers["X-Attestation"] = base64.b64encode(json.dumps(rec, separators=(",", ":")).encode()).decode()
r = c.post("/v1/memory/submit", content=body, headers=headers)
print(f"[4] tampered attestation -> {r.status_code} {r.json().get('error')} (blocked before SAGE)")
assert r.status_code == 422

# 5) EAT stapled to a DIFFERENT author rejected
other = AgentKey.generate()
headers, body = build_submit(k, content="someone elses memory", domain_tag="general")
h2 = other.sign_sage_request("POST", "/v1/memory/submit", body)  # other key signs the request...
h2["Content-Type"] = "application/json"; h2["X-Attestation"] = headers["X-Attestation"]  # ...but k's attestation
r = c.post("/v1/memory/submit", content=body, headers=h2)
print(f"[5] EAT bound to key A, request signed by key B -> {r.status_code} {r.json().get('error')}")
assert r.status_code == 422

# 6) byte-identical attestation replay is de-duplicated (rejected within the freshness window)
headers, body = build_submit(k, content=f"replay-test [{uuid.uuid4().hex[:8]}]", domain_tag="general")
r1 = c.post("/v1/memory/submit", content=body, headers=headers)
r2 = c.post("/v1/memory/submit", content=body, headers=headers)  # identical -> same digest
print(f"[6] same attestation reused -> first {r1.status_code}, replay {r2.status_code} {r2.json().get('error')}")
assert r1.status_code in (200, 201) and r2.status_code == 422

print("\nDEMO PASSED — attested identity -> edge verify + author-bind + replay-dedup -> consensus commit -> provenance-badge fetch")
