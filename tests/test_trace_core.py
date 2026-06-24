import sys, os, copy
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from bridge.identity import AgentKey, agent_id_matches_cnf
from bridge.trace_record import mint_record
from bridge.trace_verify import verify_record

BODY = b'{"content":"the well is poisoned at depth 40m","domain":"field-notes"}'

def test_happy_path():
    k = AgentKey.generate()
    rec = mint_record(k, submit_body=BODY)
    v = verify_record(rec, agent_id_hex=k.agent_id, submit_body=BODY)
    assert v.ok, v.reason
    assert v.checks == {"canonical_encoding":True,"signature":True,"freshness":True,"identity_binding":True,"request_binding":True}
    assert v.attestation_digest.startswith("sha256:")
    assert v.cnf_thumbprint and not v.hardware_backed and v.platform == "software-only"
    # IDB-1: the bridge thumbprint must equal the canonical RFC7638 thumbprint of the same key
    from bridge.identity import jwk_thumbprint_sha256
    assert v.cnf_thumbprint == jwk_thumbprint_sha256(rec["cnf"]["jwk"]["x"]) == k.thumbprint
    print("  happy path OK  digest=%s… thumb=%s…" % (v.attestation_digest[:21], v.cnf_thumbprint[:12]))

def test_noncanonical_x_rejected():
    # IDB-1: a record whose cnf.jwk.x uses std-base64 ('+'/'/') instead of urlsafe is rejected,
    # so the stored thumbprint/digest can never diverge from the on-chain RFC7638 pin.
    import base64, json
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    # find a key whose raw pubkey base64 differs between std and urlsafe alphabets
    for _ in range(200):
        k = AgentKey.generate()
        x = k.cnf["x"]; std = x.replace("-","+").replace("_","/")
        if std != x:
            break
    else:
        print("  (no +// key found in 200 tries; skipping)"); return
    rec = mint_record(k, submit_body=BODY)
    rec["cnf"]["jwk"]["x"] = std  # non-canonical, decodes to the same bytes
    v = verify_record(rec, agent_id_hex=k.agent_id, submit_body=BODY)
    assert not v.ok and v.checks.get("canonical_encoding") is False, v.checks
    print("  non-canonical cnf.jwk.x rejected  OK")

def test_identity_is_the_binding():
    # SAGE agent_id (hex pubkey) and TRACE cnf.jwk.x decode to the SAME 32 bytes
    k = AgentKey.generate()
    assert agent_id_matches_cnf(k.agent_id, k.cnf["x"])
    print("  identity: X-Agent-ID == cnf.jwk.x (same key)  OK")

def test_tamper_rejected():
    k = AgentKey.generate(); rec = mint_record(k, submit_body=BODY)
    bad = copy.deepcopy(rec); bad["subject"] = "spiffe://sage.local/agent/mallory"
    v = verify_record(bad, agent_id_hex=k.agent_id, submit_body=BODY)
    assert not v.ok and v.checks["signature"] is False
    print("  tampered record rejected  OK")

def test_wrong_key_binding_rejected():
    k = AgentKey.generate(); other = AgentKey.generate()
    rec = mint_record(k, submit_body=BODY)
    v = verify_record(rec, agent_id_hex=other.agent_id, submit_body=BODY)  # someone else's memory
    assert not v.ok and v.checks.get("identity_binding") is False
    print("  EAT stapled to a different author rejected  OK")

def test_replay_on_other_body_rejected():
    k = AgentKey.generate(); rec = mint_record(k, submit_body=BODY)
    v = verify_record(rec, agent_id_hex=k.agent_id, submit_body=b'{"content":"different write"}')
    assert not v.ok and v.checks.get("request_binding") is False
    print("  fresh EAT replayed onto a different write rejected  OK")

def test_staleness_rejected():
    k = AgentKey.generate(); rec = mint_record(k, submit_body=BODY)
    v = verify_record(rec, agent_id_hex=k.agent_id, submit_body=BODY, now=rec["iat"]+10_000)
    assert not v.ok and v.checks.get("freshness") is False
    print("  stale EAT rejected  OK")

if __name__ == "__main__":
    for name in [n for n in dir() if n.startswith("test_")]:
        globals()[name]()
    print("ALL CORE TESTS PASSED")
