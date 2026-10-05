"""Offline tests of the actual demo/conformance entrypoints and historical badge serving."""
import asyncio
import builtins
import contextlib
import io
import os
from pathlib import Path
import runpy
import sys
from unittest.mock import patch

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bridge.cmcp_adapter import CmcpTrust
from bridge.evidence_store import Evidence, EvidenceStore
from bridge.identity import AgentKey
from bridge.proxy import build_app


def test_startup_configuration():
    hardware_names = ("CMCP_TRUSTED_TPM_CA_PEM", "CMCP_TRUSTED_ARK_PEM",
                      "CMCP_TRUSTED_INTEL_ROOT_PEM", "CMCP_EXPECTED_GATEWAY_MEASUREMENT")
    for name in hardware_names:
        for value in ("", "unreadable-or-unapproved-hardware-input"):
            with patch.dict(os.environ, {name: value}, clear=True), \
                 patch("bridge.evidence_store.EvidenceStore") as store, \
                 patch("bridge.proxy.build_app") as build:
                try:
                    runpy.run_path(str(ROOT / "bridge/app.py"))
                except SystemExit as exc:
                    assert name in str(exc) and "unsupported" in str(exc), str(exc)
                else:
                    raise AssertionError(f"startup ignored configured {name}")
                store.assert_not_called()
                build.assert_not_called()
    with patch.dict(os.environ, {"CMCP_TRUSTED_GATEWAY_KEY_HEX": "ab" * 32,
                                 "ATTESTATION_DB": ":memory:"}, clear=True), \
         patch("bridge.evidence_store.EvidenceStore") as store, \
         patch("bridge.proxy.build_app") as build:
        runpy.run_path(str(ROOT / "bridge/app.py"))
        store.assert_called_once_with(":memory:")
        assert build.call_args.kwargs["cmcp_trust"] == CmcpTrust(trusted_gateway_key_hex="ab" * 32)
    print("  startup rejects all configured hardware options; software gateway pin remains available  OK")


async def test_legacy_badge():
    store = EvidenceStore(":memory:")
    record = {"cmcp_version": "1.0", "trace": {"runtime": {"platform": "tpm2"},
               "subject": "spiffe://example/legacy", "eat_profile": "historical-profile"}}
    store.put(Evidence(memory_id="legacy", agent_id="a", attestation_digest="sha256:old",
                       cnf_thumbprint="old-thumb", platform="tpm2", hardware_backed=True,
                       record=record, verified_at=123, identity_anchored=True))
    before = store._db.execute("SELECT * FROM attestation").fetchall()
    changes = store._db.total_changes
    raw = store.get("legacy")
    assert raw.hardware_backed is True and raw.record == record
    badge = store.badge("legacy")
    assert badge["hardware_verified"] is False
    assert badge["hardware_verification"] == "legacy-unqualified"
    assert badge["historical_hardware_backed"] is True
    assert badge["attestation_digest"] == raw.attestation_digest and badge["verified_at"] == 123
    async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(500))) as upstream:
        app = build_app(upstream="http://unused", store=store, client=upstream)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://offline") as client:
            response = await client.get("/v1/attestation/legacy")
            assert response.status_code == 200 and response.json() == badge
    assert store._db.execute("SELECT * FROM attestation").fetchall() == before
    assert store._db.total_changes == changes, "badge reads must not rewrite audit evidence"
    assert store.get("legacy").hardware_backed is True
    print("  historical hardware flag/record remain intact; HTTP badge discloses legacy-unqualified  OK")


class DemoClient:
    def __init__(self, status, read_code=200):
        self.status = status
        self.read_code = read_code
        self.badge_reads = 0
        self.posts = iter((201, 422, 422, 201, 422))

    def post(self, path, **kwargs):
        return httpx.Response(next(self.posts), json={"memory_id": "demo", "error": "blocked"})

    def get(self, path, **kwargs):
        if path.startswith("/v1/attestation/"):
            self.badge_reads += 1
            return httpx.Response(200, json={"verification": "edge-only", "hardware_verified": False,
                "attestation_kind": "trace", "platform_claimed": "software-only",
                "eat_profile": "test", "subject": "test"})
        return httpx.Response(self.read_code, json={"status": self.status})


def test_demo_requires_commit():
    for status, read_code in (("proposed", 200), ("deprecated", 200), (None, 503), ("committed", 200)):
        client = DemoClient(status, read_code)
        output = io.StringIO()
        with patch("httpx.Client", return_value=client), \
             patch.object(AgentKey, "from_seed_file", return_value=AgentKey.generate()), \
             patch("time.sleep"), contextlib.redirect_stdout(output):
            try:
                runpy.run_path(str(ROOT / "demo/run_demo.py"), run_name="__main__")
            except RuntimeError as exc:
                assert status != "committed" and "did not reach committed" in str(exc)
                assert client.badge_reads == 0 and "DEMO PASSED" not in output.getvalue()
            else:
                assert status == "committed" and client.badge_reads == 1
                assert "DEMO PASSED" in output.getvalue()
    print("  actual demo cannot pass pending/deprecated/unreadable memory; committed control passes  OK")


def test_missing_conformance_is_failure():
    original_import = builtins.__import__

    def without_trace_tests(name, *args, **kwargs):
        if name == "trace_tests" or name.startswith("trace_tests."):
            raise ModuleNotFoundError("simulated absent conformance dependency", name=name)
        return original_import(name, *args, **kwargs)

    output = io.StringIO()
    with patch("builtins.__import__", side_effect=without_trace_tests), contextlib.redirect_stdout(output):
        try:
            runpy.run_path(str(ROOT / "tests/test_conformance.py"), run_name="__main__")
        except SystemExit as exc:
            assert exc.code != 0 and "cannot run" in str(exc)
        else:
            raise AssertionError("missing conformance dependency counted as success")
        hardening = runpy.run_path(str(ROOT / "tests/test_hardening.py"))
        try:
            hardening["test_C6_tracetests_grades_bare_c2"]()
        except ModuleNotFoundError:
            pass
        else:
            raise AssertionError("hardening swallowed a missing conformance dependency")
    assert "CONFORMANCE TESTS PASSED" not in output.getvalue()
    print("  missing conformance dependency fails both actual entrypoints  OK")


if __name__ == "__main__":
    test_startup_configuration()
    asyncio.run(test_legacy_badge())
    test_demo_requires_commit()
    test_missing_conformance_is_failure()
    print("EVIDENCE GATE TESTS PASSED")
