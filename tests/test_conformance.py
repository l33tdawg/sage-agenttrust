import sys, os, json, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from datetime import datetime, UTC
from cmcp_runtime.audit.keys import SigningKey
from cmcp_runtime.audit.trace_claim import (generate_trace_claim, AttestationReportInfo,
    PolicyBundleInfo, ToolCatalogInfo, CallSummary, CallGraphSummary)
try:
    from trace_tests.loader import load_record
    from trace_tests.runner import run
except ModuleNotFoundError:
    print("  SKIPPED conformance: agentrust-trace-tests not installed "
          "(run `pip install -e \".[dev]\"` to run the conformance stage)")
    sys.exit(0)

def _mint():
    return generate_trace_claim(session_id="s", signing_key=SigningKey(),
        attestation_report=AttestationReportInfo(provider="software-only", measurement="", report_data="",
            attestation_generated_at=datetime.now(UTC).isoformat(), attestation_validity_seconds=86400),
        policy_bundle=PolicyBundleInfo(hash="sha256:"+"a"*64, enforcement_mode="enforcing", policy_version="1"),
        tool_catalog=ToolCatalogInfo(hash="sha256:"+"b"*64),
        call_summary=CallSummary(tool_calls_total=1, tool_calls_allowed=1, tool_calls_denied=0, tool_calls_faulted=0,
            tools_invoked=["sage_remember"], session_max_sensitivity="internal",
            call_graph_summary=CallGraphSummary(compliance_domains_touched=["x"], cross_boundary_events=[])),
        audit_chain_root="sha256:"+"c"*64, audit_chain_tip="sha256:"+"d"*64, audit_chain_length=1
    ).model_dump(exclude_none=True)

def _failures(results):
    return sum(1 for findings in results.values() for f in findings if f.failed())

p = tempfile.mktemp(suffix=".json"); open(p,"w").write(json.dumps(_mint()))
data, fmt = load_record(p)
assert fmt == "cmcp-runtime", fmt
res0 = run(data, fmt, level=0)
assert _failures(res0) == 0, "cMCP claim must pass trace-tests Level 0"
print(f"  cMCP RuntimeClaim PASSES agentrust-trace-tests Level 0  (fmt={fmt}, 0 failures)")
# Honesty: Level 1 must FAIL for software-only (no hardware root)
res1 = run(data, fmt, level=1)
assert _failures(res1) > 0, "software-only must NOT pass Level 1"
print(f"  software-only correctly FAILS Level 1 ({_failures(res1)} failures) — no hardware root claimed")
print("CONFORMANCE TESTS PASSED")
