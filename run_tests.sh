#!/usr/bin/env bash
# Offline suite (no node needed): core crypto, proxy logic vs mock SAGE, cMCP verify, conformance.
set -e
cd "$(dirname "$0")"
PY=./.venv/bin/python
echo "== core ==";        $PY tests/test_trace_core.py
echo "== proxy e2e ==";   $PY tests/test_proxy_e2e.py
echo "== cmcp path ==";   $PY tests/test_cmcp_path.py 2>/dev/null
echo "== hardening ==";   $PY tests/test_hardening.py 2>/dev/null
echo "== conformance =="; $PY tests/test_conformance.py
echo "ALL OFFLINE TESTS PASSED"
