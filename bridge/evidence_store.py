"""Off-chain attestation evidence store, keyed by SAGE memory_id.

The full TRACE record lives here (off-chain); the digest + cnf thumbprint are what a
future on-chain pin would carry. A caller fetches the provenance badge for a known
memory_id via GET /v1/attestation/{memory_id} (a lookup, not an automatic recall join).
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any


@dataclass
class Evidence:
    memory_id: str
    agent_id: str
    attestation_digest: str
    cnf_thumbprint: str
    platform: str
    hardware_backed: bool
    record: dict[str, Any]
    verified_at: int


class EvidenceStore:
    def __init__(self, path: str = "attestations.db") -> None:
        # M1: one shared connection across async/threaded handlers needs a lock — sqlite3 with
        # check_same_thread=False is not safe for concurrent use without serialization.
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute(
            """CREATE TABLE IF NOT EXISTS attestation (
                   memory_id TEXT PRIMARY KEY,
                   agent_id TEXT NOT NULL,
                   attestation_digest TEXT NOT NULL,
                   cnf_thumbprint TEXT NOT NULL,
                   platform TEXT,
                   hardware_backed INTEGER,
                   record_json TEXT NOT NULL,
                   verified_at INTEGER NOT NULL
               )"""
        )
        self._db.commit()

    def put(self, ev: Evidence) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO attestation VALUES (?,?,?,?,?,?,?,?)",
                (ev.memory_id, ev.agent_id, ev.attestation_digest, ev.cnf_thumbprint,
                 ev.platform, int(ev.hardware_backed), json.dumps(ev.record), ev.verified_at),
            )
            self._db.commit()

    def get(self, memory_id: str) -> Evidence | None:
        with self._lock:
            row = self._db.execute(
                "SELECT memory_id,agent_id,attestation_digest,cnf_thumbprint,platform,"
                "hardware_backed,record_json,verified_at FROM attestation WHERE memory_id=?",
                (memory_id,),
            ).fetchone()
        if not row:
            return None
        return Evidence(
            memory_id=row[0], agent_id=row[1], attestation_digest=row[2],
            cnf_thumbprint=row[3], platform=row[4], hardware_backed=bool(row[5]),
            record=json.loads(row[6]), verified_at=row[7],
        )

    def badge(self, memory_id: str) -> dict[str, Any] | None:
        """Compact provenance badge for recall enrichment."""
        ev = self.get(memory_id)
        if not ev:
            return None
        # Bare TRACE records carry these at top level; cMCP envelopes nest them under "trace".
        trace = ev.record.get("trace", {}) if isinstance(ev.record.get("trace"), dict) else {}
        # The badge states exactly what was proven: an edge-verified signature + (for C-2) a
        # key-equal author binding. The bridge does NOT verify hardware, so `verification` is
        # always "edge-only", `hardware_verified` is always false, and the runtime platform is
        # surfaced as `platform_claimed` (self-asserted, NOT verified by this bridge).
        is_cmcp = "cmcp_version" in ev.record
        return {
            "edge_verified": True,
            "verification": "edge-only",
            "hardware_verified": False,
            # The binding strength travels WITH the badge, not just in the README.
            "binding": "gateway-asserted (no trust root)" if is_cmcp else "key-equal (cnf == author)",
            "attestation_kind": "cmcp-runtime" if is_cmcp else "trace",
            "attestation_digest": ev.attestation_digest,
            "cnf_thumbprint": ev.cnf_thumbprint,
            "eat_profile": ev.record.get("eat_profile") or trace.get("eat_profile"),
            "platform_claimed": ev.platform,
            "subject": ev.record.get("subject") or trace.get("subject"),
            "verified_at": ev.verified_at,
        }


def now() -> int:
    return int(time.time())
