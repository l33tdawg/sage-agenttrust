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
    # C-1 only: the gateway key was checked against an operator-pinned key. Defaults to False so
    # every existing construction (and every C-2 record, which is key-equal by construction)
    # keeps its meaning: unanchored.
    identity_anchored: bool = False


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
                   identity_anchored INTEGER DEFAULT 0,
                   record_json TEXT NOT NULL,
                   verified_at INTEGER NOT NULL
               )"""
        )
        # A database written before identity_anchored existed keeps working: add the column
        # rather than requiring a fresh store.
        cols = {row[1] for row in self._db.execute("PRAGMA table_info(attestation)")}
        if "identity_anchored" not in cols:
            self._db.execute(
                "ALTER TABLE attestation ADD COLUMN identity_anchored INTEGER DEFAULT 0")
        self._db.commit()

    def put(self, ev: Evidence) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO attestation "
                "(memory_id,agent_id,attestation_digest,cnf_thumbprint,platform,"
                " hardware_backed,identity_anchored,record_json,verified_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (ev.memory_id, ev.agent_id, ev.attestation_digest, ev.cnf_thumbprint,
                 ev.platform, int(ev.hardware_backed), int(ev.identity_anchored),
                 json.dumps(ev.record), ev.verified_at),
            )
            self._db.commit()

    def get(self, memory_id: str) -> Evidence | None:
        with self._lock:
            row = self._db.execute(
                "SELECT memory_id,agent_id,attestation_digest,cnf_thumbprint,platform,"
                "hardware_backed,record_json,verified_at,identity_anchored "
                "FROM attestation WHERE memory_id=?",
                (memory_id,),
            ).fetchone()
        if not row:
            return None
        return Evidence(
            memory_id=row[0], agent_id=row[1], attestation_digest=row[2],
            cnf_thumbprint=row[3], platform=row[4], hardware_backed=bool(row[5]),
            record=json.loads(row[6]), verified_at=row[7],
            identity_anchored=bool(row[8]),
        )

    def badge(self, memory_id: str) -> dict[str, Any] | None:
        """Compact provenance badge for recall enrichment."""
        ev = self.get(memory_id)
        if not ev:
            return None
        # Bare TRACE records carry these at top level; cMCP envelopes nest them under "trace".
        trace = ev.record.get("trace", {}) if isinstance(ev.record.get("trace"), dict) else {}
        # The badge states exactly what was proven: an edge-verified signature, then the author
        # binding at whatever strength this deployment actually established. `verification` is
        # always "edge-only" — it names WHERE verification happened (at the proxy, not re-checked
        # in SAGE consensus), not how strong the evidence is; strength lives in `binding`,
        # `identity_anchored` and `hardware_verified`. The runtime platform is always surfaced as
        # `platform_claimed` (self-asserted) — `hardware_verified` true means a pinned silicon
        # root was actually checked, and that requires the operator to have pinned one.
        is_cmcp = "cmcp_version" in ev.record
        if not is_cmcp:
            binding = "key-equal (cnf == author)"
        elif ev.identity_anchored:
            binding = "pinned-issuer (gateway key matches the configured trusted key)"
        else:
            binding = "gateway-asserted (no trust root)"
        return {
            "edge_verified": True,
            "verification": "edge-only",
            "hardware_verified": ev.hardware_backed,
            # The binding strength travels WITH the badge, not just in the README.
            "binding": binding,
            "identity_anchored": ev.identity_anchored,
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
