"""A bounded polling monitor for exported security logs.

This is the first live path beyond one-shot analysis.  It deliberately reads
the source files through the same read-only importer used by ``import`` and
rebuilds a signed snapshot when their normalized contents change.  It does not
tail partial rows, delete source data, or infer missing fields as safe.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import threading
import time
from pathlib import Path

from .connectors import build_snapshot, MAX_ROWS, MAX_SOURCE_BYTES
from .schema import canonical, IMPORT_MAX_ASSETS, IMPORT_MAX_EVENTS, utcnow
from .store import Store


@dataclass(frozen=True)
class PollResult:
    changed: bool
    snapshot_id: str | None
    findings: int
    priority_one: int
    quality: dict

    def as_dict(self) -> dict:
        return {"changed": self.changed, "snapshot_id": self.snapshot_id,
                "findings": self.findings, "priority_one": self.priority_one,
                "quality": self.quality}


class FileMonitor:
    """Poll one or more read-only log exports and ingest changed evidence."""

    def __init__(self, store: Store, sources: list[tuple[Path, dict]], *,
                 unknown_assets: str = "record", max_rows: int = MAX_ROWS,
                 interval: float = 30.0):
        if not sources:
            raise ValueError("監視するソースが必要です。")
        if not 1 <= interval <= 3600:
            raise ValueError("監視間隔は1〜3600秒にしてください。")
        self.store = store
        self.sources = sources
        self.unknown_assets = unknown_assets
        self.max_rows = max_rows
        self.interval = interval
        self._fingerprint: str | None = None

    def poll_once(self) -> PollResult:
        snapshot, quality = build_snapshot(
            self.sources, unknown_assets=self.unknown_assets,
            max_rows=self.max_rows, max_bytes=MAX_SOURCE_BYTES, now=utcnow(),
        )
        fingerprint = hashlib.sha256(canonical(snapshot).encode("utf-8")).hexdigest()
        if fingerprint == self._fingerprint:
            state = self.store.state()
            findings = state["findings"]
            return PollResult(False, state["snapshot_id"], len(findings),
                              sum(f["priority"] == "P1" for f in findings), quality)
        sid = self.store.ingest(snapshot, "imported", max_events=IMPORT_MAX_EVENTS,
                                max_assets=IMPORT_MAX_ASSETS, verified_provenance=True)
        self._fingerprint = fingerprint
        state = self.store.state()
        findings = state["findings"]
        self.store.record("monitor.polled", {
            "snapshot_id": sid, "changed": True,
            "sources": len(self.sources), "events": quality["totals"]["events"],
            "findings": len(findings),
            "priority_one": sum(f["priority"] == "P1" for f in findings),
            "quality_warnings": len(quality["warnings"]),
        })
        return PollResult(True, sid, len(findings),
                          sum(f["priority"] == "P1" for f in findings), quality)

    def run(self, stop: threading.Event | None = None):
        stop = stop or threading.Event()
        while not stop.is_set():
            self.poll_once()
            stop.wait(self.interval)
