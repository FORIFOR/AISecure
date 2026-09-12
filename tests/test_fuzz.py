"""Fuzz the untrusted-input boundary: the log importer.

The importer is the main place attacker-influenced bytes enter the system, so
these tests throw many random and adversarial inputs at it and assert the
invariants that must hold no matter what: it never raises an unhandled
exception (only the declared ImportError_/ValidationError), it never carries a
value from an un-mapped column into the snapshot, unreadable values stay null
rather than becoming a "safe" value, and whatever survives still passes strict
normalization. Deterministic: each case uses a seeded RNG.
"""
from __future__ import annotations
import json
import random
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from aisecure.connectors import build_snapshot, load_profile, ImportError_
from aisecure.schema import normalize, ValidationError

KEY = b"z" * 32
NOW = datetime(2026, 9, 2, tzinfo=timezone.utc)
ASSET_HEADER = "asset_id,type,exposed,admin_path,sensitive_path,patch,observed_at,advisory,cvss,kev\n"
HOSTILE = ["</script>", "<img src=x onerror=alert(1)>", "\x00", "\t", "\n", "\r", "%s%n", "{0.__class__}",
           " ", " ", "'; DROP TABLE assets;--", "../../etc/passwd", "\\", '"', ",", "™日本語",
           "inf", "nan", "1e400", "-1", "true", "false", "null", "9" * 40, "A" * 5000, "🙂", "﻿"]


def rnd_token(rng: random.Random) -> str:
    if rng.random() < 0.5:
        return rng.choice(HOSTILE)
    return "".join(rng.choice("abcABC012 \t,\"</>\x00%{}日") for _ in range(rng.randrange(0, 40)))


class ImportFuzzTests(unittest.TestCase):
    ALLOWED_LOGIN = {"id", "type", "at", "actor", "session", "gateway_id", "success", "privileged", "device_trusted", "approved"}
    ALLOWED_FILE = {"id", "type", "at", "actor", "session", "asset_id", "file_id", "sensitive", "bytes_read"}

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        (self.dir / "assets.csv").write_text(
            ASSET_HEADER + "fileserver-01,server,no,なし,あり,適用済,2026-09-01T09:00:00,,,\n", encoding="utf-8")
        self.assets = (self.dir / "assets.csv", load_profile("generic-asset-csv"))

    def _write(self, name: str, data: bytes) -> Path:
        p = self.dir / name
        p.write_bytes(data)
        return p

    def test_csv_login_fuzz_never_crashes_or_leaks(self):
        auth = load_profile("generic-auth-csv")
        header = "timestamp,event_id,user,session_id,gateway,result,account_type,device_state,change_ticket,secret_col\n"
        for seed in range(250):
            rng = random.Random(seed)
            rows = [header]
            for _ in range(rng.randrange(0, 6)):
                cols = [rnd_token(rng) for _ in range(rng.randrange(0, 12))]
                rows.append(",".join(c.replace("\n", " ").replace("\r", " ") for c in cols) + "\n")
            marker = f"CANARY{seed}"
            rows.append(f"2026-09-01T09:00:00,e{seed},{marker},s,gw,success,user,managed,CHG-1,{marker}SECRET\n")
            path = self._write(f"a{seed}.csv", "".join(rows).encode("utf-8", "surrogatepass"))
            try:
                snapshot, quality = build_snapshot([self.assets, (path, auth)])
            except (ImportError_, ValidationError):
                continue  # declared refusals are fine
            blob = json.dumps(snapshot, ensure_ascii=False)
            # the un-mapped "secret_col" must never reach the snapshot
            self.assertNotIn(f"{marker}SECRET", blob, f"seed {seed}: un-mapped column leaked")
            # every event carries only allowlisted keys
            for e in snapshot["events"]:
                self.assertLessEqual(set(e), self.ALLOWED_LOGIN, f"seed {seed}: extra key")
            # whatever survived must pass strict normalization without raising unexpectedly
            try:
                normalize(snapshot, KEY, source_mode="imported", now=NOW)
            except ValidationError:
                self.fail(f"seed {seed}: importer produced a snapshot that normalize() rejected")

    def test_jsonl_file_access_fuzz_never_crashes(self):
        prof = load_profile("generic-file-access-jsonl")
        for seed in range(250):
            rng = random.Random(1000 + seed)
            lines = []
            for _ in range(rng.randrange(0, 6)):
                choice = rng.random()
                if choice < 0.3:
                    lines.append("".join(rng.choice("{}[]\":,\x00 abc</script> ") for _ in range(rng.randrange(0, 60))))
                elif choice < 0.6:
                    lines.append(json.dumps({"ts": rng.choice([rnd_token(rng), rng.randrange(-10, 10**13), 1e400]),
                                             "user": {"id": rnd_token(rng)}, "session": rnd_token(rng),
                                             "host": rng.choice(["fileserver-01", rnd_token(rng)]),
                                             "path": rnd_token(rng), "label": rnd_token(rng),
                                             "bytes": rng.choice([rnd_token(rng), rng.randrange(-5, 10**13)])}))
                else:
                    lines.append(rng.choice(["[]", "123", "\"x\"", "null", "true", "{not json}", ""]))
            path = self._write(f"j{seed}.jsonl", ("\n".join(lines) + "\n").encode("utf-8", "surrogatepass"))
            try:
                snapshot, quality = build_snapshot([self.assets, (path, prof)])
            except (ImportError_, ValidationError):
                continue
            for e in snapshot["events"]:
                self.assertLessEqual(set(e), self.ALLOWED_FILE, f"seed {seed}: extra key")
                # bytes_read is either a bounded int or unknown — never a hostile string
                self.assertTrue(e["bytes_read"] is None or isinstance(e["bytes_read"], int), f"seed {seed}: bad bytes_read")
            try:
                normalize(snapshot, KEY, source_mode="imported", now=NOW)
            except ValidationError:
                self.fail(f"seed {seed}: importer produced a snapshot that normalize() rejected")

    def test_random_bytes_are_refused_or_read_but_never_crash(self):
        auth = load_profile("generic-auth-csv")
        for seed in range(120):
            rng = random.Random(5000 + seed)
            blob = bytes(rng.randrange(0, 256) for _ in range(rng.randrange(0, 2048)))
            path = self._write(f"r{seed}.bin", blob)
            try:
                build_snapshot([self.assets, (path, auth)])
            except (ImportError_, ValidationError):
                pass  # only the declared exception types are acceptable


if __name__ == "__main__":
    unittest.main()
