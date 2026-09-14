from __future__ import annotations
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
import unittest.mock

from aisecure.connectors import build_snapshot, load_profile, builtin_profiles, slug, ImportError_
from aisecure.connectors import profile as profile_module
from aisecure.engine import analyze
from aisecure.schema import normalize, ValidationError

KEY = b'y' * 32
ASSET_HEADER = "asset_id,type,exposed,admin_path,sensitive_path,patch,observed_at,advisory,cvss,kev\n"
AUTH_HEADER = "timestamp,event_id,user,session_id,gateway,result,account_type,device_state,change_ticket\n"


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)

    def write(self, name: str, text: str) -> Path:
        path = self.dir / name
        path.write_text(text, encoding="utf-8")
        return path

    def assets(self, rows: str = "") -> Path:
        default = "edge-vpn-01,vpn,yes,あり,あり,未適用,2026-09-01T09:00:00,DEMO-ADV-001,6.5,no\nfileserver-01,fileserver,no,なし,あり,適用済,2026-09-01T09:00:00,,,\n"
        return self.write("assets.csv", ASSET_HEADER + (rows or default))

    def source(self, name: str, path: Path):
        return (path, load_profile(name))


class ProfileTests(Fixture):
    def test_builtin_profiles_load(self):
        self.assertEqual(set(builtin_profiles()), {"generic-asset-csv", "generic-auth-csv", "generic-file-access-jsonl", "okta-system-log-jsonl", "windows-security-logon-csv"})
        for name in builtin_profiles():
            self.assertEqual(load_profile(name)["profile_version"], 1)

    def test_profile_cannot_map_a_target_outside_the_allowlist(self):
        with self.assertRaises(ValidationError):
            profile_module.load({"profile_version": 1, "name": "bad", "format": "csv", "record": "login",
                                 "map": {"at": {"field": "t"}, "actor": {"field": "u"}, "session": {"field": "s"},
                                         "gateway_id": {"field": "g"}, "success": {"field": "r"},
                                         "file_contents": {"field": "body"}}})

    def test_required_targets_must_be_mapped(self):
        with self.assertRaises(ValidationError):
            profile_module.load({"profile_version": 1, "name": "bad", "format": "csv", "record": "file_access",
                                 "map": {"at": {"field": "t"}}})

    def test_unknown_profile_keys_rejected(self):
        raw = json.loads((builtin_profiles()["generic-auth-csv"]).read_text(encoding="utf-8"))
        raw["execute"] = "rm -rf /"
        with self.assertRaises(ValidationError):
            profile_module.load(raw)

    def test_missing_profile_names_the_builtins(self):
        with self.assertRaises(ValidationError) as caught:
            load_profile("does-not-exist")
        self.assertIn("generic-auth-csv", str(caught.exception))

    def test_slug_keeps_valid_names_and_separates_different_ones(self):
        self.assertEqual(slug("edge-vpn-01"), "edge-vpn-01")
        self.assertNotEqual(slug("社内 ファイルサーバ"), slug("社内 ファイルサーバ 2"))
        self.assertTrue(slug("//: ").isascii())


class ImportTests(Fixture):
    def test_end_to_end_import_detects_the_correlation(self):
        rows = ["2026-09-01T22:00:00,lg-1,vendor@example.invalid,sess-1,edge-vpn-01,success,maintenance,unmanaged,none\n"]
        auth = self.write("auth.csv", AUTH_HEADER + "".join(rows))
        lines = []
        for i in range(130):
            lines.append(json.dumps({"ts": int(datetime(2026, 9, 1, 13, 5, i % 60, tzinfo=timezone.utc).timestamp() * 1000) + i * 2000,
                                     "user": {"id": "vendor@example.invalid"}, "session": "sess-1",
                                     "host": "fileserver-01", "path": f"/share/personnel/{i}", "label": "confidential", "bytes": 2048}))
        access = self.write("access.jsonl", "\n".join(lines) + "\n")
        snapshot, quality = build_snapshot([self.source("generic-asset-csv", self.assets()),
                                            self.source("generic-auth-csv", auth),
                                            self.source("generic-file-access-jsonl", access)])
        document = normalize(snapshot, KEY, source_mode="imported", now=datetime(2026, 9, 2, tzinfo=timezone.utc))
        self.assertEqual({f["rule"] for f in analyze(document)}, {"AS-001", "AS-002", "AS-003", "AS-004"})
        self.assertEqual(quality["totals"]["rows_imported"], 133)

    def test_sources_are_hashed_for_provenance(self):
        snapshot, quality = build_snapshot([self.source("generic-asset-csv", self.assets())])
        self.assertEqual(len(snapshot["provenance"]), 1)
        self.assertEqual(snapshot["provenance"][0]["label"], "assets.csv")
        self.assertRegex(snapshot["provenance"][0]["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(quality["sources"][0]["rows_imported"], 2)

    def test_unmapped_columns_never_reach_the_snapshot(self):
        path = self.write("assets.csv", ASSET_HEADER.rstrip("\n") + ",password,secret_note\n"
                          "edge-vpn-01,vpn,yes,あり,あり,未適用,2026-09-01T09:00:00,DEMO-ADV-001,6.5,no,hunter2,機密メモ\n")
        snapshot, _ = build_snapshot([self.source("generic-asset-csv", path)])
        self.assertNotIn("hunter2", json.dumps(snapshot, ensure_ascii=False))
        self.assertNotIn("機密メモ", json.dumps(snapshot, ensure_ascii=False))

    def test_unreadable_value_becomes_unknown_not_safe(self):
        path = self.write("assets.csv", ASSET_HEADER + "edge-vpn-01,vpn,たぶん,,,未適用,2026-09-01T09:00:00,DEMO-ADV-001,6.5,\n")
        snapshot, quality = build_snapshot([self.source("generic-asset-csv", path)])
        asset = snapshot["assets"][0]
        self.assertIsNone(asset["internet_exposed"])
        self.assertIsNone(asset["privileged_path"])
        self.assertEqual(quality["totals"]["unknown_values"]["internet_exposed"], 1)

    def test_row_without_a_timezone_is_skipped_not_guessed(self):
        spec = load_profile("generic-auth-csv")
        spec["map"]["at"]["timezone"] = None
        auth = self.write("auth.csv", AUTH_HEADER + "2026-09-01T22:00:00,lg-1,u,s,edge-vpn-01,success,user,managed,CHG-1\n")
        snapshot, quality = build_snapshot([self.source("generic-asset-csv", self.assets()), (auth, spec)])
        self.assertEqual(snapshot["events"], [])
        self.assertEqual(quality["totals"]["skip_reasons"], {"atを読み取れません": 1})

    def test_declared_timezone_is_converted_to_utc(self):
        auth = self.write("auth.csv", AUTH_HEADER + "2026-09-01T09:00:00,lg-1,u,s,edge-vpn-01,success,user,managed,CHG-1\n")
        snapshot, _ = build_snapshot([self.source("generic-asset-csv", self.assets()), self.source("generic-auth-csv", auth)])
        self.assertEqual(snapshot["events"][0]["at"], "2026-09-01T00:00:00Z")

    def test_asset_seen_only_in_logs_is_recorded_as_unknown(self):
        auth = self.write("auth.csv", AUTH_HEADER + "2026-09-01T09:00:00,lg-1,u,s,shadow-gateway,success,user,managed,CHG-1\n")
        snapshot, quality = build_snapshot([self.source("generic-asset-csv", self.assets()), self.source("generic-auth-csv", auth)])
        shadow = next(a for a in snapshot["assets"] if a["id"] == "shadow-gateway")
        self.assertEqual((shadow["patch_state"], shadow["kind"]), ("unknown", "unknown"))
        self.assertIsNone(shadow["internet_exposed"])
        self.assertEqual(quality["shadow_assets"], ["shadow-gateway"])
        document = normalize(snapshot, KEY, source_mode="imported", now=datetime(2026, 9, 2, tzinfo=timezone.utc))
        self.assertIn("AS-005", {f["rule"] for f in analyze(document)})

    def test_skip_policy_drops_events_for_unknown_assets(self):
        auth = self.write("auth.csv", AUTH_HEADER + "2026-09-01T09:00:00,lg-1,u,s,shadow-gateway,success,user,managed,CHG-1\n")
        snapshot, _ = build_snapshot([self.source("generic-asset-csv", self.assets()), self.source("generic-auth-csv", auth)],
                                     unknown_assets="skip")
        self.assertEqual(snapshot["events"], [])
        self.assertNotIn("shadow-gateway", [a["id"] for a in snapshot["assets"]])

    def test_repeated_identical_rows_collapse_to_one_event(self):
        spec = load_profile("generic-auth-csv")
        del spec["map"]["id"]  # no event id in the source: identity is derived from content
        spec["map"]["id"] = {"target": "id", "kind": "id", "derive": "content"}
        line = "2026-09-01T09:00:00,ignored,u,s,edge-vpn-01,success,user,managed,CHG-1\n"
        auth = self.write("auth.csv", AUTH_HEADER + line + line)
        snapshot, _ = build_snapshot([self.source("generic-asset-csv", self.assets()), (auth, spec)])
        document = normalize(snapshot, KEY, source_mode="imported", now=datetime(2026, 9, 2, tzinfo=timezone.utc))
        self.assertEqual(len(document["events"]), 1)

    def test_malformed_json_lines_are_counted_not_fatal(self):
        access = self.write("access.jsonl", "{not json}\n[]\n" + json.dumps(
            {"ts": 1788195720000, "user": {"id": "u"}, "session": "s", "host": "fileserver-01",
             "path": "/share/a", "label": "internal", "bytes": 1}) + "\n")
        snapshot, quality = build_snapshot([self.source("generic-asset-csv", self.assets()),
                                            self.source("generic-file-access-jsonl", access)])
        self.assertEqual(len(snapshot["events"]), 1)
        self.assertEqual(quality["totals"]["rows_skipped"], 2)

    def test_file_path_is_kept_only_as_a_pseudonymous_identifier(self):
        access = self.write("access.jsonl", json.dumps(
            {"ts": 1788195720000, "user": {"id": "tanaka@example.invalid"}, "session": "s",
             "host": "fileserver-01", "path": "/share/人事/給与2026.xlsx", "label": "機密", "bytes": 1}) + "\n")
        snapshot, _ = build_snapshot([self.source("generic-asset-csv", self.assets()),
                                      self.source("generic-file-access-jsonl", access)])
        self.assertTrue(snapshot["events"][0]["sensitive"])
        document = normalize(snapshot, KEY, source_mode="imported", now=datetime(2026, 9, 2, tzinfo=timezone.utc))
        stored = json.dumps(document, ensure_ascii=False)
        self.assertNotIn("給与2026", stored)
        self.assertNotIn("tanaka", stored)

    def test_symlinked_source_refused(self):
        target = self.assets()
        link = self.dir / "link.csv"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(ImportError_):
            build_snapshot([self.source("generic-asset-csv", link)])

    def test_row_limit_is_enforced(self):
        rows = "".join(f"asset-{i},server,no,なし,なし,適用済,2026-09-01T09:00:00,,,\n" for i in range(10))
        with self.assertRaises(ImportError_):
            build_snapshot([self.source("generic-asset-csv", self.write("many.csv", ASSET_HEADER + rows))], max_rows=5)

    def test_oversized_source_refused(self):
        with self.assertRaises(ImportError_):
            build_snapshot([self.source("generic-asset-csv", self.assets())], max_bytes=10)

    def test_import_without_an_inventory_is_refused(self):
        auth = self.write("auth.csv", AUTH_HEADER + "2026-09-01T09:00:00,lg-1,u,s,edge-vpn-01,success,user,managed,CHG-1\n")
        with self.assertRaises(ImportError_):
            build_snapshot([self.source("generic-auth-csv", auth)], unknown_assets="skip")

    def test_missing_sources_are_reported_as_warnings(self):
        _, quality = build_snapshot([self.source("generic-asset-csv", self.assets())])
        self.assertTrue(any("認証ログ" in w for w in quality["warnings"]))
        self.assertTrue(any("真正性" in w for w in quality["warnings"]))

    def test_control_characters_do_not_poison_the_whole_snapshot(self):
        auth = self.write("auth.csv", AUTH_HEADER
                          + "2026-09-01T09:00:00,lg-1,good,s,edge-vpn-01,success,user,managed,CHG-1\n"
                          + "2026-09-01T09:01:00,lg-2,bad\x00user,s,edge-vpn-01,success,user,managed,CHG-1\n")
        snapshot, quality = build_snapshot([self.source("generic-asset-csv", self.assets()),
                                            self.source("generic-auth-csv", auth)])
        self.assertEqual(len(snapshot["events"]), 1)
        self.assertEqual(quality["totals"]["skip_reasons"], {"actorに制御文字が含まれます": 1})
        # The remaining rows must still survive validation.
        normalize(snapshot, KEY, source_mode="imported", now=datetime(2026, 9, 2, tzinfo=timezone.utc))

    def test_tab_in_a_file_path_skips_only_that_row(self):
        rows = [json.dumps({"ts": 1788195720000, "user": {"id": "u"}, "session": "s", "host": "fileserver-01",
                            "path": "/share/a\tb", "label": "internal", "bytes": 1}),
                json.dumps({"ts": 1788195721000, "user": {"id": "u"}, "session": "s", "host": "fileserver-01",
                            "path": "/share/ok", "label": "internal", "bytes": 1})]
        access = self.write("access.jsonl", "\n".join(rows) + "\n")
        snapshot, quality = build_snapshot([self.source("generic-asset-csv", self.assets()),
                                            self.source("generic-file-access-jsonl", access)])
        self.assertEqual(len(snapshot["events"]), 1)
        self.assertEqual(quality["totals"]["rows_skipped"], 1)
        normalize(snapshot, KEY, source_mode="imported", now=datetime(2026, 9, 2, tzinfo=timezone.utc))

    def test_same_event_id_with_different_content_keeps_both_records(self):
        """A planted row must not be able to evict the genuine one it collides with."""
        auth = self.write("auth.csv", AUTH_HEADER
                          + "2026-09-01T08:00:00,lg-1,attacker,s0,edge-vpn-01,failure,user,managed,none\n"
                          + "2026-09-01T23:17:00,lg-1,vendor,s1,edge-vpn-01,success,maintenance,unmanaged,none\n")
        snapshot, quality = build_snapshot([self.source("generic-asset-csv", self.assets()),
                                            self.source("generic-auth-csv", auth)])
        self.assertEqual(len(snapshot["events"]), 2)
        self.assertEqual(len({e["id"] for e in snapshot["events"]}), 2)
        genuine = [e for e in snapshot["events"] if e["privileged"] is True]
        self.assertEqual(len(genuine), 1)
        self.assertIs(genuine[0]["device_trusted"], False)
        self.assertIn("同じイベントIDのため別IDを付与", quality["totals"]["skip_reasons"])
        self.assertTrue(any("別IDを付与" in w for w in quality["warnings"]))
        document = normalize(snapshot, KEY, source_mode="imported", now=datetime(2026, 9, 2, tzinfo=timezone.utc))
        self.assertEqual(len(document["events"]), 2)

    def test_normalized_identifier_cannot_be_forged_as_a_raw_name(self):
        """slug() output must never be producible by a raw name, or an attacker could
        name a device so that it merges with, and overwrites, somebody else's asset."""
        victim = "VPN装置 01"
        forged = slug(victim)
        self.assertNotEqual(slug(forged), forged)
        path = self.write("assets.csv", ASSET_HEADER
                          + f"{victim},vpn,yes,あり,あり,未適用,2026-09-01T09:00:00,DEMO-ADV-001,6.5,no\n"
                          + f"{forged},pc,no,なし,なし,適用済,2026-09-01T10:00:00,,,\n")
        snapshot, _ = build_snapshot([self.source("generic-asset-csv", path)])
        self.assertEqual(len(snapshot["assets"]), 2)
        gateway = next(a for a in snapshot["assets"] if a["kind"] == "vpn")
        self.assertTrue(gateway["internet_exposed"])
        self.assertEqual(gateway["patch_state"], "pending")

    def test_two_names_mapping_to_one_identifier_are_refused(self):
        with self.assertRaises(ImportError_):
            with unittest.mock.patch("aisecure.connectors.importer.slug", lambda v: "merged-id"):
                build_snapshot([self.source("generic-asset-csv", self.assets())])

    def test_non_finite_number_skips_only_that_row(self):
        rows = [json.dumps({"ts": 1788195720000, "user": {"id": "u"}, "session": "s", "host": "fileserver-01",
                            "path": "/share/a", "label": "internal", "bytes": "inf"}),
                json.dumps({"ts": 1788195721000, "user": {"id": "u"}, "session": "s", "host": "fileserver-01",
                            "path": "/share/b", "label": "internal", "bytes": 4096})]
        access = self.write("access.jsonl", "\n".join(rows) + "\n")
        snapshot, _ = build_snapshot([self.source("generic-asset-csv", self.assets()),
                                      self.source("generic-file-access-jsonl", access)])
        self.assertEqual(len(snapshot["events"]), 2)
        self.assertIsNone(next(e for e in snapshot["events"] if e["file_id"].endswith("/a"))["bytes_read"])

    def test_identical_repeated_rows_are_counted_as_duplicates(self):
        line = "2026-09-01T09:00:00,lg-1,alice,s,edge-vpn-01,success,user,managed,CHG-1\n"
        auth = self.write("auth.csv", AUTH_HEADER + line + line)
        snapshot, quality = build_snapshot([self.source("generic-asset-csv", self.assets()),
                                            self.source("generic-auth-csv", auth)])
        self.assertEqual(len(snapshot["events"]), 1)
        self.assertEqual(quality["totals"]["skip_reasons"], {"同じ行の重複": 1})
        self.assertEqual(quality["sources"][1]["rows_imported"], 1)

    def test_hostile_sources_are_refused_or_counted_never_crash(self):
        cases = {
            "deep.jsonl": "[" * 50000 + "]" * 50000 + "\n",
            "binary.jsonl": "".join(chr(c) for c in range(1, 256)) * 50 + "\n",
            "long.jsonl": '{"ts":1,"user":{"id":"' + "x" * 400000 + '"}}\n',
        }
        for name, text in cases.items():
            path = self.write(name, text)
            snapshot, quality = build_snapshot([self.source("generic-asset-csv", self.assets()),
                                                self.source("generic-file-access-jsonl", path)])
            self.assertEqual(snapshot["events"], [], name)
            self.assertGreater(quality["totals"]["rows_skipped"], 0, name)

    def test_oversized_csv_field_is_refused_without_leaking_content(self):
        path = self.write("big.csv", ASSET_HEADER + "a,server,no,なし,なし,適用済,2026-09-01T09:00:00," + "z" * 100000 + ",,\n")
        with self.assertRaises(ImportError_) as caught:
            build_snapshot([self.source("generic-asset-csv", path)])
        self.assertNotIn("z" * 20, str(caught.exception))

    def test_hand_written_provenance_is_marked_unverified(self):
        """A snapshot can claim any origin; only the importing run may assert one."""
        forged = {"schema_version": 1, "as_of": "2026-09-01T12:00:00Z",
                  "provenance": [{"label": "corp-vpn-audit.csv", "sha256": "0" * 64,
                                  "rows_read": 120000, "rows_imported": 120000, "connector": "file-import"}],
                  "assets": [{"id": "edge-vpn-01", "kind": "vpn", "internet_exposed": True, "privileged_path": True,
                              "sensitive_path": True, "patch_state": "applied",
                              "observed_at": "2026-09-01T09:00:00Z", "vulnerability": None}],
                  "events": []}
        document = normalize(forged, KEY, source_mode="imported", now=datetime(2026, 9, 2, tzinfo=timezone.utc))
        self.assertFalse(document["provenance"][0]["verified"])
        trusted = normalize(forged, KEY, source_mode="imported", now=datetime(2026, 9, 2, tzinfo=timezone.utc),
                            verified_provenance=True)
        self.assertTrue(trusted["provenance"][0]["verified"])

    def test_windows_security_profile_maps_4624_4625(self):
        rows = ("TimeCreated,EventID,TargetUserName,TargetLogonId,IpAddress,LogonType,WorkstationName\n"
                "2026-09-01 08:59:11,4625,u,0x0,10.0.0.1,3,fileserver-01\n"
                "2026-09-01 09:00:02,4624,u,0x3E9,10.0.0.1,3,fileserver-01\n")
        path = self.write("winsec.csv", rows)
        snapshot, quality = build_snapshot([self.source("generic-asset-csv", self.assets()),
                                            self.source("windows-security-logon-csv", path)])
        logins = sorted(snapshot["events"], key=lambda e: e["at"])
        self.assertEqual([e["success"] for e in logins], [False, True])
        self.assertEqual(logins[1]["at"], "2026-09-01T00:00:02Z")  # +09:00 -> UTC
        self.assertIsNone(logins[0]["privileged"])  # not knowable from this log
        self.assertEqual(quality["totals"]["rows_skipped"], 0)

    def test_okta_system_log_profile_round_trips_jsonl(self):
        rows = [
            {"uuid": "okta-evt-001", "published": "2026-09-15T00:00:01.000Z",
             "actor": {"alternateId": "operator@example.invalid"},
             "authenticationContext": {"externalSessionId": "okta-session-001"},
             "outcome": {"result": "SUCCESS"}, "client": {"ipAddress": "192.0.2.10"}},
            {"uuid": "okta-evt-002", "published": "2026-09-15T00:00:08.000Z",
             "actor": {"alternateId": "operator@example.invalid"},
             "authenticationContext": {"externalSessionId": "okta-session-002"},
             "outcome": {"result": "FAILURE"}, "client": {"ipAddress": "192.0.2.10"}},
        ]
        okta = self.write("okta.jsonl", "\n".join(json.dumps(row) for row in rows) + "\n")
        asset_rows = "okta-idp,saas,no,なし,なし,適用済,2026-09-15T09:00:00,,,\n"
        snapshot, quality = build_snapshot([self.source("generic-asset-csv", self.assets(asset_rows)),
                                            self.source("okta-system-log-jsonl", okta)],
                                           now=datetime(2026, 9, 15, 1, tzinfo=timezone.utc))
        logins = sorted(snapshot["events"], key=lambda event: event["id"])
        self.assertEqual([event["success"] for event in logins], [True, False])
        self.assertEqual([event["gateway_id"] for event in logins], ["okta-idp", "okta-idp"])
        self.assertIsNone(logins[0]["privileged"])
        self.assertEqual(quality["sources"][1]["rows_imported"], 2)
        document = normalize(snapshot, KEY, source_mode="imported", now=datetime(2026, 9, 15, 1, tzinfo=timezone.utc))
        stored = json.dumps(document, ensure_ascii=False)
        self.assertNotIn("operator@example.invalid", stored)
        self.assertNotIn("okta-session-001", stored)
        self.assertEqual(len(document["events"]), 2)

    def test_same_input_produces_the_same_snapshot(self):
        first, _ = build_snapshot([self.source("generic-asset-csv", self.assets())])
        second, _ = build_snapshot([self.source("generic-asset-csv", self.assets())])
        self.assertEqual(first["assets"], second["assets"])
        self.assertEqual(first["events"], second["events"])


if __name__ == '__main__':
    unittest.main()
