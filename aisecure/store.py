"""Local single-owner persistence with authenticated audit chains.

The audit chain detects modification without the key. Tail truncation needs a
separately retained checkpoint; host/key compromise is explicitly out of scope.
"""
from __future__ import annotations
from contextlib import contextmanager
from datetime import timedelta
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import threading
from .schema import canonical, normalize, utcnow, iso, parse_time, ValidationError, MAX_EVENTS, MAX_ASSETS
from .engine import analyze, coverage, RULE_VERSION
from .policy import plan_for, SimulationAdapter
from .responder import ResponderError, SignedWebhookResponder
from .rules import RuleConfig, DEFAULT as DEFAULT_RULES, describe
from .storage import StorageCipher, StorageCipherError, KEY_BYTES

ZERO = "0" * 64
# An explicit export still has to fit in a browser tab.
MAX_EXPORT_EVENTS = 200_000


class ConflictError(ValueError):
    pass


class IntegrityError(RuntimeError):
    pass


class Store:
    def __init__(self, directory: str | Path, config: RuleConfig | None = None,
                 master_key: bytes | None = None):
        self.config = config or DEFAULT_RULES
        self.directory = Path(directory).expanduser()
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            self.directory.chmod(0o700)
        key_path = self.directory / "master.key"
        db_path = self.directory / "state.sqlite3"
        self.encrypted = master_key is not None
        if master_key is not None:
            if not isinstance(master_key, bytes) or len(master_key) != KEY_BYTES:
                raise ValidationError("保管時暗号化の鍵は32バイトで指定してください。")
            self.master = master_key
            # A legacy local key in the same directory makes the source of
            # truth ambiguous. Do not silently open or migrate such a store.
            if key_path.exists() and db_path.exists():
                raise IntegrityError("暗号化ストアにローカル鍵が併存しています。移行手順を確認してください。")
        else:
            # Never silently replace a lost key for existing evidence.
            if db_path.exists() and not key_path.exists():
                raise IntegrityError("既存DBの鍵がありません。新しい鍵では起動しません。")
            try:
                fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(fd, "wb") as f:
                    f.write(secrets.token_bytes(KEY_BYTES))
            self.master = key_path.read_bytes()
            if len(self.master) != KEY_BYTES:
                raise IntegrityError("鍵の長さが不正です。")
            if os.name != "nt":
                key_path.chmod(0o600)
        self.identity_key = hmac.new(self.master, b"identity-v1", hashlib.sha256).digest()
        self.audit_key = hmac.new(self.master, b"audit-v1", hashlib.sha256).digest()
        self.cipher = StorageCipher(self.master) if self.encrypted else None
        self.lock = threading.RLock()
        self.db = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA journal_mode=DELETE")
        self.db.execute("PRAGMA busy_timeout=3000")
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS snapshots (
            id TEXT PRIMARY KEY, created_at TEXT NOT NULL, body TEXT NOT NULL, mac TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS current_snapshot (
            singleton INTEGER PRIMARY KEY CHECK (singleton=1), id TEXT REFERENCES snapshots(id));
          CREATE TABLE IF NOT EXISTS proposals (
            id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL REFERENCES snapshots(id),
            finding_id TEXT NOT NULL, body TEXT NOT NULL, created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL, status TEXT NOT NULL,
            approved_target_hmac TEXT);
          CREATE TABLE IF NOT EXISTS audit (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, action TEXT NOT NULL,
            payload TEXT NOT NULL, prev TEXT NOT NULL, mac TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS store_meta (
            key TEXT PRIMARY KEY, value TEXT NOT NULL);
        """)
        proposal_columns = {row["name"] for row in self.db.execute("PRAGMA table_info(proposals)")}
        if "approved_target_hmac" not in proposal_columns:
            self.db.execute("ALTER TABLE proposals ADD COLUMN approved_target_hmac TEXT")
        if os.name != "nt":
            db_path.chmod(0o600)
        mode = "encrypted" if self.encrypted else "plaintext"
        try:
            stored_mode = self.db.execute("SELECT value FROM store_meta WHERE key='storage_mode'").fetchone()
            if stored_mode is None:
                self.db.execute("INSERT INTO store_meta(key,value) VALUES('storage_mode',?)", (mode,))
            elif stored_mode[0] != mode:
                raise IntegrityError("保管モードが起動設定と一致しません。鍵または設定を確認してください。")
            if not self.verify_audit()["valid"]:
                raise IntegrityError("監査チェーンの検証に失敗しました。書き込みを停止します。")
            self._record_rule_config()
        except Exception:
            self.db.close()
            raise

    def _snapshot_aad(self, snapshot_id: str) -> str:
        return "snapshot:" + snapshot_id

    @staticmethod
    def _proposal_aad(proposal_id: str) -> str:
        return "proposal:" + proposal_id

    def _target_hmac(self, target: str) -> str:
        return hmac.new(self.audit_key, ("provider-target\0" + target).encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def _validate_provider_target(target: str) -> None:
        if not isinstance(target, str) or not 1 <= len(target) <= 160 or any(ord(c) < 32 for c in target):
            raise ValidationError("実操作には、防御側で確認した対象IDの明示指定が必要です。")

    @staticmethod
    def _audit_aad(seq: int, at: str, action: str, previous: str) -> str:
        return canonical(["audit", seq, at, action, previous])

    def _protect(self, value: str, associated_data: str) -> str:
        return self.cipher.encrypt(value, associated_data) if self.cipher else value

    def _unprotect(self, value: str, associated_data: str) -> str:
        if not self.cipher:
            return value
        try:
            return self.cipher.decrypt(value, associated_data)
        except StorageCipherError as exc:
            raise IntegrityError("保管データの完全性検証に失敗しました。") from exc

    def _audit_payload(self, row) -> dict:
        body = self._unprotect(row["payload"], self._audit_aad(row["seq"], row["at"], row["action"], row["prev"]))
        try:
            value = json.loads(body)
        except (ValueError, TypeError, UnicodeError) as exc:
            raise IntegrityError("監査ペイロードの形式が不正です。") from exc
        if not isinstance(value, dict):
            raise IntegrityError("監査ペイロードの形式が不正です。")
        return value

    def _proposal_plan(self, row) -> dict:
        body = self._unprotect(row["body"], self._proposal_aad(row["id"]))
        try:
            value = json.loads(body)
        except (ValueError, TypeError, UnicodeError) as exc:
            raise IntegrityError("対応計画の形式が不正です。") from exc
        if not isinstance(value, dict):
            raise IntegrityError("対応計画の形式が不正です。")
        return value

    @staticmethod
    def _validate_approval_assertions(assertions: list[dict] | None, proposal_id: str,
                                      snapshot_id: str, action: str,
                                      primary_operator: str, secondary_operator: str) -> None:
        if assertions is None:
            return
        if not isinstance(assertions, list) or len(assertions) != 2:
            raise ValidationError("署名付き承認証明は2件必要です。")
        expected = {"primary": primary_operator.strip(), "secondary": secondary_operator.strip()}
        seen_roles = set()
        seen_operators = set()
        for claim in assertions:
            if not isinstance(claim, dict):
                raise ValidationError("承認証明の形式が不正です。")
            role, operator = claim.get("role"), claim.get("approver")
            if role not in expected or role in seen_roles or operator != expected[role]:
                raise ValidationError("承認証明の役割または承認者がCLIの指定と一致しません。")
            if operator in seen_operators or claim.get("proposal_id") != proposal_id or claim.get("snapshot_id") != snapshot_id:
                raise ValidationError("承認証明が現在の計画に対応していないか、承認者が重複しています。")
            if claim.get("action") != action or claim.get("decision") != "approve":
                raise ValidationError("承認証明の操作または決定が現在の計画と一致しません。")
            seen_roles.add(role)
            seen_operators.add(operator)
        if seen_roles != set(expected):
            raise ValidationError("primaryとsecondaryの承認証明がそろっていません。")

    def _record_rule_config(self):
        """A threshold change alters what is detected, so it is entered as evidence."""
        last = self.db.execute("SELECT * FROM audit WHERE action='rules.configured' ORDER BY seq DESC LIMIT 1").fetchone()
        previous_digest = self._audit_payload(last)["digest"] if last else None
        if previous_digest == self.config.digest:
            return
        self.record("rules.configured", {"digest": self.config.digest, "values": self.config.as_dict(),
                                         "rule_version": RULE_VERSION, "previous": previous_digest})

    def close(self):
        self.db.close()

    @contextmanager
    def transaction(self):
        with self.lock:
            if not self.verify_audit()["valid"]:
                raise IntegrityError("監査チェーンが不整合です。変更を拒否します。")
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    def _audit(self, action: str, payload: dict):
        last = self.db.execute("SELECT seq,mac FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        seq, previous = (last["seq"] + 1, last["mac"]) if last else (1, ZERO)
        at, body = iso(utcnow()), canonical(payload)
        stored_body = self._protect(body, self._audit_aad(seq, at, action, previous))
        mac = hmac.new(self.audit_key, canonical([seq, at, action, stored_body, previous]).encode(), hashlib.sha256).hexdigest()
        self.db.execute("INSERT INTO audit(seq,at,action,payload,prev,mac) VALUES (?,?,?,?,?,?)", (seq, at, action, stored_body, previous, mac))

    def record(self, action: str, payload: dict):
        with self.transaction():
            self._audit(action, payload)

    def verify_audit(self, anchor: dict | None = None) -> dict:
        with self.lock:
            rows = self.db.execute("SELECT * FROM audit ORDER BY seq").fetchall()
            previous, valid, seen = ZERO, True, {0: ZERO}
            for index, row in enumerate(rows, start=1):
                expected = hmac.new(self.audit_key, canonical([row["seq"], row["at"], row["action"], row["payload"], row["prev"]]).encode(), hashlib.sha256).hexdigest()
                payload_valid = True
                try:
                    self._audit_payload(row)
                except IntegrityError:
                    payload_valid = False
                if row["seq"] != index or row["prev"] != previous or not hmac.compare_digest(expected, row["mac"]) or not payload_valid:
                    valid = False
                previous = row["mac"]
                seen[index] = previous
            anchored = False
            if anchor is not None:
                count, tip = anchor.get("count"), anchor.get("tip")
                anchored = type(count) is int and isinstance(tip, str) and count in seen and hmac.compare_digest(seen[count], tip)
                valid = valid and anchored
            return {"valid": valid, "count": len(rows), "tip": previous, "anchor_checked": anchor is not None, "anchor_valid": anchored,
                    "limitation": "外部チェックポイントなしでは末尾削除を検出できません。ホストと鍵の同時侵害には耐えません。",
                    "limitation_en": "Without an external checkpoint, tail truncation cannot be detected. It does not withstand simultaneous compromise of the host and the key."}

    def ingest(self, raw: dict, source_mode: str = "imported", now=None, max_events: int = MAX_EVENTS,
               max_assets: int = MAX_ASSETS, verified_provenance: bool = False) -> str:
        """`verified_provenance` is only ever set by the importer in the same run
        that read the files; it can never be claimed by the submitted data."""
        document = normalize(raw, self.identity_key, source_mode=source_mode, now=now, max_events=max_events,
                             max_assets=max_assets, verified_provenance=verified_provenance)
        body = canonical(document)
        sid = "S-" + hashlib.sha256(body.encode()).hexdigest()[:24]
        mac = hmac.new(self.audit_key, body.encode(), hashlib.sha256).hexdigest()
        stored_body = self._protect(body, self._snapshot_aad(sid))
        with self.transaction():
            old = self.db.execute("SELECT body,mac FROM snapshots WHERE id=?", (sid,)).fetchone()
            if old:
                old_body = self._unprotect(old["body"], self._snapshot_aad(sid))
                if old_body != body or not hmac.compare_digest(old["mac"], mac):
                    raise IntegrityError("同一IDのスナップショットが不整合です。")
            self.db.execute("INSERT OR IGNORE INTO snapshots VALUES (?,?,?,?)", (sid, iso(utcnow()), stored_body, mac))
            self.db.execute("INSERT INTO current_snapshot VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET id=excluded.id", (sid,))
            self._audit("snapshot.ingested", {"snapshot_id": sid, "source_mode": source_mode, "events": len(document["events"]), "assets": len(document["assets"]), "deduplicated_snapshot": old is not None,
                                                 "provenance": document["provenance"], "rule_config_digest": self.config.digest})
        return sid

    def snapshot(self) -> tuple[str | None, dict | None]:
        with self.lock:
            row = self.db.execute("SELECT s.* FROM snapshots s JOIN current_snapshot c ON s.id=c.id WHERE c.singleton=1").fetchone()
            if row is None:
                return None, None
            body = self._unprotect(row["body"], self._snapshot_aad(row["id"]))
            expected = hmac.new(self.audit_key, body.encode(), hashlib.sha256).hexdigest()
            expected_id = "S-" + hashlib.sha256(body.encode()).hexdigest()[:24]
            if not hmac.compare_digest(expected, row["mac"]) or row["id"] != expected_id:
                raise IntegrityError("スナップショットの完全性検証に失敗しました。")
            try:
                document = json.loads(body)
            except (ValueError, TypeError, UnicodeError) as exc:
                raise IntegrityError("スナップショットの形式が不正です。") from exc
            if not isinstance(document, dict):
                raise IntegrityError("スナップショットの形式が不正です。")
            return row["id"], document

    @staticmethod
    def summarize(document: dict) -> dict:
        """What the UI needs. The event list is not part of the always-on payload:
        an imported snapshot can hold millions of events."""
        events = document["events"]
        return {"schema_version": document["schema_version"], "as_of": document["as_of"],
                "source_mode": document["source_mode"], "provenance": document["provenance"],
                "assets": document["assets"], "events_included": False,
                "event_counts": {"total": len(events),
                                 "login": sum(e["type"] == "login" for e in events),
                                 "file_access": sum(e["type"] == "file_access" for e in events)}}

    def export_document(self, max_events: int = MAX_EXPORT_EVENTS) -> dict:
        """The full dataset, for an explicit export only."""
        with self.lock:
            state = self.state()
            sid, document = self.snapshot()
            if sid != state["snapshot_id"]:
                raise ConflictError("書き出し中に入力が更新されました。やり直してください。")
            if document is not None:
                if len(document["events"]) > max_events:
                    raise ValidationError(f"イベントが{max_events:,}件を超えるため画面からは書き出せません。CLIを使用してください。")
                state["snapshot"] = {**self.summarize(document), "events": document["events"], "events_included": True}
            return state

    def state(self) -> dict:
        with self.lock:
            sid, doc = self.snapshot()
            audit = self.verify_audit()
            findings = analyze(doc, self.config) if doc else []
            proposals = []
            if sid:
                for row in self.db.execute("SELECT * FROM proposals WHERE snapshot_id=? ORDER BY created_at DESC", (sid,)).fetchall():
                    status = "expired" if row["status"] == "pending" and parse_time(row["expires_at"]) < utcnow() else row["status"]
                    proposals.append({"id": row["id"], "finding_id": row["finding_id"], "plan": self._proposal_plan(row), "created_at": row["created_at"], "expires_at": row["expires_at"], "status": status})
            records = [{"seq": r["seq"], "at": r["at"], "action": r["action"], "payload": self._audit_payload(r), "mac": r["mac"]} for r in self.db.execute("SELECT * FROM audit ORDER BY seq DESC LIMIT 100")]
            return {
                "version": "0.3.0",
                "rule_version": RULE_VERSION,
                "storage": {"encrypted_at_rest": self.encrypted,
                            "key_source": "external-secret" if self.encrypted else "local-file"},
                "rule_config": {"digest": self.config.digest, "values": self.config.as_dict(), "parameters": describe(self.config)},
                "snapshot_id": sid,
                "snapshot": self.summarize(doc) if doc else None,
                "findings": findings,
                "proposals": proposals,
                "audit": audit,
                "audit_records": records,
                "coverage": coverage(doc) if doc else {"live_connectors": 0, "expected_connectors": 3, "snapshot_only": True, "missing_sources": ["資産台帳", "認証ログ", "ファイル参照ログ"]},
                "mode": "local-prototype",
                "real_actions_enabled": False,
                "generated_at": iso(utcnow()),
            }

    def get_finding(self, sid: str, fid: str) -> dict:
        current, document = self.snapshot()
        if sid != current or document is None:
            raise ConflictError("入力データが更新されています。画面を再読み込みしてください。")
        f = next((f for f in analyze(document, self.config) if f["id"] == fid), None)
        if f is None:
            raise ValidationError("検知IDが見つかりません。")
        return f

    def propose(self, sid: str, fid: str) -> dict:
        with self.transaction():
            f = self.get_finding(sid, fid)
            now = utcnow()
            existing = self.db.execute("SELECT * FROM proposals WHERE snapshot_id=? AND finding_id=? AND status='pending' ORDER BY created_at DESC LIMIT 1", (sid, fid)).fetchone()
            if existing and parse_time(existing["expires_at"]) > now:
                return {"proposal_id": existing["id"], "plan": self._proposal_plan(existing), "expires_at": existing["expires_at"], "reused": True}
            plan = plan_for(f)
            pid, expires = "P-" + secrets.token_hex(12), iso(now + timedelta(minutes=5))
            stored_plan = self._protect(canonical(plan), self._proposal_aad(pid))
            self.db.execute("INSERT INTO proposals(id,snapshot_id,finding_id,body,created_at,expires_at,status) VALUES(?,?,?,?,?,?,?)",
                            (pid, sid, fid, stored_plan, iso(now), expires, "pending"))
            self._audit("plan.proposed", {"proposal_id": pid, "snapshot_id": sid, "finding_id": fid, "action": plan["action"], "execution_mode": "simulation_only"})
            return {"proposal_id": pid, "plan": plan, "expires_at": expires, "reused": False}

    def approve_and_simulate(self, proposal_id: str, expected_snapshot: str, confirmation: str, reason: str) -> dict:
        if confirmation != "SIMULATE ONLY":
            raise ValidationError("確認文字列が一致しません。")
        if not isinstance(reason, str) or not 10 <= len(reason.strip()) <= 500:
            raise ValidationError("承認理由は10〜500文字で入力してください。")
        with self.transaction():
            row = self.db.execute("SELECT * FROM proposals WHERE id=?", (proposal_id,)).fetchone()
            if row is None:
                raise ValidationError("計画が見つかりません。")
            if row["status"] != "pending":
                raise ConflictError("この計画はすでに処理済みです。")
            if row["snapshot_id"] != expected_snapshot or self.snapshot()[0] != expected_snapshot:
                raise ConflictError("計画作成後に入力が更新されました。再確認が必要です。")
            if parse_time(row["expires_at"]) <= utcnow():
                raise ConflictError("承認期限の5分を過ぎています。計画を作り直してください。")
            # Do not trust a mutable stored action: compare against the current policy.
            expected = plan_for(self.get_finding(expected_snapshot, row["finding_id"]))
            if self._unprotect(row["body"], self._proposal_aad(row["id"])) != canonical(expected):
                raise IntegrityError("計画と現行ポリシーの内容が一致しません。")
            reason_mac = hmac.new(self.audit_key, reason.strip().encode(), hashlib.sha256).hexdigest()
            self._audit("plan.approved", {"proposal_id": proposal_id, "operator": "local-owner", "reason_hmac": reason_mac, "reason_plaintext_saved": False})
            result = SimulationAdapter().simulate(expected)
            self.db.execute("UPDATE proposals SET status='simulated' WHERE id=?", (proposal_id,))
            self._audit("plan.simulated", {"proposal_id": proposal_id, "executed": False, "adapter": result["adapter"]})
            return result

    def approve_for_execution(self, proposal_id: str, expected_snapshot: str, confirmation: str,
                              secondary_confirmation: str, reason: str,
                              primary_operator: str, secondary_operator: str,
                              provider_target: str | None = None,
                              approval_assertions: list[dict] | None = None) -> dict:
        """Record two explicit approvals without contacting the responder.

        The responder remains a separate trust boundary.  Names are only used
        to prove that two distinct approval labels were supplied; production
        deployments must bind them to authenticated identities in the
        responder or an SSO/RBAC layer.
        """
        if confirmation != "EXECUTE REAL ACTION":
            raise ValidationError("実操作にはEXECUTE REAL ACTIONの確認が必要です。")
        if secondary_confirmation != "SECOND APPROVER CONFIRMED":
            raise ValidationError("別担当者の確認文字列が一致しません。")
        for label, value in (("承認者", primary_operator), ("第二承認者", secondary_operator)):
            if not isinstance(value, str) or not 1 <= len(value.strip()) <= 120 or any(ord(c) < 32 for c in value):
                raise ValidationError(f"{label}の識別子が不正です。")
        if primary_operator.strip() == secondary_operator.strip():
            raise ValidationError("実操作には異なる2名の承認者が必要です。")
        if not isinstance(reason, str) or not 10 <= len(reason.strip()) <= 500:
            raise ValidationError("承認理由は10〜500文字で入力してください。")
        self._validate_provider_target(provider_target)
        with self.transaction():
            row = self.db.execute("SELECT * FROM proposals WHERE id=?", (proposal_id,)).fetchone()
            if row is None:
                raise ValidationError("計画が見つかりません。")
            if row["status"] != "pending":
                raise ConflictError("この計画はすでに処理済みです。")
            if row["snapshot_id"] != expected_snapshot or self.snapshot()[0] != expected_snapshot:
                raise ConflictError("計画作成後に入力が更新されました。再確認が必要です。")
            if parse_time(row["expires_at"]) <= utcnow():
                raise ConflictError("承認期限の5分を過ぎています。計画を作り直してください。")
            expected = plan_for(self.get_finding(expected_snapshot, row["finding_id"]))
            self._validate_approval_assertions(approval_assertions, proposal_id, expected_snapshot,
                                               expected["action"], primary_operator, secondary_operator)
            if self._unprotect(row["body"], self._proposal_aad(row["id"])) != canonical(expected):
                raise IntegrityError("計画と現行ポリシーの内容が一致しません。")
            self._audit("plan.approved", {
                "proposal_id": proposal_id,
                "execution_mode": "real",
                "primary_operator_hmac": hmac.new(self.audit_key, primary_operator.strip().encode(), hashlib.sha256).hexdigest(),
                "secondary_operator_hmac": hmac.new(self.audit_key, secondary_operator.strip().encode(), hashlib.sha256).hexdigest(),
                "reason_hmac": hmac.new(self.audit_key, reason.strip().encode(), hashlib.sha256).hexdigest(),
                "provider_target_hmac": self._target_hmac(provider_target),
                "identity_attested": approval_assertions is not None,
                "reason_plaintext_saved": False,
            })
            self.db.execute("UPDATE proposals SET status='approved', approved_target_hmac=? WHERE id=?",
                            (self._target_hmac(provider_target), proposal_id))
            return {"proposal_id": proposal_id, "status": "approved", "execution_mode": "real"}

    def execute_approved(self, proposal_id: str, expected_snapshot: str,
                         responder: SignedWebhookResponder, provider_target: str) -> dict:
        """Execute exactly one approved plan and require verified provider state."""
        self._validate_provider_target(provider_target)
        with self.transaction():
            row = self.db.execute("SELECT * FROM proposals WHERE id=?", (proposal_id,)).fetchone()
            if row is None:
                raise ValidationError("計画が見つかりません。")
            if row["status"] != "approved":
                raise ConflictError("実行可能な承認済み計画がありません。")
            if row["snapshot_id"] != expected_snapshot or self.snapshot()[0] != expected_snapshot:
                raise ConflictError("承認後に入力が更新されました。実行を拒否します。")
            if parse_time(row["expires_at"]) <= utcnow():
                raise ConflictError("承認期限を過ぎています。新しい計画と承認が必要です。")
            approved_target = row["approved_target_hmac"]
            if not isinstance(approved_target, str) or not hmac.compare_digest(approved_target, self._target_hmac(provider_target)):
                raise ConflictError("承認時に確認した対象IDと実行対象が一致しません。再承認が必要です。")
            finding = self.get_finding(expected_snapshot, row["finding_id"])
            expected = plan_for(finding)
            if self._unprotect(row["body"], self._proposal_aad(row["id"])) != canonical(expected):
                raise IntegrityError("計画と現行ポリシーの内容が一致しません。")
            plan = {**expected, "execution_mode": "real", "automatic_execution": False}
            context = {"proposal_id": proposal_id, "snapshot_id": expected_snapshot,
                       "evidence_ids": finding.get("evidence_ids", []),
                       "provider_target": provider_target}
            self.db.execute("UPDATE proposals SET status='executing' WHERE id=?", (proposal_id,))
            self._audit("plan.execution_started", {"proposal_id": proposal_id, "adapter": responder.adapter_name})

        try:
            result = responder.execute(plan, context)
        except Exception as exc:
            with self.transaction():
                self.db.execute("UPDATE proposals SET status='failed' WHERE id=? AND status='executing'", (proposal_id,))
                self._audit("plan.failed", {"proposal_id": proposal_id, "error_type": type(exc).__name__})
            if isinstance(exc, ResponderError):
                raise
            raise ResponderError("実行先の処理に失敗しました。") from exc

        with self.transaction():
            if self.snapshot()[0] != expected_snapshot:
                self.db.execute("UPDATE proposals SET status='failed' WHERE id=? AND status='executing'", (proposal_id,))
                self._audit("plan.failed", {"proposal_id": proposal_id, "error_type": "stale_snapshot_after_response"})
                return {"status": "failed", "executed": False, "adapter": responder.adapter_name}
            safe_result = result if isinstance(result, dict) else {}
            final_status = "verified" if safe_result.get("status") == "verified" and safe_result.get("executed") is True else "failed"
            self.db.execute("UPDATE proposals SET status=? WHERE id=? AND status='executing'", (final_status, proposal_id))
            audit_result = {"proposal_id": proposal_id, "executed": final_status == "verified",
                            "adapter": responder.adapter_name}
            # Provider responses are outside this process's trust boundary.
            # Preserve only small, allowlisted post-action metadata in the audit.
            for key, limit in (("provider", 80), ("verification", 160)):
                value = safe_result.get(key)
                if isinstance(value, str) and 1 <= len(value) <= limit and not any(ord(c) < 32 for c in value):
                    audit_result[key] = value
            self._audit("plan.verified" if final_status == "verified" else "plan.failed", audit_result)
        if final_status != "verified":
            return {**safe_result, "status": "failed", "executed": False}
        return safe_result
