"""Text-action preflight for trusted application adapters, NOT a host-wide DLP.

This module does not send requests or monitor browsers/VPNs. guarded_call refuses
non-allowed actions before invoking a caller-supplied transport. The adapter must
own policy, labels, tool registry and transport; model-generated labels are not
trusted. See docs/PREVENTION_BOUNDARY.ja.md for required integration and gaps.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import ipaddress
import json
from pathlib import Path
import re
import sys
import unicodedata
from typing import Callable, TypeVar
from urllib.parse import urlsplit

MAX_TEXT_BYTES = 262144
MAX_INPUT_BYTES = 2 * 1024 * 1024
CLASSES = frozenset({"public", "internal", "confidential", "restricted", "unknown"})
READ_ACTIONS = frozenset({"ai.prompt", "storage.upload", "agent.read"})
REVIEW_ACTIONS = frozenset({"agent.execute", "agent.delete", "agent.share", "agent.send"})
ID = re.compile(r"EV-[0-9]{1,12}\Z")
TOOL = re.compile(r"[a-z][a-z0-9_.-]{0,79}\Z")
SECRET = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----|"
    r"\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|"
    r"(?i:\b(?:api[_-]?key|password|secret|access[_-]?token)\s*[:=]\s*[\"']?[^\s\"']{8,})"
)
PERSONAL = re.compile(
    r"(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@"
    r"[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,10}|"
    r"(?<!\d)0[789]0[- ]?\d{4}[- ]?\d{4}(?!\d)"
)
MESSAGES = {
    "PG-001": "登録されていない送信先・操作・ツールです。実行を拒否します。",
    "PG-002": "機密または持出禁止の分類です。この外部送信経路では実行を拒否します。",
    "PG-003": "秘密鍵・認証情報に似た文字列を検出しました。値を表示せず実行を拒否します。",
    "PG-004": "データ分類が未確認です。安全と判断せず、実行を保留します。",
    "PG-005": "実行・削除・共有・送信の操作には別の認証済み承認経路が必要です。",
    "PG-006": "メールアドレスまたは携帯電話番号に似た文字列があります。実行を保留します。",
    "PG-007": "送信先に対して許可されていないデータ分類です。実行を拒否します。",
}


class InputError(ValueError):
    """Intentionally does not include input values or secrets."""


def endpoint(value: str) -> str:
    if type(value) is not str or not 1 <= len(value) <= 2048:
        raise InputError("送信先の形式が不正です。")
    if (not value.startswith("https://") or not value.isascii()
            or any(c.isspace() or ord(c) < 33 or ord(c) == 127 for c in value)
            or any(c in value for c in "@?#%\\")):
        raise InputError("送信先は認証情報・クエリ等を含まない固定HTTPS URLにしてください。")
    try:
        u = urlsplit(value)
        host = u.hostname or ""
        if not host or u.port not in (None, 443) or u.username or u.password:
            raise ValueError
        if len(host) > 253 or "." not in host or host.endswith("."):
            raise ValueError
        if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in host.split(".")):
            raise ValueError
        if any(p in (".", "..") for p in u.path.split("/")):
            raise ValueError
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError
    except ValueError:
        raise InputError("送信先の形式が不正です。") from None
    return value  # Exact URL equality; never suffix/substring matching.


@dataclass(frozen=True)
class Request:
    event_id: str
    action: str
    destination: str
    text: str
    data_class: str = "unknown"
    tool: str | None = None

    def __post_init__(self):
        if type(self.event_id) is not str or not ID.fullmatch(self.event_id):
            raise InputError("証跡IDの形式が不正です。")
        if type(self.action) is not str or self.action not in READ_ACTIONS | REVIEW_ACTIONS:
            raise InputError("未対応の操作です。")
        endpoint(self.destination)
        if type(self.text) is not str:
            raise InputError("本文は対応するテキスト形式にしてください。")
        try:
            size = len(self.text.encode("utf-8"))
        except UnicodeError:
            raise InputError("本文の文字コードが不正です。") from None
        if size > MAX_TEXT_BYTES:
            raise InputError("本文が検査上限を超えています。")
        if type(self.data_class) is not str or self.data_class not in CLASSES:
            raise InputError("データ分類が不正です。")
        if self.tool is not None and (type(self.tool) is not str or not TOOL.fullmatch(self.tool)):
            raise InputError("ツール名の形式が不正です。")
        if self.action.startswith("agent.") != (self.tool is not None):
            raise InputError("操作とツール指定の組み合わせが不正です。")


@dataclass(frozen=True)
class Grant:
    action: str
    destination: str
    data_classes: tuple[str, ...]
    tool: str | None = None

    def __post_init__(self):
        if type(self.action) is not str or self.action not in READ_ACTIONS:
            raise InputError("このガードでは高影響操作の許可を作成できません。")
        endpoint(self.destination)
        if (type(self.data_classes) is not tuple or not self.data_classes
                or any(type(c) is not str or c not in {"public", "internal"} for c in self.data_classes)):
            raise InputError("許可できる分類はpublicまたはinternalです。")
        Request("EV-0", self.action, self.destination, "", "public", self.tool)


@dataclass(frozen=True)
class Policy:
    grants: tuple[Grant, ...] = ()

    def __post_init__(self):
        if type(self.grants) is not tuple or len(self.grants) > 100 or any(type(g) is not Grant for g in self.grants):
            raise InputError("許可設定の形式が不正です。")
        keys = [(g.action, g.destination, g.tool) for g in self.grants]
        if len(keys) != len(set(keys)):
            raise InputError("重複する許可設定は使用できません。")


@dataclass(frozen=True)
class Decision:
    event_id: str
    decision: str
    rule_ids: tuple[str, ...]

    def report(self) -> dict:
        return {
            "event_id": self.event_id, "decision": self.decision,
            "rule_ids": list(self.rule_ids),
            "reasons": [MESSAGES[r] for r in self.rule_ids] or ["登録ポリシーの検査に一致しました。安全性の保証ではありません。"],
            "llm_used": False, "execution_state": "not_executed",
            "coverage": "submitted_text_action_only",
        }

    def finding(self) -> dict:
        """Metadata-only input for existing Explainer; no payload or destination."""
        return {"rule": "PREFLIGHT", "priority": "P1" if self.decision == "block" else "P2",
                "title": "送信・操作の事前検査", "reasons": self.report()["reasons"],
                "evidence_ids": [self.event_id]}


class GuardDenied(PermissionError):
    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__("送信・操作を実行しませんでした。")


def evaluate(request: Request, policy: Policy) -> Decision:
    if type(request) is not Request or type(policy) is not Policy:
        raise InputError("検査入力の型が不正です。")
    rules, blocked = [], False
    if request.action in REVIEW_ACTIONS:
        rules.append("PG-005")
    else:
        grant = next((g for g in policy.grants if
                      (g.action, g.destination, g.tool) == (request.action, request.destination, request.tool)), None)
        if grant is None:
            rules.append("PG-001")
            blocked = True
        elif request.data_class in {"public", "internal"} and request.data_class not in grant.data_classes:
            rules.append("PG-007")
            blocked = True
    if request.data_class in {"confidential", "restricted"}:
        rules.append("PG-002")
        blocked = True
    elif request.data_class == "unknown":
        rules.append("PG-004")
    # Small, explicit heuristics; not a general PII/prompt-injection classifier.
    normalized = unicodedata.normalize("NFKC", request.text)
    if SECRET.search(normalized):
        rules.append("PG-003")
        blocked = True
    if PERSONAL.search(normalized):
        rules.append("PG-006")
    return Decision(request.event_id, "block" if blocked else "review" if rules else "allow", tuple(rules))


T = TypeVar("T")


def guarded_call(request: Request, policy: Policy, transport: Callable[[Request], T]) -> T:
    """Only a trusted adapter may call this, with its fixed, no-redirect transport.

    An allowed result does not verify delivery, containment, or absence of leaks.
    No approval boolean can override a block/review; use a separate approved path.
    """
    decision = evaluate(request, policy)
    if decision.decision != "allow":
        raise GuardDenied(decision)
    return transport(request)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("重複するJSONキーは使用できません。")
        result[key] = value
    return result


def decode(raw: bytes):
    if len(raw) > MAX_INPUT_BYTES:
        raise InputError("入力が上限を超えています。")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except (ValueError, UnicodeError, RecursionError):
        raise InputError("入力JSONが不正です。") from None


def parse_request(value: dict) -> Request:
    allowed = {"event_id", "action", "destination", "text", "data_class", "tool"}
    if type(value) is not dict or not set(value) <= allowed:
        raise InputError("未対応の入力項目があります。")
    try:
        return Request(**value)
    except TypeError:
        raise InputError("必須項目が不足しています。") from None


def parse_policy(value: dict) -> Policy:
    if type(value) is not dict or set(value) != {"grants"} or type(value["grants"]) is not list:
        raise InputError("許可設定の形式が不正です。")
    grants = []
    for g in value["grants"]:
        if (type(g) is not dict or not {"action", "destination", "data_classes"} <= set(g)
                or not set(g) <= {"action", "destination", "data_classes", "tool"}
                or type(g["data_classes"]) is not list):
            raise InputError("許可項目の形式が不正です。")
        grants.append(Grant(**{**g, "data_classes": tuple(g["data_classes"])}))
    return Policy(tuple(grants))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="提出されたテキスト操作の検査。通信・端末監視は行いません。")
    parser.add_argument("--policy", type=Path, help="管理者が保護する許可設定。省略時は許可なし。")
    parser.add_argument("--history", action="store_true", help="提出した操作履歴のJSON配列を検査（最大1000件）。")
    args = parser.parse_args(argv)
    try:
        policy = Policy()
        if args.policy:
            with args.policy.open("rb") as file:
                policy = parse_policy(decode(file.read(MAX_INPUT_BYTES + 1)))
        value = decode(sys.stdin.buffer.read(MAX_INPUT_BYTES + 1))
        if args.history and (type(value) is not list or len(value) > 1000):
            raise InputError("履歴は1000件以下のJSON配列にしてください。")
        requests = [parse_request(v) for v in value] if args.history else [parse_request(value)]
        if len({r.event_id for r in requests}) != len(requests):
            raise InputError("履歴に重複する証跡IDがあります。")
        reports = [evaluate(r, policy).report() for r in requests]
        if args.history:
            for report in reports:
                report["execution_state"] = "historical_execution_unknown"
            output = {"reports": reports, "note": "提出された履歴のみの再検査です。実送信・漏えいの有無は証明しません。"}
        else:
            output = reports[0]
        print(json.dumps(output, ensure_ascii=False))
        return 2 if any(r["decision"] != "allow" for r in reports) else 0
    except (InputError, OSError):
        print(json.dumps({"error": "入力または設定を確認できないため実行不可です。", "execution_state": "not_executed"}, ensure_ascii=False))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
