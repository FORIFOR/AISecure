from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import sys
from .schema import read_json, IMPORT_MAX_ASSETS, IMPORT_MAX_EVENTS, ValidationError
from .store import Store
from .demo import sample
from . import rules as rule_config


def _write(path: Path | None, text: str, label: str):
    if path is None:
        print(text, end="" if text.endswith("\n") else "\n")
        return
    path.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
    print(f"{label}: {path}", file=sys.stderr)


def _dump(value) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def _load_rules(path: Path | None):
    if path is None:
        return rule_config.DEFAULT
    return rule_config.from_mapping(read_json(path.read_bytes()))


def _storage_key(args) -> bytes | None:
    """Read an encrypted-store key only when the operator explicitly opts in."""
    if not getattr(args, "encrypted", False):
        return None
    name = args.master_key_env
    value = os.environ.get(name)
    if not value:
        raise ValueError(f"保管時暗号化の鍵を環境変数から指定してください: {name}")
    try:
        key = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("保管時暗号化の鍵は64文字の16進数で指定してください。") from exc
    if len(key) != 32:
        raise ValueError("保管時暗号化の鍵は64文字の16進数（32バイト）で指定してください。")
    return key


def _store(args, config):
    return Store(args.data_dir, config, master_key=_storage_key(args))


def _approval_assertions(args) -> list[dict] | None:
    paths = (args.approval_keys, args.primary_approval, args.secondary_approval)
    supplied = any(path is not None for path in paths)
    if not supplied and not args.require_attested_approvals:
        return None
    if not all(path is not None for path in paths):
        raise ValueError("署名付き承認には--approval-keys、--primary-approval、--secondary-approvalの3つが必要です。")
    from .approvals import verify_pair
    return verify_pair(args.primary_approval, args.secondary_approval, args.approval_keys,
                       args.proposal_id, args.snapshot_id)


def _add_approval_options(parser):
    parser.add_argument("--approval-keys", type=Path, default=None,
                        help="External Ed25519 approver public-key registry")
    parser.add_argument("--primary-approval", type=Path, default=None,
                        help="Signed approval document for the primary approver")
    parser.add_argument("--secondary-approval", type=Path, default=None,
                        help="Signed approval document for the secondary approver")
    parser.add_argument("--require-attested-approvals", action="store_true",
                        help="Refuse real execution unless both signed approvals are supplied")


def _sources(pairs: list[str]):
    from .connectors import load_profile
    out = []
    for pair in pairs:
        if "=" not in pair:
            raise ValidationError(f"--source は プロファイル=ファイル の形式で指定してください: {pair}")
        name, _, target = pair.partition("=")
        out.append((Path(target).expanduser(), load_profile(name)))
    return out


MAX_SCENARIO_BYTES = 512 * 1024 * 1024


def _scenarios(paths: list[Path]) -> list[dict]:
    """Scenario files are much larger than an API payload, but still parsed strictly."""
    return [read_json(path.read_bytes(), MAX_SCENARIO_BYTES) for path in paths]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aisecure", description="AI Secure — local security analysis and response control")
    parser.add_argument("--data-dir", default=str(Path.home() / ".ai-secure-demo"), help="Local state; do not place in a shared or cloud-synced folder")
    parser.add_argument("--rules", type=Path, default=None, help="Detection threshold overrides (JSON). Recorded in the audit chain.")
    parser.add_argument("--encrypted", action="store_true", help="Encrypt snapshot and audit fields using the external key below")
    parser.add_argument("--master-key-env", default="AISECURE_MASTER_KEY", help="Environment variable holding a 64-hex-character store key")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="Start local development UI")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--demo", action="store_true", help="Load synthetic metadata only when the database is empty")
    serve.add_argument("--ollama-model", default=None, help="Optional already-installed local model; cloud models rejected")

    analyze = sub.add_parser("analyze", help="Import a normalized JSON snapshot and print findings")
    analyze.add_argument("input", type=Path)

    sub.add_parser("sample", help="Write synthetic input JSON to stdout; does not open a database")
    verify = sub.add_parser("verify-audit", help="Verify local HMAC audit chain")
    verify.add_argument("--anchor", type=Path, help="Independently retained {count,tip} checkpoint")
    sub.add_parser("checkpoint", help="Print audit checkpoint for independent retention")
    publish_checkpoint = sub.add_parser("publish-checkpoint", help="Publish an audit checkpoint to an independent HTTPS sink")
    publish_checkpoint.add_argument("--url", required=True, help="HTTPS checkpoint sink URL; HTTP is allowed only for localhost tests")
    publish_checkpoint.add_argument("--secret-env", default="AISECURE_AUDIT_SINK_SECRET", help="Environment variable holding the separate sink signing secret")

    sub.add_parser("profiles", help="List built-in read-only log mapping profiles")
    importer = sub.add_parser("import", help="Read real log files into a snapshot (read-only; nothing is written back)")
    importer.add_argument("--source", action="append", required=True, metavar="PROFILE=PATH",
                          help="Repeatable. PROFILE is a built-in name or a path to a mapping profile.")
    importer.add_argument("--out", type=Path, help="Write the snapshot JSON here instead of stdout")
    importer.add_argument("--quality", type=Path, help="Write the import quality report here")
    importer.add_argument("--unknown-assets", choices=["record", "skip"], default="record",
                          help="record: keep assets seen only in logs as unknown (default). skip: drop their events.")
    importer.add_argument("--max-rows", type=int, default=None, help="Row limit per source")
    importer.add_argument("--ingest", action="store_true", help="Also load the result into the local database")

    watch = sub.add_parser("watch", help="Poll read-only log exports and ingest changed snapshots")
    watch.add_argument("--source", action="append", required=True, metavar="PROFILE=PATH",
                       help="Repeatable. Uses the same read-only mapping profiles as import.")
    watch.add_argument("--interval", type=float, default=30.0, help="Polling interval in seconds (1..3600)")
    watch.add_argument("--once", action="store_true", help="Poll once and exit")
    watch.add_argument("--unknown-assets", choices=["record", "skip"], default="record")
    watch.add_argument("--max-rows", type=int, default=None)

    watch_okta = sub.add_parser("watch-okta", help="Poll Okta System Log and ingest an authenticated login window")
    watch_okta.add_argument("--asset-source", required=True, metavar="PROFILE=PATH",
                            help="Asset inventory source; the profile must have record=asset")
    watch_okta.add_argument("--source", action="append", default=[], metavar="PROFILE=PATH",
                            help="Optional local file-access source(s) to combine with Okta logins")
    watch_okta.add_argument("--okta-domain", required=True, help="Okta org URL, for example https://example.okta.com")
    watch_okta.add_argument("--token-env", default="OKTA_ACCESS_TOKEN", help="Environment variable holding the scoped Okta token")
    watch_okta.add_argument("--auth-scheme", choices=["Bearer", "SSWS"], default="Bearer")
    watch_okta.add_argument("--lookback", type=int, default=1800, help="Overlapping System Log window in seconds (60..604800)")
    watch_okta.add_argument("--interval", type=float, default=30.0, help="Polling interval in seconds (1..3600)")
    watch_okta.add_argument("--once", action="store_true", help="Poll once and exit")
    watch_okta.add_argument("--unknown-assets", choices=["record", "skip"], default="record")
    watch_okta.add_argument("--max-rows", type=int, default=None)

    baseline = sub.add_parser("baseline", help="Generate labeled synthetic normal traffic for tuning")
    baseline.add_argument("--name", default="baseline")
    baseline.add_argument("--seed", type=int, default=1)
    baseline.add_argument("--days", type=int, default=3)
    baseline.add_argument("--users", type=int, default=24)
    baseline.add_argument("--attack", action="store_true", help="Include one labeled incident")
    baseline.add_argument("--unpatched-gateway", action="store_true", help="Leave the gateway unpatched without an incident")
    baseline.add_argument("--start", help="Scenario start, ISO 8601 with a timezone (default 2026-09-01T00:00:00+09:00)")
    baseline.add_argument("--out", type=Path)

    evaluate = sub.add_parser("evaluate", help="Measure detections and false positives on labeled scenarios")
    evaluate.add_argument("scenarios", nargs="+", type=Path)
    evaluate.add_argument("--sweep", action="store_true", help="Also grid-search the bulk-access threshold and window")
    evaluate.add_argument("--format", choices=["markdown", "json"], default="markdown")
    evaluate.add_argument("--out", type=Path)
    evaluate.add_argument("--save-rules", type=Path, help="Write the recommended thresholds as a rules file (--sweep only)")

    execute = sub.add_parser("execute", help="Deliver an explicitly double-approved response through a signed webhook")
    execute.add_argument("--proposal-id", required=True, help="Pending proposal ID from the local UI or state export")
    execute.add_argument("--snapshot-id", required=True, help="Snapshot ID the approvers reviewed")
    execute.add_argument("--provider-target", required=True, help="Target ID verified in the provider console; never inferred from the pseudonymized finding")
    execute.add_argument("--webhook-url", required=True, help="HTTPS responder URL; HTTP is allowed only for localhost tests")
    execute.add_argument("--secret-env", default="AISECURE_WEBHOOK_SECRET", help="Environment variable holding the 32+ byte signing secret")
    execute.add_argument("--allow-action", action="append", required=True, choices=["revoke_session", "restrict_remote_access", "review_evidence"],
                         help="Repeat for each action the responder is allowed to receive")
    execute.add_argument("--primary-operator", required=True, help="First approver label")
    execute.add_argument("--secondary-operator", required=True, help="Second, distinct approver label")
    execute.add_argument("--reason", required=True, help="Why this real action is approved")
    execute.add_argument("--confirm", required=True, help="Type EXECUTE REAL ACTION")
    execute.add_argument("--second-confirm", required=True, help="Type SECOND APPROVER CONFIRMED")
    execute.add_argument("--emergency-stop-file", type=Path, default=None, help="Presence of this local file blocks the real request")
    _add_approval_options(execute)

    execute_okta = sub.add_parser("execute-okta", help="Clear an explicitly double-approved Okta user's sessions and verify the System Log")
    execute_okta.add_argument("--proposal-id", required=True)
    execute_okta.add_argument("--snapshot-id", required=True)
    execute_okta.add_argument("--provider-target", required=True, help="Verified Okta user ID (00u...); never use the pseudonymized finding actor")
    execute_okta.add_argument("--okta-domain", required=True, help="Okta org URL, for example https://example.okta.com")
    execute_okta.add_argument("--token-env", default="OKTA_ACCESS_TOKEN", help="Environment variable holding the scoped Okta token")
    execute_okta.add_argument("--auth-scheme", choices=["Bearer", "SSWS"], default="Bearer")
    execute_okta.add_argument("--verification-timeout", type=float, default=5.0)
    execute_okta.add_argument("--primary-operator", required=True)
    execute_okta.add_argument("--secondary-operator", required=True)
    execute_okta.add_argument("--reason", required=True)
    execute_okta.add_argument("--confirm", required=True, help="Type EXECUTE REAL ACTION")
    execute_okta.add_argument("--second-confirm", required=True, help="Type SECOND APPROVER CONFIRMED")
    execute_okta.add_argument("--emergency-stop-file", type=Path, default=None, help="Presence of this local file blocks the Okta request")
    _add_approval_options(execute_okta)
    return parser


def _run_import(args, config):
    from .connectors import build_snapshot, MAX_ROWS
    sources = _sources(args.source)
    snapshot, quality = build_snapshot(sources, unknown_assets=args.unknown_assets,
                                       max_rows=args.max_rows or MAX_ROWS)
    if args.quality:
        args.quality.write_text(_dump(quality), encoding="utf-8")
    for warning in quality["warnings"]:
        print(f"警告: {warning}", file=sys.stderr)
    totals = quality["totals"]
    print(f"読み込み {totals['rows_read']:,} 行 / 取り込み {totals['rows_imported']:,} 行 / "
          f"読み飛ばし {totals['rows_skipped']:,} 行 / 資産 {totals['assets']} / イベント {totals['events']:,}", file=sys.stderr)
    if args.ingest:
        store = _store(args, config)
        try:
            # Only this path read and hashed the files itself.
            sid = store.ingest(snapshot, "imported", max_events=IMPORT_MAX_EVENTS,
                               max_assets=IMPORT_MAX_ASSETS, verified_provenance=True)
        finally:
            store.close()
        print(f"取り込み済みスナップショット: {sid}", file=sys.stderr)
    # The intermediate snapshot still holds raw identifiers: pseudonymization happens
    # when the data is stored, not when it is read.
    print("警告: 書き出すスナップショットには仮名化前のユーザー名・セッションID・ファイルパスが含まれます。"
          "保存先と共有範囲を確認してください。", file=sys.stderr)
    _write(args.out, _dump(snapshot), "スナップショット")


def _run_evaluate(args, config):
    from .baseline import load_scenario
    from .evaluate import evaluate as run_evaluate, markdown, prepare, sweep as run_sweep
    scenarios = [load_scenario(raw) for raw in _scenarios(args.scenarios)]
    prepared = [prepare(s) for s in scenarios]
    report = run_evaluate(prepared, config)
    sweep_report = run_sweep(scenarios, config) if args.sweep else None
    if args.save_rules:
        if not sweep_report or not sweep_report["recommended"]:
            raise ValidationError("--save-rules には --sweep と、検知漏れのない推奨設定が必要です。")
        recommended = config.replace(distinct_file_threshold=sweep_report["recommended"]["distinct_file_threshold"],
                                     window_seconds=sweep_report["recommended"]["window_seconds"])
        args.save_rules.write_text(_dump(recommended.as_dict()), encoding="utf-8")
        print(f"推奨設定: {args.save_rules}", file=sys.stderr)
    text = markdown(report, sweep_report) if args.format == "markdown" else _dump({"evaluation": report, "sweep": sweep_report})
    _write(args.out, text, "レポート")


def main():
    args = build_parser().parse_args()
    if args.command == "sample":
        _write(None, _dump(sample()), "")
        return
    if os.name != "nt":
        os.umask(0o077)
    config = _load_rules(args.rules)
    if args.command == "profiles":
        from .connectors import builtin_profiles, load_profile
        for name in builtin_profiles():
            spec = load_profile(name)
            print(f"{name}\n  形式: {spec['format']} / 種別: {spec['record']}\n  {spec['description']}\n")
        return
    if args.command == "import":
        _run_import(args, config)
        return
    if args.command == "watch":
        from .monitor import FileMonitor
        monitor = FileMonitor(_store(args, config), _sources(args.source),
                              unknown_assets=args.unknown_assets,
                              max_rows=args.max_rows or 2_000_000,
                              interval=args.interval)
        try:
            result = monitor.poll_once()
            print(json.dumps(result.as_dict(), ensure_ascii=False, indent=2))
            if not args.once:
                print("監視中です。停止するにはCtrl+Cを押してください。", file=sys.stderr)
                monitor.run()
        except KeyboardInterrupt:
            pass
        finally:
            monitor.store.close()
        return
    if args.command == "watch-okta":
        from .monitor import OktaSystemLogMonitor
        from .providers.okta import OktaConfig, OktaClient, OktaSystemLogCollector
        token = os.environ.get(args.token_env)
        if not token:
            raise ValueError(f"Oktaトークンの環境変数が未設定です: {args.token_env}")
        asset_source = _sources([args.asset_source])[0]
        collector = OktaSystemLogCollector(
            OktaClient(OktaConfig(base_url=args.okta_domain, token=token, auth_scheme=args.auth_scheme)),
            asset_source, _sources(args.source), lookback_seconds=args.lookback,
            max_rows=args.max_rows or 2_000_000, unknown_assets=args.unknown_assets,
        )
        store = _store(args, config)
        monitor = OktaSystemLogMonitor(store, collector, interval=args.interval)
        try:
            result = monitor.poll_once()
            print(json.dumps(result.as_dict(), ensure_ascii=False, indent=2))
            if not args.once:
                print("Okta System Logを監視中です。停止するにはCtrl+Cを押してください。", file=sys.stderr)
                monitor.run()
        except KeyboardInterrupt:
            pass
        finally:
            store.close()
        return
    if args.command == "baseline":
        from .baseline import scenario
        from .schema import parse_time, utcnow
        data = scenario(args.name, seed=args.seed, days=args.days, users=args.users, attack=args.attack,
                        unpatched_gateway=args.unpatched_gateway,
                        start=parse_time(args.start) if args.start else None)
        if parse_time(data["snapshot"]["as_of"]) > utcnow():
            print("警告: このシナリオの終了時刻は未来です。評価（evaluate）には使えますが、"
                  "analyze や import --ingest では拒否されます。--start で開始日を指定してください。", file=sys.stderr)
        _write(args.out, _dump(data), "シナリオ")
        return
    if args.command == "evaluate":
        _run_evaluate(args, config)
        return

    store = _store(args, config)
    try:
        if args.command == "serve":
            from .server import LocalServer
            if not 0 <= args.port <= 65535:
                raise ValueError("port must be 0..65535")
            if args.demo and store.snapshot()[0] is None:
                store.ingest(sample(), "demo")
            server = LocalServer(store, args.port, args.ollama_model)
            print("AI Secure v0.3.0 — LOCAL INTEGRATION / 防御側への実操作は明示承認と署名付きレスポンダー経由", flush=True)
            print("表示はスナップショット解析です。継続監視は watch / watch-okta、実操作は execute / execute-okta を使用します。", flush=True)
            print(f"検知設定: {config.digest}" + ("（既定値）" if args.rules is None else f"（{args.rules}）"), flush=True)
            print(f"Open: {server.origin}/#token={server.token}", flush=True)
            print(f"API token: {server.token}", flush=True)
            if args.ollama_model:
                print("Ollamaは任意です。ローカルモデルと外向き通信禁止を別途確認してください。", flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
        elif args.command == "analyze":
            # The CLI reads files the operator already has; the HTTP boundary keeps
            # its much smaller limits.
            store.ingest(read_json(args.input.read_bytes(), MAX_SCENARIO_BYTES),
                         max_events=IMPORT_MAX_EVENTS, max_assets=IMPORT_MAX_ASSETS)
            state = store.state()
            _write(None, _dump({k: state[k] for k in ("snapshot_id", "rule_config", "findings", "coverage", "audit")}), "")
        elif args.command == "checkpoint":
            audit = store.verify_audit()
            if not audit["valid"]:
                raise ValueError("監査チェーンが不整合です。")
            print(json.dumps({"count": audit["count"], "tip": audit["tip"]}))
        elif args.command == "publish-checkpoint":
            from .audit_sink import AuditSinkConfig, ExternalAuditSink
            secret = os.environ.get(args.secret_env)
            if not secret:
                raise ValueError(f"監査チェックポイント署名鍵の環境変数が未設定です: {args.secret_env}")
            secret_bytes = secret.encode("utf-8")
            if len(secret_bytes) < 32:
                raise ValueError("監査チェックポイント署名鍵は32バイト以上が必要です。")
            audit = store.verify_audit()
            if not audit["valid"]:
                raise ValueError("監査チェーンが不整合です。")
            checkpoint = {"count": audit["count"], "tip": audit["tip"]}
            result = ExternalAuditSink(AuditSinkConfig(args.url, secret_bytes)).publish(checkpoint)
            store.record("audit.checkpoint_published", {"count": checkpoint["count"], "tip": checkpoint["tip"], "adapter": result["adapter"]})
            result["current_checkpoint"] = {key: store.verify_audit()[key] for key in ("count", "tip")}
            _write(None, _dump(result), "")
        elif args.command == "verify-audit":
            anchor = read_json(args.anchor.read_bytes()) if args.anchor else None
            result = store.verify_audit(anchor)
            _write(None, _dump(result), "")
            if not result["valid"]:
                sys.exit(2)
        elif args.command == "execute":
            from .responder import ResponderConfig, SignedWebhookResponder
            secret_text = os.environ.get(args.secret_env)
            if not secret_text:
                raise ValueError(f"署名鍵の環境変数が未設定です: {args.secret_env}")
            responder = SignedWebhookResponder(ResponderConfig(
                url=args.webhook_url,
                secret=secret_text.encode("utf-8"),
                allowed_actions=frozenset(args.allow_action),
                emergency_stop_file=args.emergency_stop_file,
            ))
            approval_assertions = _approval_assertions(args)
            store.approve_for_execution(
                args.proposal_id, args.snapshot_id, args.confirm, args.second_confirm,
                args.reason, args.primary_operator, args.secondary_operator, args.provider_target,
                approval_assertions,
            )
            result = store.execute_approved(args.proposal_id, args.snapshot_id, responder, args.provider_target)
            _write(None, _dump(result), "")
        elif args.command == "execute-okta":
            from .providers.okta import OktaConfig, OktaSessionResponder
            token = os.environ.get(args.token_env)
            if not token:
                raise ValueError(f"Oktaトークンの環境変数が未設定です: {args.token_env}")
            responder = OktaSessionResponder(OktaConfig(
                base_url=args.okta_domain, token=token, auth_scheme=args.auth_scheme,
                verification_timeout=args.verification_timeout,
                emergency_stop_file=args.emergency_stop_file,
            ))
            approval_assertions = _approval_assertions(args)
            store.approve_for_execution(
                args.proposal_id, args.snapshot_id, args.confirm, args.second_confirm,
                args.reason, args.primary_operator, args.secondary_operator, args.provider_target,
                approval_assertions,
            )
            result = store.execute_approved(args.proposal_id, args.snapshot_id, responder, args.provider_target)
            _write(None, _dump(result), "")
    finally:
        store.close()


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
