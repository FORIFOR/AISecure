from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import sys
from .schema import read_json
from .store import Store
from .demo import sample


def main():
    parser = argparse.ArgumentParser(description="AI Secure — loopback-only security analysis prototype")
    parser.add_argument("--data-dir", default=str(Path.home() / ".ai-secure-demo"), help="Local state; do not place in a shared or cloud-synced folder")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="Start local development UI")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--demo", action="store_true", help="Load synthetic metadata only when the database is empty")
    serve.add_argument("--ollama-model", default=None, help="Optional already-installed local model; cloud models rejected")
    analyze = sub.add_parser("analyze", help="Import a normalized JSON snapshot and print findings")
    analyze.add_argument("input", type=Path)
    demo = sub.add_parser("sample", help="Write synthetic input JSON to stdout; does not open a database")
    verify = sub.add_parser("verify-audit", help="Verify local HMAC audit chain")
    verify.add_argument("--anchor", type=Path, help="Independently retained {count,tip} checkpoint")
    sub.add_parser("checkpoint", help="Print audit checkpoint for independent retention")
    args = parser.parse_args()
    if args.command == "sample":
        print(json.dumps(sample(), ensure_ascii=False, indent=2))
        return
    if os.name != "nt":
        os.umask(0o077)
    store = Store(args.data_dir)
    try:
        if args.command == "serve":
            from .server import LocalServer
            if not 0 <= args.port <= 65535:
                raise ValueError("port must be 0..65535")
            if args.demo and store.snapshot()[0] is None:
                store.ingest(sample(), "demo")
            server = LocalServer(store, args.port, args.ollama_model)
            print("AI Secure v0.1 — LOCAL PROTOTYPE / 実環境への対応操作は無効", flush=True)
            print("表示はスナップショット解析です。常時監視・VPN保護は行いません。", flush=True)
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
            with args.input.open("rb") as f:
                raw = f.read(2 * 1024 * 1024 + 1)
            store.ingest(read_json(raw))
            state = store.state()
            print(json.dumps({k: state[k] for k in ("snapshot_id", "findings", "coverage", "audit")}, ensure_ascii=False, indent=2))
        elif args.command == "checkpoint":
            audit = store.verify_audit()
            if not audit["valid"]:
                raise ValueError("監査チェーンが不整合です。")
            print(json.dumps({"count": audit["count"], "tip": audit["tip"]}))
        elif args.command == "verify-audit":
            anchor = read_json(args.anchor.read_bytes()) if args.anchor else None
            result = store.verify_audit(anchor)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            if not result["valid"]:
                sys.exit(2)
    finally:
        store.close()


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
