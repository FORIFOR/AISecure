"""Measure what a detection threshold costs on normal traffic.

A finding counts as a true positive only when at least one of its evidence IDs
belongs to the labeled incident. Everything else a behavioral rule produces is
counted as a false positive — an analyst burst, a backup job, or a migration day
that would land on someone's queue.

Asset hygiene rules (AS-001, AS-005) are reported as volume, not as precision:
"this asset is unpatched" or "this inventory row is unknown" is true whenever the
inventory says so, and judging it against an incident label would be meaningless.
"""
from __future__ import annotations
from collections import Counter
from datetime import timedelta
import hashlib
import itertools

from .baseline import BEHAVIORAL_RULES, HYGIENE_RULES, load_scenario
from .engine import analyze, RULE_VERSION
from .rules import RuleConfig, DEFAULT as DEFAULT_RULES
from .schema import normalize, parse_time, iso, utcnow, IMPORT_MAX_ASSETS, IMPORT_MAX_EVENTS, ValidationError

# Evaluation runs offline on synthetic or exported data and persists nothing, so
# this key is a fixed domain separator, not a secret.
EVAL_KEY = hashlib.sha256(b"ai-secure/evaluation-only/v1").digest()
SWEEP_THRESHOLDS = (60, 100, 150, 200, 300, 500, 800)
SWEEP_WINDOWS = (120, 300, 600)


def prepare(scenario: dict) -> dict:
    """Normalize a scenario snapshot once so a sweep does not re-validate it per cell."""
    scenario = load_scenario(scenario)
    snapshot = scenario["snapshot"]
    return {**scenario, "normalized": normalize(snapshot, EVAL_KEY, source_mode="demo",
                                                now=parse_time(snapshot["as_of"]),
                                                max_events=IMPORT_MAX_EVENTS, max_assets=IMPORT_MAX_ASSETS)}


def _span_days(document: dict) -> float:
    events = document["events"]
    if len(events) < 2:
        return 1.0
    span = parse_time(events[-1]["at"]) - parse_time(events[0]["at"])
    return max(span / timedelta(days=1), 1.0 / 24)


def score(prepared: dict, config: RuleConfig) -> dict:
    """Classify one scenario's findings against its incident labels."""
    labels = prepared["labels"]
    malicious = set(labels["malicious_event_ids"]) | {"asset:" + a for a in labels["malicious_asset_ids"]}
    findings = analyze(prepared["normalized"], config)
    per_rule: dict[str, Counter] = {rule: Counter() for rule in BEHAVIORAL_RULES + HYGIENE_RULES}
    false_positive_actors: set[str] = set()
    for f in findings:
        bucket = per_rule.setdefault(f["rule"], Counter())
        bucket["alerts"] += 1
        if f["rule"] in HYGIENE_RULES:
            continue
        if malicious & set(f["evidence_ids"]):
            bucket["tp"] += 1
        else:
            bucket["fp"] += 1
            if "actor" in f:
                false_positive_actors.add(f["actor"])
    missed = [rule for rule in labels["expect_rules"] if not per_rule.get(rule, Counter())["tp"]]
    for rule in missed:
        per_rule.setdefault(rule, Counter())["fn"] += 1
    days = _span_days(prepared["normalized"])
    behavioral_fp = sum(per_rule[rule]["fp"] for rule in BEHAVIORAL_RULES)
    return {"scenario": prepared["name"], "attack": bool(prepared.get("attack")), "days": round(days, 2),
            "events": len(prepared["normalized"]["events"]),
            "per_rule": {rule: dict(counts) for rule, counts in per_rule.items() if counts},
            "behavioral": {"tp": sum(per_rule[r]["tp"] for r in BEHAVIORAL_RULES), "fp": behavioral_fp,
                           "fn": sum(per_rule[r]["fn"] for r in BEHAVIORAL_RULES),
                           "false_positive_actors": len(false_positive_actors),
                           "false_positives_per_day": round(behavioral_fp / days, 2)},
            "hygiene_alerts": sum(per_rule[r]["alerts"] for r in HYGIENE_RULES),
            "missed_rules": missed}


def evaluate(scenarios: list[dict], config: RuleConfig | None = None) -> dict:
    """Run every scenario under one configuration and aggregate the result."""
    config = config or DEFAULT_RULES
    if not scenarios:
        raise ValidationError("評価するシナリオを1つ以上指定してください。")
    prepared = [s if "normalized" in s else prepare(s) for s in scenarios]
    results = [score(p, config) for p in prepared]
    days = sum(r["days"] for r in results)
    tp = sum(r["behavioral"]["tp"] for r in results)
    fp = sum(r["behavioral"]["fp"] for r in results)
    fn = sum(r["behavioral"]["fn"] for r in results)
    expected = sum(len(p["labels"]["expect_rules"]) for p in prepared)
    per_rule: dict[str, Counter] = {}
    for row in results:
        for rule, counts in row["per_rule"].items():
            per_rule.setdefault(rule, Counter()).update(counts)
    return {"rule_version": RULE_VERSION, "rule_config": {"digest": config.digest, "values": config.as_dict()},
            "generated_at": iso(utcnow()), "scenarios": results,
            "totals": {"scenarios": len(results), "days": round(days, 2),
                       "events": sum(r["events"] for r in results),
                       "true_positives": tp, "false_positives": fp, "missed": fn,
                       "expected_detections": expected,
                       "precision": round(tp / (tp + fp), 4) if tp + fp else None,
                       "recall": round(tp / expected, 4) if expected else None,
                       "false_positives_per_day": round(fp / days, 2) if days else None,
                       "hygiene_alerts": sum(r["hygiene_alerts"] for r in results),
                       "per_rule": {rule: dict(counts) for rule, counts in sorted(per_rule.items())}},
            "caveats": ["合成データ上の数値であり、実環境の誤検知率ではありません。",
                        "AS-001とAS-005は台帳の登録内容をそのまま示すため、精度計算には含めていません。",
                        "検知漏れは、ラベル付き事案に対して期待したルールが1件も一致しなかった場合に数えています。"]}


def sweep(scenarios: list[dict], base: RuleConfig | None = None,
          thresholds: tuple[int, ...] = SWEEP_THRESHOLDS, windows: tuple[int, ...] = SWEEP_WINDOWS) -> dict:
    """Grid-search the bulk-access thresholds and report the cost of each cell."""
    base = base or DEFAULT_RULES
    prepared = [prepare(s) for s in scenarios]
    cells = []
    for threshold, window in itertools.product(sorted(thresholds), sorted(windows)):
        config = base.replace(distinct_file_threshold=threshold, window_seconds=window)
        summary = evaluate(prepared, config)["totals"]
        cells.append({"distinct_file_threshold": threshold, "window_seconds": window,
                      "true_positives": summary["true_positives"], "false_positives": summary["false_positives"],
                      "missed": summary["missed"], "recall": summary["recall"],
                      "precision": summary["precision"],
                      "false_positives_per_day": summary["false_positives_per_day"],
                      "per_rule": {rule: {"tp": summary["per_rule"].get(rule, {}).get("tp", 0),
                                          "fp": summary["per_rule"].get(rule, {}).get("fp", 0)}
                                   for rule in BEHAVIORAL_RULES}})
    complete = [c for c in cells if c["recall"] == 1.0] if any(c["recall"] == 1.0 for c in cells) else []
    # Prefer no false positives, then the most sensitive threshold that still holds,
    # so a smaller incident than the labeled one still has room to trip the rule.
    recommended = min(complete, key=lambda c: (c["false_positives"], c["distinct_file_threshold"], -c["window_seconds"])) if complete else None
    return {"generated_at": iso(utcnow()), "rule_version": RULE_VERSION, "base_config": base.as_dict(),
            "scenarios": [p["name"] for p in prepared], "cells": cells, "recommended": recommended,
            "caveats": ["推奨値は同梱の合成シナリオに対する結果です。導入先の正常ログで再測定してください。",
                        "検知漏れ0を優先し、その中で最も感度の高い（閾値の小さい）設定を選んでいます。",
                        "この探索は大量参照の閾値と時間窓のみを対象とし、他の条件は変更していません。"]}


def markdown(report: dict, sweep_report: dict | None = None) -> str:
    totals = report["totals"]
    lines = ["# 誤検知評価レポート — AI Secure", "",
             f"生成: {report['generated_at']} / ルール {report['rule_version']} / 設定 `{report['rule_config']['digest']}`", "",
             "## 設定", "", "| 項目 | 値 |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in report["rule_config"]["values"].items()]
    lines += ["", "## 全体", "", "| 指標 | 値 |", "|---|---|",
              f"| シナリオ数 | {totals['scenarios']} |",
              f"| 対象期間（合計） | {totals['days']} 日 |",
              f"| イベント数 | {totals['events']:,} |",
              f"| 検知（ラベル一致） | {totals['true_positives']} |",
              f"| 誤検知 | {totals['false_positives']} |",
              f"| 検知漏れ | {totals['missed']} / {totals['expected_detections']} |",
              f"| 適合率 | {totals['precision'] if totals['precision'] is not None else '—'} |",
              f"| 再現率 | {totals['recall'] if totals['recall'] is not None else '—'} |",
              f"| 誤検知 / 日 | {totals['false_positives_per_day'] if totals['false_positives_per_day'] is not None else '—'} |",
              f"| 資産ルールの件数（精度計算外） | {totals['hygiene_alerts']} |", "",
              "## シナリオ別", "", "| シナリオ | 事案 | 日数 | イベント | 検知 | 誤検知 | 漏れ | 誤検知/日 | 影響を受ける利用者 |", "|---|---|---|---|---|---|---|---|---|"]
    for row in report["scenarios"]:
        b = row["behavioral"]
        lines.append(f"| {row['scenario']} | {'あり' if row['attack'] else 'なし'} | {row['days']} | {row['events']:,} | "
                     f"{b['tp']} | {b['fp']} | {b['fn']} | {b['false_positives_per_day']} | {b['false_positive_actors']} |")
    rule_totals: Counter = Counter()
    for row in report["scenarios"]:
        for rule, counts in row["per_rule"].items():
            for key, value in counts.items():
                rule_totals[(rule, key)] += value
    rules_seen = sorted({rule for rule, _ in rule_totals})
    lines += ["", "## ルール別", "", "| ルール | 件数 | 検知 | 誤検知 | 漏れ |", "|---|---|---|---|---|"]
    for rule in rules_seen:
        note = "（精度計算外）" if rule in HYGIENE_RULES else ""
        lines.append(f"| {rule}{note} | {rule_totals[(rule, 'alerts')]} | {rule_totals[(rule, 'tp')]} | "
                     f"{rule_totals[(rule, 'fp')]} | {rule_totals[(rule, 'fn')]} |")
    if sweep_report:
        lines += ["", "## 閾値スイープ", "",
                  "大量参照の閾値と時間窓だけを動かした結果です。AS-003は単体の大量参照、AS-004は接続機器・特権ログイン・大量参照の相関です。", "",
                  "| 異なるファイル数 | 時間窓(秒) | AS-003 検知 | AS-003 誤検知 | AS-004 検知 | AS-004 誤検知 | 漏れ | 誤検知/日 |",
                  "|---|---|---|---|---|---|---|---|"]
        for cell in sweep_report["cells"]:
            bulk, link = cell["per_rule"]["AS-003"], cell["per_rule"]["AS-004"]
            lines.append(f"| {cell['distinct_file_threshold']} | {cell['window_seconds']} | {bulk['tp']} | {bulk['fp']} | "
                         f"{link['tp']} | {link['fp']} | {cell['missed']} | {cell['false_positives_per_day']} |")
        recommended = sweep_report["recommended"]
        lines += ["", "### 推奨", "",
                  (f"`distinct_file_threshold = {recommended['distinct_file_threshold']}` / "
                   f"`window_seconds = {recommended['window_seconds']}`（誤検知 {recommended['false_positives']} 件、検知漏れ {recommended['missed']} 件）"
                   if recommended else "検知漏れのない設定が探索範囲内に見つかりませんでした。ルール条件そのものの見直しが必要です。")]
        lines += ["", *[f"- {c}" for c in sweep_report["caveats"]]]
    lines += ["", "## この結果から言えること", "", *observations(report)]
    lines += ["", "## 注意", "", *[f"- {c}" for c in report["caveats"]],
              "- 本レポートは導入判断の材料であり、検知性能の保証ではありません。"]
    return "\n".join(lines) + "\n"


def observations(report: dict) -> list[str]:
    """Statements read directly off the numbers. No extrapolation to real environments."""
    totals = report["totals"]
    per_rule = totals["per_rule"]
    out = []
    bulk = per_rule.get("AS-003", {})
    link = per_rule.get("AS-004", {})
    if bulk.get("fp"):
        out.append(f"- 単体の大量参照（AS-003）は、この合成データで誤検知 {bulk['fp']} 件・検知 {bulk.get('tp', 0)} 件でした。"
                   "分析作業、バックアップ、移行作業が同じ形をしているためで、閾値だけでは分離できていません。")
    if link:
        out.append(f"- 相関（AS-004）は検知 {link.get('tp', 0)} 件・誤検知 {link.get('fp', 0)} 件でした。"
                   "公開・未修正の接続機器と、承認・端末条件を満たさない特権ログインを同時に要求しているためです。")
    if totals["missed"]:
        out.append(f"- ラベル付き事案のうち {totals['missed']} 件のルールが未検知です。閾値かルール条件の見直しが必要です。")
    else:
        out.append("- ラベル付き事案は、期待したすべてのルールで検知できています。")
    if totals["false_positives_per_day"] is not None:
        out.append(f"- この設定では1日あたり約 {totals['false_positives_per_day']} 件が担当者の確認対象になります。"
                   "運用可能な件数かどうかは、導入先の体制で判断してください。")
    out.append("- 合成データの正常側には、バックアップ、分析作業、移行作業、承認済みの保守接続を含めています。"
               "実環境にはこれ以外の正常な大量参照が存在します。")
    return out
