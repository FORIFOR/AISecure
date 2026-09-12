# テスター募集 投稿キット（コピペ用）

> **更新（2026-09-13）**: Launchloom で AISecure の実UIから launch film を生成しました
> （`docs/media/launch-kit/aisecure-film.mp4` / 縦型 `…-vertical.mp4` / 一式 `aisecure-launch-kit.zip`）。
> 投稿に添付すると説得力が上がります。動画は投稿・公開しません（あなたが貼るまで手元のまま）。

---

## 0. いま、このニュースに接続する（最重要・時事フック）

2026-09-11、デジタル庁が Government Solution Service（GSS）への不正アクセスを公表しました
（出典: https://www.digital.go.jp/news/2026-0911-01 ）。公表内容の要点:

- 約 **24.6万件** の個人情報が漏えいのおそれ（職員 約18.9万・事業者 約5.7万）
- **VPNの脆弱性**を突かれて 2026-07-09 に侵入、2026-06-25 に**不審なファイルアクセス**を検知、
  当該アカウントを停止し外部通信を遮断
- マイナンバー・口座情報・年金番号は含まれず

この事案の“形” — **外部に露出した境界機器（VPN）→ 侵入 → 不審な大量ファイルアクセス** — は、
AI Secure が「1件の証拠つきの経路」として可視化しようとしているものそのものです。

**投稿での正直な言い方（厳守）**: 「AI Secure ならこの侵害を防げた」とは**言わない**。
言えるのは「この“形”を一枚の画面に出すことを狙った試作がある。合成データで試せる／壊してほしい」まで。
断定・実績の誇張・防止の主張はしない。

### X（日本語・時事版）

> 2026-09-11、デジタル庁がGSSへの不正アクセスを公表（約24.6万件のおそれ）。
> VPNの脆弱性から侵入 → 不審な大量ファイルアクセスを検知、という“形”でした。
>
> この「露出した境界機器 → 大量ファイル閲覧」を、CVSS順のアラートの山ではなく
> 1件の“証拠つきの経路”として出すことを狙った試作を作っています。合成データ・依存ゼロ・ローカル完結。
>
> ブラウザで試す（インストール不要）: https://forifor.github.io/AISecure/try.html
> 壊してくれる人を探しています（取り込めない実ログ形式／正常業務なのに誤検知になる例）。実ログ・秘密は貼らないでください。
> https://github.com/FORIFOR/AISecure
>
> ※この試作が同事案を防げたという主張ではありません。狙っているのは“形”を早く可視化することです。

### Hacker News（Show HN・時事版・英語）

**Title:** Show HN: AI Secure – turn "exposed VPN → bulk file read" into one evidence-backed case

**Body:**
Japan's Digital Agency disclosed on 2026-09-11 that its Government Solution Service was breached via a VPN vulnerability, with suspicious bulk file access before the account was cut (~246k records potentially exposed). That shape — an exposed perimeter device, then bulk reads — is exactly what a stack of CVSS-sorted alerts tends to bury.

AI Secure is a small, zero-dependency (Python stdlib only), local-first prototype that correlates an exposed unpatched device, a privileged login through it, and bulk file access from that session into a single evidence-backed case. Runs offline, all demo data is synthetic, every response action is gated behind an explicit approval, and I ship an honest "is this production-secure?" checklist that marks real-log validation, pen test and third-party review as NOT done.

To be clear: I'm not claiming this would have stopped that breach. I'm claiming the *shape* is worth making visible early, and I want people to break the prototype.

Try in-browser (synthetic data, no install): https://forifor.github.io/AISecure/try.html
Code: https://github.com/FORIFOR/AISecure

What I'd love: (1) a real log-export format that won't import, (2) normal activity that false-positives.

---

各チャネルにそのまま貼れる投稿文です。すべて**合成データのプロトタイプ**である旨を明記し、誇張を避けています。リンク: リポジトリ https://github.com/FORIFOR/AISecure ／ ブラウザ試用 https://forifor.github.io/AISecure/try.html

---

## 1. Hacker News（Show HN）

**Title:**
Show HN: AI Secure – local-first triage that links exposure + privileged login + bulk read

**Body:**
I built a small, zero-dependency (Python stdlib only) prototype that tries to answer one question a stack of CVSS-sorted alerts doesn't: is there a *path* here? It correlates three signals that are boring alone but dangerous together — an internet-exposed unpatched device, a privileged login through it, and bulk file access from that session — into a single evidence-backed case.

It came out of a Sept-2026 incident where a Medium-rated, already-published vuln was exploited before the patch landed and a maintenance account read a lot of files. Severity ranking would have buried it.

Everything runs locally and offline. No install beyond Python. All data in the demo is synthetic, actions are simulated, and I've written up the threat model and an honest "is this production-secure?" checklist (mostly ❌ for the parts that need real logs / a pen test / third-party review — I'm not pretending otherwise).

Try it in-browser (real UI, synthetic data, nothing to install): https://forifor.github.io/AISecure/try.html
Code: https://github.com/FORIFOR/AISecure

What I'd love feedback on: (1) a real log-export format that won't import, (2) normal activity that would false-positive. It's a prototype and I'm looking for people to break it.

---

## 2. Reddit — r/blueteam / r/netsec

**Title:** Local-first, zero-dependency triage prototype that correlates exposure + privileged login + bulk read into one case — looking for people to break it

**Body:**
Most triage surfaces I've used rank alerts by severity. That misses the case where three individually-unremarkable things line up: an exposed unpatched box, a privileged login through it, and bulk file access from that session.

AI Secure is a small prototype (Python stdlib only, runs locally/offline) that builds those into a single evidence-backed case instead of N separate alerts. Approvals for any real-world action are gated (confirmation string, reason, expiry) and everything's simulated in the demo.

I'm specifically looking for two kinds of feedback:
- A real log-export format (Okta / Entra / Windows Security / your SIEM export) that the importer chokes on.
- Normal business activity that the correlation rule would flag as a false positive.

Browser demo (synthetic data, no install): https://forifor.github.io/AISecure/try.html
Repo + threat model + security checklist: https://github.com/FORIFOR/AISecure

Please don't paste real logs or secrets into issues — a redacted shape of the format is enough. All demo data is synthetic; I make no claims about real-world false-positive rates.

---

## 3. X / Twitter（英語・スレッド）

**1/**
Alerts sorted by CVSS miss the dangerous case: an exposed unpatched device + a privileged login through it + bulk file access from that session. Each is boring. Together they're a breach.

I built a local-first prototype that links them into one evidence-backed case. 🧵

**2/**
Zero dependencies (Python stdlib only), runs entirely offline, no account. The demo data is synthetic and every action is simulated.

Try the real UI in your browser — nothing to install:
https://forifor.github.io/AISecure/try.html

**3/**
I wrote an honest "is this production-secure?" checklist too — the parts that need real logs, a pen test, or third-party review are marked ❌, not hand-waved.

Looking for testers to break it: a log format that won't import, or normal activity that false-positives.
https://github.com/FORIFOR/AISecure

---

## 4. X / Twitter（日本語）

アラートをCVSS順に並べると、いちばん危ない形を見落とします。

「ネットに露出した未パッチ機器」＋「そこを通った特権ログイン」＋「その後の大量ファイル閲覧」。単体ではどれも地味。でも並ぶと侵害です。

この3つを1件の"証拠つきの経路"にまとめるローカル完結のプロトタイプを作りました。依存ゼロ・オフライン・合成データ。

ブラウザで試す（インストール不要）:
https://forifor.github.io/AISecure/try.html

壊してくれる人を探しています。取り込めない実ログ形式、あるいは正常業務なのに誤検知になるケースを教えてください（実ログ・秘密は貼らないでください）。
https://github.com/FORIFOR/AISecure

---

## 5. LinkedIn（短文）

Sharing a weekend-scale prototype: AI Secure, a local-first security-triage tool that correlates an exposed unpatched device, a privileged login through it, and bulk file access into one evidence-backed case — instead of three separate alerts you'd rank by severity and miss.

Zero dependencies, runs offline, synthetic demo data, and an honest production-readiness checklist that doesn't pretend the hard parts (real-log validation, pen test, third-party review) are done.

If you work in detection/response, I'd value two things: a real log-export format that won't import, or normal activity that false-positives.

Browser demo (no install): https://forifor.github.io/AISecure/try.html
Code: https://github.com/FORIFOR/AISecure

---

## 6. 日本語コミュニティ（Zenn / Qiita 冒頭）

**タイトル:** アラートを重大度順に並べるのをやめて「経路」で見る — 依存ゼロのローカル完結セキュリティ・トリアージを作った

**冒頭:**
CVSSでソートされたアラートの山は、「単体では地味だが並ぶと危険」な形を見落とします。露出した未パッチ機器、そこを通った特権ログイン、その後の大量ファイル閲覧 — この3つを1件の"証拠つきの経路"にまとめる小さなプロトタイプ「AI Secure」を作りました。

- Python標準ライブラリのみ・依存ゼロ・完全オフライン
- デモは全て合成データ、実対応は全てシミュレーション
- 脅威モデルと「本番として安全か」の正直なチェックリスト同梱（実ログ検証・ペンテスト・第三者レビューは未実施として❌明記）

ブラウザ試用（インストール不要）: https://forifor.github.io/AISecure/try.html
リポジトリ: https://github.com/FORIFOR/AISecure

（本文へ続く…）

---

## 投稿のコツ（任意）
- **Show HN** は平日の午前（米国東部）に立てると伸びやすい。最初のコメントに「何を試してほしいか」を自分で置く。
- **Reddit** はサブレディットのルールを確認。自己宣伝許可日がある場合あり。
- どのチャネルでも、最初に返ってくる質問に**早く・正直に**返すと信頼が伸びる。
- 実ログ・秘密情報は絶対に貼らせない（誤検知報告は「形式の再現」で十分）と最初に明記済み。
