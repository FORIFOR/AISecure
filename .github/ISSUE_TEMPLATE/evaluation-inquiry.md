---
name: Evaluation / adoption inquiry / 導入・評価の相談
about: Discuss importing your own logs and measuring false positives on your environment
title: "[evaluation] "
labels: evaluation
---

<!--
English follows below. まず日本語です。

⚠️ 実ログ・認証情報・個人情報・秘密は貼らないでください。
   この Issue は公開です。ログ「形式」の説明だけで十分です。
⚠️ Do NOT paste real logs, credentials, personal data, or secrets.
   This issue is PUBLIC. A description of the log *shape* is enough.

AI Secure は検証用プロトタイプです（常時監視・実際の遮断は未実装）。
「評価」は、あなたのログ形式を取り込めるか試し、事案のない期間で
誤検知率を測る、探索的な共同作業です。有料の運用サービスではありません。
-->

## 何を確かめたいですか / What do you want to find out?
<!-- 例: 自社のVPN/認証/ファイルアクセスのログを取り込めるか。正常業務が誤検知にならないか。 -->


## 対象システム（種類だけで可） / Systems involved (types only)
<!-- 例: Okta / Entra ID / Windows Security / 自社SIEMのエクスポート / VPNゲートウェイ。製品名がわかる範囲で。 -->


## ログ形式 / Log shape
<!--
実データではなく「形式」を書いてください。例:
- CSV, columns: timestamp, event_id, user, src_ip, result …
- JSON Lines, keys: ts, actor, host, path, bytes …
文字コード・時刻書式（TZ有無）もわかれば。
Describe the FORMAT, not real rows. Encoding and timestamp format (TZ?) help.
-->


## 規模・期間の目安 / Rough scale & period
<!-- 例: 1日あたり約Nイベント、評価したい期間（事案のない◯週間 など）。概算で可。 -->


## 制約・気になる点 / Constraints or concerns
<!-- 例: データを外に出せない（ローカル完結で問題ありません）／特定の正常業務が誤検知になりそう 等 -->


---

**進め方の前提 / How this works**
- すべて手元・オフラインで評価できます。実ログをこの Issue やどこかにアップロードする必要はありません。
- 誤検知の報告として最も価値があるのは「取り込めない実ログ形式」「正常業務なのに検知される例」です（形式の再現で十分）。
- You can evaluate entirely locally and offline — no need to upload real logs anywhere.
