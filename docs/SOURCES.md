# 一次情報と設計への対応

確認日: 2026年9月12日。事案は今後更新される可能性があります。直接引用ではなく要約と設計上の解釈を区別しています。

| ID | 一次情報 | この成果物での使い方 |
|---|---|---|
| S1 | デジタル庁「ガバメントソリューションサービスへの不正アクセスによる職員等の個人情報の漏えいの可能性について」2026年9月11日 | VPN、保守アカウント、大量参照という設計の背景。実際のログや詳細構成の推測には用いない |
| S2 | デジタル庁「本事案に関するQ&A」 | 当初Medium評価・修正前悪用・具体的脆弱性非公表を踏まえ、数値だけに依存しない優先度設計 |
| S3 | NIST SP 800-207, Zero Trust Architecture | ネットワーク位置による暗黙の信頼を避ける原則。規格適合を認定したものではない |
| S4 | OWASP Gen AI Security Project, LLM01:2025 Prompt Injection | AIの入力と権限を分離する設計。プロンプトのみで防御したと主張しない |
| S5 | Python公式 `http.server` documentation | 標準HTTPサーバーを本番推奨としない制約を明記 |
| S6 | CISA公式 `cisagov/kev-data` | 将来の既知悪用情報の照合候補。v0.1は同期も照合も行わない |
| S7 | Ollama公式 Generate a chat message API | 任意のローカル `/api/chat` 説明アダプターのリクエスト形式 |

## URLs

- S1: https://www.digital.go.jp/news/2026-0911-01
- S2: https://www.digital.go.jp/press/5fc99139-a4e2-4b7b-8b0c-d475e926143f
- S3: https://csrc.nist.gov/pubs/sp/800/207/final
- S4: https://genai.owasp.org/llmrisk/llm01-prompt-injection/
- S5: https://docs.python.org/3/library/http.server.html
- S6: https://github.com/cisagov/kev-data
- S7: https://docs.ollama.com/api/chat

CISAのカタログWebページは取得時403となったため、同組織の公式GitHubミラーを参照しました。デジタル大臣の2026年9月11日会見ページには確認時点で会見要旨未掲載の表示があり、内容の根拠には用いていません。

## 不明・推測しない事項

GSSで悪用されたCVE番号・VPN製品・完全なシステム構成・取得された正確なログ・第三者の攻撃手順は、この公開情報から確定していません。デモのCVSS 6.5や `DEMO-ADV-001` を実事案へ結び付けてはいけません。本製品によって当該事案を防止できたとする効果検証は行っていません。
