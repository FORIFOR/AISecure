# dependency-map/n-aisecure-explain-py-6f5760

[解析トップへ戻る](../../README.md)

確認済みファイル: `aisecure/explain.py`

解析: Python AST。静的なimport／export参照です。関数の実行順序やHTTP通信は表していません。

宣言: `NoRedirect`, `template`, `Explainer`

- `__future__` → 外部・標準ライブラリ・別名など。ローカル対応先は未確定
- `json` → 外部・標準ライブラリ・別名など。ローカル対応先は未確定
- `re` → 外部・標準ライブラリ・別名など。ローカル対応先は未確定
- `urllib.request` → 外部・標準ライブラリ・別名など。ローカル対応先は未確定
- `schema` → `aisecure/schema.py`（内容確認済み）


```mermaid
graph TD
    source["ソース\naisecure/explain.py"]
    n-future-05a733["__future__\n外部・別名・未解決"]
    source -->|"Python AST: import／export"| n-future-05a733
    n-json-05d97e["json\n外部・別名・未解決"]
    source -->|"Python AST: import／export"| n-json-05d97e
    n-re-c387c9["re\n外部・別名・未解決"]
    source -->|"Python AST: import／export"| n-re-c387c9
    n-urllib-request-920e11["urllib.request\n外部・別名・未解決"]
    source -->|"Python AST: import／export"| n-urllib-request-920e11
    n-schema-fe7042["schema\naisecure/schema.py"]
    source -->|"Python AST: import／export"| n-schema-fe7042
```

## 要素の説明

### n-future-05a733

参照名: `__future__`

ローカルのソース対応先を確定できませんでした。外部ライブラリ、標準ライブラリ、型別名などを区別する追加確認が必要です。

### n-json-05d97e

参照名: `json`

ローカルのソース対応先を確定できませんでした。外部ライブラリ、標準ライブラリ、型別名などを区別する追加確認が必要です。

### n-re-c387c9

参照名: `re`

ローカルのソース対応先を確定できませんでした。外部ライブラリ、標準ライブラリ、型別名などを区別する追加確認が必要です。

### n-schema-fe7042

参照名: `schema`

対応する実在ソース: `aisecure/schema.py`。内容確認済み。

### n-urllib-request-920e11

参照名: `urllib.request`

ローカルのソース対応先を確定できませんでした。外部ライブラリ、標準ライブラリ、型別名などを区別する追加確認が必要です。

### source

`aisecure/explain.py` の内容を確認しました。

