# 001: Shared Workspace + Evidence Ledger

## 概要

セッションデータの永続化基盤とEvidence（証跡）の改ざん耐性を持つ保存機構を実装する。

## 目的

- セッション単位でState/Evidence/Cacheを管理
- Evidenceの追記専用（append-only）保存とsha256ハッシュによる整合性保証
- Filesystem MCPとの連携

## スコープ

### インスコープ

- セッションディレクトリ構造の作成・管理
- Evidence Ledger（追記専用、sha256付き）
- State/Evidence/Cacheの基本CRUD操作
- Filesystem MCP連携

### アウトオブスコープ

- State更新ロジック（Patchプロトコルで実装）
- 正規化処理（Passerで実装）

## ディレクトリ構造

```
/workspace/sessions/<session_id>/
  state/
    scope.json
    target_profile.json
    candidates_vuln.json
    candidates_exploit.json
    execution_plans.json
    execution_results.jsonl
    observations.jsonl
    findings.json
    decision_traces.jsonl
    state_version.json
    context_bundles/
      recon/<ts>.json
      enumeration/<ts>.json
      planner/<ts>.json
      exploitation/<ts>.json
  evidence/
    <evidence_id>/
      raw.<ext>
      meta.json
  cache/
    cve/<query_hash>.json
    snyk/<query_hash>.json
    git/<query_hash>.json
  reports/
    draft.md
```

## 実装タスク

- [x] セッション管理クラスの実装
  - [x] セッションID生成（UUID v4）
  - [x] ディレクトリ構造の初期化
  - [x] セッション一覧取得
- [x] Evidence Ledger実装
  - [x] Evidence保存（raw + meta.json）
  - [x] sha256ハッシュ計算・保存
  - [x] Evidence取得（ID指定）
  - [x] Evidence一覧取得
  - [x] 削除禁止の強制（参照整合性）
- [x] State Store実装
  - [x] JSONファイルの読み書き
  - [x] JSONLファイルの追記・読み取り
  - [x] state_version管理
- [x] Cache Store実装
  - [x] クエリハッシュ計算
  - [x] キャッシュ保存・取得
  - [x] TTL管理（オプション）
- [x] Filesystem MCP Adapter実装
  - [x] ファイル読み書きのラッパー
  - [x] エラーハンドリング
- [x] 単体テスト
  - [x] セッション作成・削除テスト
  - [x] Evidence保存・取得・ハッシュ検証テスト
  - [x] State読み書きテスト
  - [x] キャッシュテスト

## 受け入れ基準

- [x] [AC-2] Evidenceがsha256付きで追記保存され、Stateから参照できる

## 依存関係

- なし（最初に実装）

## 関連ファイル

```
/src/storage/
  session_manager.py
  evidence_ledger.py
  state_store.py
  cache_store.py
/src/mcp_adapters/
  filesystem_adapter.py
```

## メモ

- Evidence保存時は必ずmeta.jsonにtimestamp、source_tool、query_params、response_codeを記録
- 大容量出力（>10MB）は分割保存を検討
