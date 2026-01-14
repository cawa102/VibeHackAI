# 004: Patchプロトコル

## 概要

AgentからOrchestratorへの状態更新提案（Patch）の仕組みを実装する。楽観ロックによる競合回避と安全性検証を行う。

## 目的

- Agentの出力を機械的に適用可能にする
- 競合・重複・誤更新を抑制
- 危険操作の事前検出

## スコープ

### インスコープ

- Patch構造の定義
- 楽観ロック（base_state_version検証）
- Orchestratorによる検証ロジック
- Patch適用処理

### アウトオブスコープ

- Agent側のPatch生成ロジック（各Agentで実装）
- 承認ゲートのUI（Orchestratorで実装）

## Patch構造

```python
class Patch:
    patch_id: str
    session_id: str
    agent_id: str
    base_state_version: int
    operations: List[PatchOperation]
    created_at: datetime

class PatchOperation:
    op: str  # 操作種別
    target: str  # 対象（スキーマ名/ID等）
    payload: dict  # 操作データ
```

## Patch操作一覧

| 操作 | 説明 | 対象 |
|------|------|------|
| `add_evidence` | Evidence追加 | EvidenceItem |
| `add_observation` | 観測記録追加 | Observation |
| `update_target_profile` | ターゲット情報更新 | TargetProfile |
| `add_vuln_candidate` | 脆弱性候補追加 | VulnCandidate |
| `add_exploit_candidate` | Exploit候補追加 | ExploitCandidate |
| `propose_execution_plan` | 実行計画提案 | ExecutionPlan |
| `record_execution_result` | 実行結果記録 | ExecutionResult |
| `add_finding_candidate` | 発見事項候補追加 | FindingCandidate |
| `promote_finding_candidate` | 発見事項候補昇格 | FindingCandidate |
| `add_decision_trace` | 意思決定記録追加 | DecisionTrace |

## 検証ルール

1. **バージョン検証**: `base_state_version`が現在のStateバージョンと一致
2. **スコープ検証**: 操作対象がScope内に含まれる
3. **必須フィールド検証**: payloadに必須フィールドが存在
4. **Evidence検証**: evidence_idsが参照するEvidenceが存在
5. **承認要件検証**: 危険操作に`requires_approval`が設定されている
6. **重複検証**: 同一IDのオブジェクトが既に存在しない

## 実装タスク

- [x] Patch構造定義
  - [x] Patchクラス実装
  - [x] PatchOperationクラス実装
  - [x] 操作種別のEnum定義
- [x] 楽観ロック実装
  - [x] state_versionの管理
  - [x] バージョン不一致時の拒否処理
  - [x] コンフリクト時のエラーメッセージ
- [x] 検証エンジン実装
  - [x] スコープ検証
  - [x] 必須フィールド検証
  - [x] Evidence存在検証
  - [x] 承認要件検証
  - [x] 重複検証
- [x] Patch適用エンジン実装
  - [x] add_evidence適用
  - [x] add_observation適用
  - [x] update_target_profile適用
  - [x] add_vuln_candidate適用
  - [x] add_exploit_candidate適用
  - [x] propose_execution_plan適用
  - [x] record_execution_result適用
  - [x] add_finding_candidate適用
  - [x] promote_finding_candidate適用
  - [x] add_decision_trace適用
- [x] アトミック更新
  - [x] トランザクション的な適用
  - [x] 失敗時のロールバック
  - [x] バージョンインクリメント
- [x] 監査ログ
  - [x] Patch適用履歴の記録
  - [x] 拒否理由の記録
- [x] 単体テスト
  - [x] 各操作の適用テスト
  - [x] バージョン不一致テスト
  - [x] スコープ違反テスト
  - [x] Evidence欠落テスト
  - [x] 承認要件欠落テスト

## 受け入れ基準

- [x] [AC-3] Patchはbase_state_version不一致で拒否される（競合回避）

## 依存関係

- 001_shared_workspace（State Store）
- 002_common_schema（スキーマ定義）

## 関連ファイル

```
/src/patch/
  __init__.py
  patch.py
  operations.py
  validator.py
  applier.py
  audit_log.py

/tests/patch/
  __init__.py
  test_patch.py
  test_validator.py
  test_applier.py
  test_audit_log.py
```

## メモ

- 検証失敗時は詳細なエラーメッセージを返す
- 部分適用は行わない（All or Nothing）
- 適用成功時は新しいstate_versionを返す
