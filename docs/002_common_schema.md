# 002: Common Schema（型定義）

## 概要

システム全体で使用する共通データスキーマを定義する。すべてのオブジェクトは統一されたフィールドと構造を持つ。

## 目的

- Agent/Orchestrator間のデータ交換を型安全に
- 必須フィールドの強制による一貫性確保
- スキーマバージョン管理による後方互換性

## スコープ

### インスコープ

- 全共通オブジェクトの型定義
- バリデーション関数
- スキーマバージョン管理

### アウトオブスコープ

- MCP出力の正規化（Passerで実装）
- Patch操作のロジック（Patchプロトコルで実装）

## 必須オブジェクト

### 共通フィールド（全オブジェクト必須）

```python
class BaseSchema:
    id: str                  # UUID v4
    session_id: str          # セッションID
    created_at: datetime     # 作成日時（ISO 8601）
    created_by: str          # 作成者（agent名 or "orchestrator" or "human"）
    scope_tag: str           # スコープタグ（ターゲット識別子）
    schema_version: str      # スキーマバージョン（semver）
```
### Context Bundle フィールド

| フィールド | 必須 | 説明 |
|-----------|------|------|
| session_id | Yes | セッション識別子 |
| state_version | Yes | 楽観ロック用バージョン |
| scope_tag | Yes | ターゲット識別タグ |
| scope | Yes | 許可されたターゲットとアクション |
| allowed_tools | Yes | 当該エージェント・フェーズで許可されたツールリスト |
| target_profile | No | Recon結果（Enumeration以降） |
| approved_execution_plan | No | 承認済み計画（Exploitation時） |
| instructions | Yes | エージェントへの指示 |

### TestPlan フィールド (Planner)

| フィールド | 必須 | 説明 |
|-----------|------|------|
| plan_id | Yes | 計画識別子 |
| version | Yes | バージョン番号（更新ごとにインクリメント） |
| session_id | Yes | セッション識別子 |
| scope_summary | Yes | スコープの要約 |
| target_description | Yes | ターゲットの説明 |
| primary_objective | Yes | 主要目的 |
| phase_sequence | Yes | フェーズの配列（recon, enum, exploit） |
| change_log | Yes | 変更履歴 |

### Phase Status (Planner)

| ステータス | 説明 |
|-----------|------|
| `pending` | 未開始 |
| `in_progress` | 実行中 |
| `completed` | 完了 |
| `suspended` | 中断 |

### ExecutionPlan フィールド (Planner)

| フィールド | 必須 | 説明 |
|-----------|------|------|
| name | Yes | 計画名 |
| objective | Yes | 目的 |
| priority | Yes | 優先度（1=最高） |
| exploit_candidate_id | Yes | 関連ExploitCandidate |
| vuln_candidate_id | Yes | 関連VulnCandidate |
| cvss_estimate | Yes | CVSS評価 |
| steps | Yes | ステップの配列 |
| estimated_success_rate | Yes | 成功確率（0-1） |
| rationale | Yes | 根拠 |
| evidence_ids | Yes | 証跡ID |

### Step フィールド

| フィールド | 必須 | 説明 |
|-----------|------|------|
| step_id | Yes | ステップ識別子 |
| order | Yes | 実行順序 |
| action | Yes | アクション名 |
| description | Yes | 詳細説明 |
| tool | Yes | 使用ツール |
| parameters | Yes | パラメータ |
| requires_approval | Yes | 承認必要か |
| expected_outcome | Yes | 期待される結果 |
| success_criteria | Yes | 成功基準 |
| fallback | No | 失敗時の代替 |
| rollback | No | ロールバック手順 |
| depends_on | No | 依存するステップ |

### entry_point_inventory フィールド(Reconnaissance)

| フィールド | 必須 | 説明 |
|-----------|------|------|
| session_id | Yes | セッションID |
| target | Yes | ターゲット識別子 |
| total_entry_points | Yes | 総入口候補数 |
| by_category | Yes | カテゴリ別入口候補リスト |
| priority_summary | Yes | 優先度別サマリ（critical/high/medium/low） |

### technology_stack フィールド(Reconnaissance)

| フィールド | 必須 | 説明 |
|-----------|------|------|
| target | Yes | ターゲット識別子 |
| detected_at | Yes | 検出日時 |
| components | Yes | 検出コンポーネント（web_server, language, framework等） |
| security_relevant | Yes | セキュリティ関連情報（outdated_components, waf_bypass_notes） |

### handoff_summary フィールド(Reconnaissance)

| フィールド | 必須 | 説明 |
|-----------|------|------|
| session_id | Yes | セッションID |
| from | Yes | "reconnaissance-agent" |
| to | Yes | "enumeration-agent" |
| target_count | Yes | ターゲット数 |
| entry_points_total | Yes | 総入口候補数 |
| priority_breakdown | Yes | 優先度別内訳 |
| key_findings | Yes | 重要発見事項リスト |
| recommended_focus | Yes | 推奨フォーカス領域 |
| anomalies_for_review | Yes | レビュー必要な異常数 |
| evidence_ids | Yes | 証跡IDリスト |

### FindingCandidate フィールド(Enumeration)

| フィールド | 必須 | 説明 |
|-----------|------|------|
| title | Yes | 発見タイトル |
| severity | Yes | high/medium/low/info |
| description | Yes | 詳細説明 |
| affected_endpoint | Yes | 影響を受けるエンドポイント |
| reproduction_steps | Yes | 再現手順リスト |
| evidence_ids | Yes | 証跡ID（2つ以上） |
| reproducibility | Yes | status, attempts, success_rate |

### hypothesis_validation フィールド(Exploitation)

| フィールド | 必須 | 説明 |
|-----------|------|------|
| vuln_candidate_id | Yes | 検証対象のVulnCandidate ID |
| validation_status | Yes | ESTABLISHED / PARTIAL / NOT_ESTABLISHED / INCONCLUSIVE |
| executability.verified | Yes | 実行可能性の検証結果 |
| executability.method | Yes | 使用した検証手法 |
| executability.evidence_id | Yes | 証跡ID |
| impact_proof.verified | Yes | 影響証明の検証結果 |
| impact_proof.impact_type | Yes | 影響の種類（data_extraction等） |
| impact_proof.evidence_id | Yes | 証跡ID |
| confidence | Yes | high / medium / low |
| next_action | Yes | 次のアクション |

### 承認要求フィールド(Exploitation)

| フィールド | 必須 | 説明 |
|-----------|------|------|
| id | Yes | 承認要求ID |
| type | Yes | privilege_escalation / lateral_movement |
| current_access | Yes | 現在のアクセスレベル・権限 |
| target_access | Yes | 目標とするアクセスレベル |
| poc_description | Yes | PoC実行内容の説明 |
| poc_command | Yes | 実行予定コマンド |
| risk_assessment.risk_level | Yes | low / medium / high / critical |
| risk_assessment.reversibility | Yes | 操作の可逆性説明 |
| risk_assessment.scope_compliance | Yes | スコープ準拠確認 |
| expected_outcome | Yes | 期待される結果 |
| fallback_plan | No | 失敗時の代替計画 |


### 定義するオブジェクト

1. **Scope** - 許可されたターゲット範囲
2. **TargetProfile** - ターゲットの詳細情報
3. **EvidenceItem** - 証跡データのメタ情報
4. **Observation** - MCP実行結果の観測記録
5. **VulnCandidate** - 脆弱性候補
6. **ExploitCandidate** - Exploit候補
7. **ExecutionPlan** - 実行計画
8. **ExecutionResult** - 実行結果
9. **FindingCandidate** - 発見事項候補
10. **DecisionTrace** - 意思決定の記録

## 受け入れ基準

- [x] [AC-5] high/critical相当のFindingCandidateはEvidence要件を満たさない限り生成/昇格できない

## 依存関係

- 001_shared_workspace（EvidenceItem参照のため）

## 関連ファイル

```
/src/
  schemas/
    __init__.py
    base.py
    scope.py
    target_profile.py
    evidence.py
    observation.py
    vuln_candidate.py
    exploit_candidate.py
    execution_plan.py
    execution_result.py
    finding_candidate.py
    decision_trace.py
    validators.py
```

## メモ

- Pydanticを使用して型安全性を確保
- schema_versionは "1.0.0" からスタート
- 重大な主張（Finding等）は必ずevidence_idsを伴う
