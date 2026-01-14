# 008: Planner Agent

## 概要

脆弱性候補の探索・成立性評価を行い、Exploit計画を立案するAgentを実装する。

## 目的

- TargetProfileに基づく脆弱性候補の特定
- CVE/Snykデータベースとの照合
- Exploit候補の探索（GitHub/GitLab）
- 実行計画（ExecutionPlan）の立案

## 責務

### 担当範囲

- 脆弱性データベース照会
- 成立性評価（バージョン、前提条件）
- PoC/Exploit候補の探索
- 実行計画の立案

### 非担当

- 情報収集（Recon/Enumerationで実施）
- Exploit実行（Exploitationで実施）

## 使用MCP

| MCP | 用途 | 優先度 |
|-----|------|--------|
| hexstrike-ai | 脆弱性参照、CVE詳細照会、露出再確認 | 高 |
| GitHub | PoC/Exploit検索 | 高 |

## 入力（Context Bundle）

```python
class PlannerContextBundle:
    session_id: str
    state_version: int
    scope: Scope
    target_profile: TargetProfile  # Recon+Enumeration結果
    observations: List[Observation]
    existing_vuln_candidates: List[VulnCandidate]
```

## 出力（Patch）

- `add_evidence`: 脆弱性情報、PoC情報等
- `add_observation`: 照会記録
- `add_vuln_candidate`: 脆弱性候補
- `add_exploit_candidate`: Exploit候補
- `propose_execution_plan`: 実行計画
- `add_decision_trace`: 選択理由

## 処理フロー

1. TargetProfileから技術スタック抽出
2. 脆弱性照会:
   a. Snykで依存関係の脆弱性チェック
   b. CVE-researchでサービス/バージョンの脆弱性照会
3. 成立性評価:
   a. バージョンマッチング
   b. 前提条件確認（認証要否、到達性等）
4. Exploit探索:
   a. GitHub/GitLabでPoC検索
   b. 信頼性評価（スター数、更新日等）
5. 実行計画立案:
   a. 優先度付け（CVSS、成立性、影響度）
   b. requires_approval設定
   c. ロールバック手順
6. Patch生成・返却

## 実装タスク

- [x] Agent基盤
  - [x] PlannerAgentクラス実装
  - [x] Context Bundle受信処理
  - [x] Patch生成処理
- [x] Snyk連携
  - [x] Snyk MCPアダプター実装
  - [x] 依存関係スキャン
  - [x] 結果のEvidence保存
  - [x] VulnCandidate変換
- [x] CVE-research連携
  - [x] CVE-research MCPアダプター実装
  - [x] CVE照会
  - [x] 結果のEvidence保存
  - [x] VulnCandidate変換
- [x] GitHub連携
  - [x] GitHub MCPアダプター実装
  - [x] PoC/Exploit検索
  - [x] 信頼性評価
  - [x] ExploitCandidate変換
- [ ] GitLab連携（優先度: 中）
  - [ ] GitLab MCPアダプター実装
  - [ ] PoC/Exploit検索
  - [ ] ExploitCandidate変換
- [x] 成立性評価
  - [x] バージョン比較ロジック
  - [x] 前提条件チェック
  - [x] confidence_level算出
- [x] 実行計画立案
  - [x] 優先度スコアリング
  - [x] ステップ分解
  - [x] requires_approval判定
  - [x] ロールバック手順生成
- [x] エラーハンドリング
  - [x] MCP失敗時のリトライ（BaseMCPAdapterで実装）
  - [x] 候補なし時の処理
- [x] 単体テスト
  - [x] 各MCP連携テスト（モック）
  - [x] 成立性評価テスト
  - [x] 実行計画生成テスト

## 停止条件

- 脆弱性候補なし（正常終了として停止提案）
- Exploit候補なし（VulnCandidateのみで終了）
- 連続MCP失敗（2回）

## FR-9: 粘り強さポリシー（Persistence Policy）

**1度の失敗ですぐに諦めない。** 以下の原則に従う：

### 失敗時の対応
1. 失敗した理由を深く分析し、根本原因を特定
2. 別のアプローチ、ツール、情報源を検討
3. 3回以上の失敗でも、代替手段があれば試行を継続

### 禁止事項
- 1度の失敗で「脆弱性は存在しない」と断定しない
- 代替手段を検討せずに分析を終了しない
- 表面的な調査で「これ以上のテストなし」と判断しない

## FR-10: Post-Exploitation評価（最重要）

Exploitationフェーズ終了後、**即座に「これ以上のテストなし」と判断しない。**

### 必須検討項目

| カテゴリ | 検討内容 |
|----------|----------|
| 認証情報活用 | 取得した認証情報を他サービス(SSH等)で試行可能か |
| データベース | LOAD_FILE()でシステムファイル読み取り可能か |
| データベース | INTO OUTFILEでWebシェル設置可能か |
| データベース | 他テーブルに機密情報はあるか |
| 特権昇格 | MySQLユーザーにFILE権限があるか |
| 横展開 | 発見した認証情報を他エンドポイントで試行可能か |
| 設定ファイル | .htpasswd、config.phpなど読み取り可能か |
| ソースコード | PHPファイル取得で追加脆弱性を発見できるか |

### 「これ以上のテストなし」と判断する条件

以下の**すべて**が満たされた場合のみ終了判断を下す：
1. 取得したアクセスを活用した追加攻撃を**検討済み**
2. データベース操作（LOAD_FILE/INTO OUTFILE）の可能性を**確認済み**
3. 横展開の可能性を**確認済み**
4. 特権昇格の可能性を**確認済み**
5. 人間が追加テストを**明示的に拒否/スキップ**

## 品質ゲート

- VulnCandidateは必ずevidence_ids付き
- ExploitCandidateはvuln_candidate_idと紐付け
- ExecutionPlanは危険ステップにrequires_approval

## 依存関係

- 001_shared_workspace（Evidence保存）
- 002_common_schema（スキーマ）
- 003_passer（正規化）
- 005_orchestrator（呼び出し元）
- 006/007（前フェーズ）

## 関連ファイル

```
/src/agents/
  planner_agent.py
/src/mcp_adapters/
  snyk_adapter.py
  cve_adapter.py
  github_adapter.py
  gitlab_adapter.py
```

## メモ

- PoC取得はPlanner段階では参照のみ（実行はExploitation）
- 未検証のPoCは信頼性を「low」としてマーク
- 複数の脆弱性がある場合は重大度順に計画
