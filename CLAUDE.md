# CLAUDE.md

MCP統合型マルチエージェント・ペネトレーションテスト支援システムのガイダンス。

---

## 0. GitHub v2 アップロード用TODOリスト

> **注意**: このセクションはGitHubアップロード完了後に削除してください。

### タスク一覧

- [x] **1. .gitignoreファイルの作成** ✅
  - センシティブファイル（.mcp.json, sessions/, workspace/, reports/, tmp/）を除外
  - .DS_Store, .pytest_cache/, .claude/settings.local.json を除外

- [x] **2. CLAUDE.mdの外部パス参照を修正** ✅
  - `/Users/kawaikyousuke/...` への絶対パス参照を相対パスに変更
  - VibeHackAI_Hexstrike_skillsへの外部参照を削除し、このリポジトリ内に統合

- [x] **3. README.mdの作成** ✅
  - プロジェクト概要、セットアップ手順、使用方法を記載
  - アーキテクチャ図を含める

- [x] **4. .mcp.json.exampleの作成** ✅
  - 実際のトークンを除去したテンプレートファイル
  - セットアップ手順の説明

- [x] **5. エージェント定義の参照パスを統合** ✅
  - .claude/agents/ 内のファイルパス参照を確認・修正
  - docs/ 内のtool_manifest.yaml参照を確認

- [x] **6. git status確認とコミット** ✅
  - 変更内容の最終確認
  - v2としてコミット・プッシュ

---

## 1. クイックスタート

### このシステムとは

4エージェント（Planner / Reconnaissance / Enumeration / Exploitation）+ Orchestratorと人間による対話型ペネトレーションテスト支援システム。

**目的**: 「攻撃の自動化」ではなく、**スコープ・安全性・証跡・再現性**を優先にLLMの推論とツール実行を統制することで、効率的なペネトレーションテストの実行。

### セッション開始手順

人間がターゲット情報を提供したのち、Orchestratorを起動し、ペネトレーションテストを実行。

---

## 2. システム概要

### アーキテクチャ

```
Orchestrator（制御プレーン - Single Writer）
├── Human Interface（承認・対話）
├── Routing/Coordination（フェーズ遷移）
└── State/Evidence管理（唯一の書き込み権限）

Agents（4つ）
├── Planner Agent
├── Reconnaissance Agent
├── Enumeration Agent
└── Exploitation Agent

Shared Workspace（共通領域）
├── State Store（正規化状態）
├── Evidence Store（生データ・追記専用）
└── Retrieval Cache（照会結果キャッシュ）

MCP Servers
├── GitHub
├── hexstrike-ai
└── Filesystem

**hexstrike-aiによって使用可能なツールは[docs/tool_manifest.yaml](docs/tool_manifest.yaml)に記載されている**
```

### 適用範囲

**インスコープ**:
- テスターが許可したターゲット（IP/CIDR/ドメイン）に対する偵察・列挙・脆弱性評価・Exploitation
- PoCプログラムの作成・テスト（承認必須）
- 証跡収集・レポート生成

**アウトオブスコープ**:
- 無差別・大規模スキャン、DoS、永続化、データ持ち出し、自律実行
- 人間承認なしの破壊的操作・ペイロード配布

---

## 3. 安全性ルール

### 絶対遵守事項

1. **スコープ厳守**: 全行動に `scope_tag` を付与、スコープ外検知で即停止
2. **証跡義務**: Evidenceは追記専用、Findingは必ずevidence_idで裏付け

### 停止条件

| 条件 | アクション |
|------|----------|
| 連続エラー閾値（同一error_class 2回） | 停止→人間エスカレーション |
| スコープ疑義 | 即停止→人間通知 |
| DoS兆候 | 即停止→人間通知 |
| 未知の破壊的挙動 | 即停止→人間通知 |

---

## 5. データ仕様

### Shared Workspace構成

```
/workspace/sessions/<session_id>/
  state/          # 正規化状態（Orchestratorのみ書き込み）
    scope.json
    target_profile.json
    candidates_vuln.json
    candidates_exploit.json
    execution_plans.json
    findings.json
    state_version.json
  evidence/       # 生データ（追記専用、sha256付き）
    <evidence_id>/
      raw.<ext>
      meta.json
  cache/          # 照会結果キャッシュ
  reports/        # レポート出力
```

### 共通スキーマ一覧
エージェント間での情報の受け渡しを安全に行うための共通スキーマが`docs/002_common_schema.md`に記載されている。
全スキーマの共通フィールド: `id`, `session_id`, `created_at`, `created_by`, `scope_tag`, `schema_version`

### Patchプロトコル

**原則**: Agentは**Patchのみ**返す。State直接更新禁止。

**操作一覧**:
- `add_evidence` - 証跡追加
- `add_observation` - MCP実行記録
- `update_target_profile` - ターゲット情報更新
- `add_vuln_candidate` - 脆弱性候補追加
- `add_exploit_candidate` - Exploit候補追加
- `propose_execution_plan` - 実行計画提案
- `record_execution_result` - 実行結果記録
- `add_finding_candidate` - 発見追加
- `promote_finding_candidate` - 発見昇格
- `add_decision_trace` - 決定理由記録


---

## 6. 行動規範

**この行動規範はすべてのサブエージェント(Orchestrator, Planner, Reconnaissance, Enumeration, Exploitation)に適応させる**

### 粘り強さポリシー

**原則**: 1度の失敗ですぐに諦めない

**失敗時の対応フロー**:
1. 失敗した理由を深く分析し、根本原因を特定
2. 別のアプローチ、ツール、ペイロードを検討
3. 段階的にエスカレーション:
   - 1回目の失敗: 別の方法を試す
   - 2回目の失敗: さらに別のアプローチを検討
   - 3回目以降: 相談し、戦略を再検討

**禁止事項**:
- 1度の失敗で「この脆弱性は存在しない」と断定しない
- 代替手段を検討せずにフェーズを終了しない
- 承認なしにテスト計画を変更しない

### Post-Exploitationループ

**原則**: Exploitation成功後、即座にレポート作成に移行しない

**ワークフロー**:
```
Exploitation結果 → Orchestrator → Planner
    ↓
Plannerが追加テストを検討
    ↓
追加テスト計画 → Orchestrator → 人間承認
    ↓
承認 → 追加テスト実行（ループ）
拒否/スキップ → 最終レポート作成
```

**終了条件**（すべて満たした場合のみ終了）:
- 取得したアクセスを活用した追加攻撃をすべて検討済み
- 人間が追加テストを明示的に拒否/スキップ

---

## 7. 参照情報

### 詳細仕様リンク

| ドキュメント | 内容 |
|-------------|------|
| [docs/001_shared_workspace.md](docs/001_shared_workspace.md) | Shared Workspace + Evidence Ledger仕様 |
| [docs/002_common_schema.md](docs/002_common_schema.md) | 共通スキーマ型定義 |
| [docs/003_passer.md](docs/003_passer.md) | 正規化エンジン仕様 |
| [docs/004_patch_protocol.md](docs/004_patch_protocol.md) | Patchプロトコル仕様 |
| [.claude/agents/pentest-orchestrator.md](.claude/agents/pentest-orchestrator.md) | Orchestrator仕様 |
| [.claude/agents/reconnaissance-agent.md](.claude/agents/reconnaissance-agent.md) | Reconnaissance Agent仕様 |
| [.claude/agents/enumeration-agent.md](.claude/agents/enumeration-agent.md) | Enumeration Agent仕様 |
| [.claude/agents/planner-agent.md](.claude/agents/planner-agent.md) | Planner Agent仕様 |
| [.claude/agents/exploitation-agent.md](.claude/agents/exploitation-agent.md) | Exploitation Agent仕様 |
