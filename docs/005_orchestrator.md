# 005: Orchestrator（制御プレーン）

## 概要

Human InterfaceとAgent群を繋ぎ、承認・順序制御・状態管理を担う制御プレーンを実装する。

## 目的

- テスターとシステムの対話インターフェース
- Agentへのルーティングと実行制御
- 承認ゲートによる安全性確保
- State/Evidenceの一元管理

## スコープ

### インスコープ

- Human Interface（CLI）
- Agent呼び出し・ルーティング
- Context Bundle生成
- 承認ゲート
- 停止条件の監視
- Patch検証・適用（004_patch_protocolを利用）

### アウトオブスコープ

- 個別Agentのロジック（各Agentチケットで実装）
- MCP直接呼び出し（Agentを介する）

## フェーズ遷移

```
Recon → Enumeration → Planner → Exploitation → [Post-Exploitation Loop] → Reporting
```

### 差し戻し条件

- version未確定 → Reconへ
- 再現手順不足（req/res欠落）→ Enumerationへ
- Exploit失敗が前提不一致 → Planner/Enumerationへ

### スキップ条件

- Shodan/OSINTで十分な確証 → Nmap省略可
- 攻撃面なし → Planner「候補なし」で停止提案

### FR-10: Post-Exploitationループ（継続的テスト評価）

**重要: Exploitationフェーズ終了後、即座にレポート作成に移行しない。**

```
┌────────────────────────────────────────────────────────┐
│              Post-Exploitation ループ                   │
├────────────────────────────────────────────────────────┤
│  1. Exploitation結果をOrchestratorが受け取る            │
│                        ↓                               │
│  2. OrchestratorがPlannerに結果を提供                   │
│                        ↓                               │
│  3. Plannerが追加テストの可能性を深く検討               │
│                        ↓                               │
│  4. Plannerが追加テスト計画をOrchestratorに提案         │
│                        ↓                               │
│  5. Orchestratorが人間に次フェーズを提案し承認を取得    │
│                        ↓                               │
│  6. 承認 → 追加テスト実行（1に戻る）                    │
│     拒否/スキップ → 最終レポート作成へ                  │
└────────────────────────────────────────────────────────┘
```

**終了条件（以下のすべてが満たされた場合のみ）:**
1. Plannerが全追加テスト項目を検討済み
2. 人間が追加テストを明示的に拒否/スキップ
3. または Plannerが「これ以上のテストなし」と判断

## 承認ゲート対象

- Metasploit実行（モジュール実行）
- ペイロード配送、永続化関連操作
- 高頻度リクエスト、ブルートフォース
- ファイル改変、設定変更、権限昇格

## 停止条件

- 連続エラー閾値（同一error_class 2回）
- スコープ疑義検出
- DoS兆候検出
- 未知の破壊的挙動

## 実装タスク

- [x] CLI実装
  - [x] セッション開始/終了
  - [x] Scope入力・確認
  - [x] フェーズ進行表示
  - [x] 承認プロンプト
  - [x] 結果表示
- [x] ルーティングエンジン
  - [x] 現在フェーズの管理
  - [x] 次フェーズの決定
  - [x] 差し戻し判定
  - [x] スキップ判定
- [x] Context Bundle生成
  - [x] Agent別の必要情報抽出
  - [x] state_version付与
  - [x] 最小化（不要情報除外）
- [x] 承認ゲート
  - [x] requires_approvalの検出
  - [x] 承認プロンプト表示
  - [x] 承認/拒否の記録
  - [x] タイムアウト処理
- [x] 停止条件監視
  - [x] エラーカウント管理
  - [x] スコープ違反検出
  - [x] 異常挙動検出
  - [x] 緊急停止処理
- [x] Patch処理統合
  - [x] Agent応答の受信
  - [x] Patch検証呼び出し
  - [x] Patch適用呼び出し
  - [x] 結果のフィードバック
- [x] 監査ログ
  - [x] 全操作の記録
  - [x] 承認/拒否の記録
  - [x] フェーズ遷移の記録
- [x] 単体テスト
  - [x] ルーティングテスト
  - [x] Context Bundle生成テスト
  - [x] 承認ゲートテスト
  - [x] 停止条件テスト
- [x] 統合テスト
  - [x] フェーズ一巡テスト（モックAgent）
  - [x] Metasploit承認テスト
  - [x] State/Evidence永続化テスト
  - [x] フェーズロールバックテスト
  - [x] 停止条件テスト
  - [x] Context Bundle受け渡しテスト

## 受け入れ基準

- [x] [AC-1] Recon→Enumeration→Planner→Exploitation が最小ケースで一巡し、State/Evidenceが保存される
- [x] [AC-4] Metasploit実行は承認なしでは実行不可

## 依存関係

- 001_shared_workspace（State/Evidence管理）
- 002_common_schema（スキーマ）
- 004_patch_protocol（Patch処理）

## 関連ファイル

```
/src/orchestrator/
  __init__.py
  orchestrator.py      # Main Orchestrator class
  router.py           # Phase routing and transitions
  context_builder.py  # Context Bundle generation
  approval_gate.py    # Approval gate for dangerous operations
  stop_monitor.py     # Stop condition monitoring
  audit_logger.py     # Audit logging
/src/cli/
  __init__.py
  cli.py              # Main CLI class
  prompts.py          # User input prompts
  display.py          # Display utilities (colors, tables, etc.)
```

## メモ

- OrchestratorのみがStateを書き込む（Single Writer）
- 承認タイムアウトはデフォルト5分
- 緊急停止時はStateスナップショットを保存
