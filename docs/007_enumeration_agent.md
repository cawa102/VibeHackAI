# 007: Enumeration Agent

## 概要

アプリケーション層の詳細調査を行い、入力点・認可境界・攻撃面を把握するAgentを実装する。

## 目的

- Webアプリケーションのサイトマップ収集
- 入力点（フォーム、API等）の特定
- 認証/認可境界の把握
- 後続のPlanner/Exploitationに必要な詳細データ提供

## 責務

### 担当範囲

- Burpsuiteによるサイトマップ/req-res収集
- アプリケーション構造の把握
- 入力点・パラメータの列挙
- 認証機構の特定

### 非担当

- 脆弱性評価（Plannerで実施）
- Exploit実行（Exploitationで実施）
- インフラ層調査（Reconで実施）

## 使用MCP

| MCP | 用途 | 優先度 |
|-----|------|--------|
| hexstrike-ai | サイトマップ/req-res収集、サービス詳細、既知パス情報 | 高 |
| GitHub | 設定例/既知パス（補助） | 低 |

## 入力（Context Bundle）

```python
class EnumerationContextBundle:
    session_id: str
    state_version: int
    scope: Scope
    target_profile: TargetProfile  # Recon結果を含む
    previous_observations: List[Observation]
```

## 出力（Patch）

- `add_evidence`: HTTP req/res、サイトマップ等
- `add_observation`: 実行記録
- `update_target_profile`: 入力点、認証情報等の追加

## 処理フロー

1. TargetProfileからWebサービスを抽出
2. 各Webサービスに対して:
   a. Burpでサイトマップ取得 → Evidence保存
   b. 入力点の列挙 → TargetProfile更新
   c. 認証機構の特定 → TargetProfile更新
3. 必要に応じて補助MCP呼び出し
4. Patch生成・返却

## 実装タスク

- [x] Agent基盤
  - [x] EnumerationAgentクラス実装
  - [x] Context Bundle受信処理
  - [x] Patch生成処理
- [x] Burpsuite連携
  - [x] Burpsuite MCPアダプター実装
  - [x] サイトマップ取得
  - [x] req/resペア取得
  - [x] 結果のEvidence保存
  - [x] Passer経由で変換
- [x] 入力点解析
  - [x] フォーム検出
  - [x] APIエンドポイント検出
  - [x] パラメータ列挙
  - [x] ファイルアップロード検出
- [x] 認証解析
  - [x] ログインフォーム検出
  - [x] セッション管理方式特定
  - [x] 認可境界の推定
- [x] 補助MCP連携
  - [x] Nmap詳細スキャン（必要時）
  - [ ] OSINT既知パス（必要時）- 将来実装
  - [ ] GitHub/GitLab設定例（必要時）- 将来実装
- [x] エラーハンドリング
  - [x] MCP失敗時のリトライ
  - [x] タイムアウト処理
  - [x] 認証要求時の処理
- [x] 単体テスト
  - [x] Burp連携テスト（モック）
  - [x] 入力点解析テスト
  - [x] 認証解析テスト
  - [x] Patch生成テスト

## 実装完了メモ

**完了日**: 2024-12-18

**テスト結果**: 105 tests passed (全agentテスト)

**実装ファイル**:
- `src/agents/enumeration_agent.py` - EnumerationAgent with full workflow
- `src/mcp_adapters/burp_adapter.py` - BurpAdapter with mock mode
- `tests/agents/test_burp_adapter.py` - 18 tests for Burp adapter
- `tests/agents/test_enumeration_agent.py` - 23 tests for Enumeration agent

**主な機能**:
- Webターゲット抽出（URL、ドメイン、ターゲットプロファイルから）
- サイトマップ収集（spider, get_sitemap）
- フォーム検出（ログインフォーム、ファイルアップロード含む）
- APIエンドポイント検出（認証要否、パラメータ情報）
- 認証機構検出（form_based, session_cookie, api_token）
- パッシブスキャン結果収集
- Cookie/ヘッダー解析

## 停止条件

- Scope外URLへのリクエスト検出
- 認証必須で認証情報なし
- 連続MCP失敗（2回）
- タイムアウト（デフォルト15分）

## 品質ゲート

- 各入力点にreq/resのEvidence
- サイトマップの完全性
- 認証境界の明確化

## 依存関係

- 001_shared_workspace（Evidence保存）
- 002_common_schema（スキーマ）
- 003_passer（正規化）
- 005_orchestrator（呼び出し元）
- 006_reconnaissance_agent（前フェーズ）

## 関連ファイル

```
/src/agents/
  enumeration_agent.py
/src/mcp_adapters/
  burp_adapter.py
```

## メモ

- クローリング深度はデフォルト3に制限
- 同一ドメイン外へのリクエストは禁止
- 大量リクエストは承認ゲート対象の可能性
