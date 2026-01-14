# 006: Reconnaissance Agent

## 概要

受動OSINT＋必要最小限のアクティブ調査を行い、ターゲットの基本情報を収集するAgentを実装する。

## 目的

- ターゲットの外部露出情報を収集
- ポート/サービス/技術スタックの初期把握
- 後続フェーズに必要な基礎データの提供

## 責務

### 担当範囲

- Shodanによる受動的ホスト情報収集
- OSINTによるドメイン/組織情報収集
- 必要最小限のNmapスキャン

### 非担当

- アプリケーション層の詳細調査（Enumerationで実施）
- 脆弱性評価（Plannerで実施）
- Exploit実行（Exploitationで実施）

## 使用MCP

| MCP | 用途 | 優先度 |
|-----|------|--------|
| hexstrike-ai | ホスト/ポート/バナー情報、ドメイン/DNS/WHOIS情報、ポートスキャン | 高 |

## 入力（Context Bundle）

```python
class ReconContextBundle:
    session_id: str
    state_version: int
    scope: Scope  # 必須
    target_profile: TargetProfile  # 初期状態または前回結果
    previous_observations: List[Observation]  # 既存の観測記録
```

## 出力（Patch）

- `add_evidence`: MCP実行結果の保存
- `add_observation`: 実行記録
- `update_target_profile`: 発見した情報の追加

## 処理フロー

1. Scope確認（ターゲットリスト取得）
2. 各ターゲットに対して:
   a. Shodan照会（受動）→ Evidence保存 → TargetProfile更新
   b. OSINT照会 → Evidence保存 → TargetProfile更新
   c. 必要に応じてNmapスキャン → Evidence保存 → TargetProfile更新
3. Patch生成・返却

## 実装タスク

- [x] Agent基盤
  - [x] ReconAgentクラス実装
  - [x] Context Bundle受信処理
  - [x] Patch生成処理
- [x] Shodan連携
  - [x] Shodan MCPアダプター実装
  - [x] ホスト情報取得
  - [x] 結果のEvidence保存
  - [x] Passer経由でTargetProfile変換
- [x] OSINT連携
  - [x] OSINT MCPアダプター実装
  - [x] ドメイン/DNS情報取得
  - [x] 結果のEvidence保存
  - [x] Passer経由でTargetProfile変換
- [x] Nmap連携
  - [x] Nmap MCPアダプター実装
  - [x] スキャン実行（最小限のポート）
  - [x] 結果のEvidence保存
  - [x] Passer経由でTargetProfile変換
- [x] スキップ判定
  - [x] Shodan/OSINTで十分な場合のNmapスキップ
  - [x] スキップ理由のDecisionTrace記録
- [x] エラーハンドリング
  - [x] MCP失敗時のリトライ
  - [x] タイムアウト処理
  - [x] 部分的成功の処理
- [x] 単体テスト
  - [x] 各MCP連携テスト（モック）
  - [x] Patch生成テスト
  - [x] スキップ判定テスト
  - [x] エラーハンドリングテスト

## 実装完了メモ

**完了日**: 2024-12-18

**テスト結果**: 64 tests passed

**実装ファイル**:
- `src/agents/__init__.py` - Agent exports
- `src/agents/base_agent.py` - BaseAgent, AgentConfig, AgentContext, AgentOutput, DecisionTrace
- `src/agents/reconnaissance_agent.py` - ReconnaissanceAgent with full workflow
- `src/mcp_adapters/__init__.py` - MCP adapter exports
- `src/mcp_adapters/base_adapter.py` - BaseMCPAdapter, MCPResult, MCPError, MCPToolType
- `src/mcp_adapters/shodan_adapter.py` - ShodanAdapter with mock mode
- `src/mcp_adapters/osint_adapter.py` - OSINTAdapter with mock mode
- `src/mcp_adapters/nmap_adapter.py` - NmapAdapter with mock mode
- `tests/agents/__init__.py`
- `tests/agents/test_base_agent.py` - 18 tests for base agent classes
- `tests/agents/test_mcp_adapters.py` - 32 tests for MCP adapters
- `tests/agents/test_reconnaissance_agent.py` - 14 tests for reconnaissance agent

## 停止条件

- Scope外ターゲットの検出
- 連続MCP失敗（2回）
- タイムアウト（デフォルト10分）

## 品質ゲート

- 最低1つのEvidenceを伴うTargetProfile更新
- Observation記録の完全性

## 依存関係

- 001_shared_workspace（Evidence保存）
- 002_common_schema（スキーマ）
- 003_passer（正規化）
- 005_orchestrator（呼び出し元）

## 関連ファイル

```
/src/agents/
  __init__.py
  base_agent.py
  reconnaissance_agent.py
/src/mcp_adapters/
  shodan_adapter.py
  osint_adapter.py
  nmap_adapter.py
```

## メモ

- Nmapは `-T2`以下の速度で実行（ステルス重視）
- 大規模CIDR（/16以上）はサンプリング提案
- 受動調査を優先し、アクティブは最小限に
