# VibeHackAI v2

MCP統合型マルチエージェント・ペネトレーションテスト支援システム

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 概要

VibeHackAIは、Claude Codeのエージェント機能とMCP (Model Context Protocol) を活用した対話型ペネトレーションテスト支援システムです。4つの専門エージェント（Reconnaissance、Enumeration、Planner、Exploitation）とOrchestratorが連携し、人間の監督のもとで安全かつ効率的なセキュリティ評価を実行します。

**重要**: このシステムは「攻撃の自動化」ではなく、**スコープ・安全性・証跡・再現性**を最優先にしたペネトレーションテストの支援を目的としています。

## アーキテクチャ

```
┌─────────────────────────────────────────────────────────────┐
│                    Human Interface                          │
│              (承認・対話・監督)                               │
└─────────────────────────────────┬───────────────────────────┘
                                  │
┌─────────────────────────────────▼───────────────────────────┐
│                 Orchestrator Agent                          │
│            (制御プレーン - Single Writer)                    │
│  ┌─────────────┬─────────────┬─────────────┐               │
│  │ State管理   │ 承認ゲート  │ エージェント │               │
│  │             │             │ ルーティング │               │
│  └─────────────┴─────────────┴─────────────┘               │
└─────────────────────────────────┬───────────────────────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        │                         │                         │
┌───────▼───────┐   ┌─────────────▼─────────────┐   ┌───────▼───────┐
│ Reconnaissance │   │      Enumeration         │   │   Planner     │
│    Agent      │   │        Agent             │   │    Agent      │
└───────────────┘   └──────────────────────────┘   └───────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │     Exploitation          │
                    │       Agent               │
                    └──────────────────────────┘
                                  │
┌─────────────────────────────────▼───────────────────────────┐
│                    Shared Workspace                         │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐            │
│  │State Store │  │Evidence    │  │Retrieval   │            │
│  │(正規化状態) │  │Store       │  │Cache       │            │
│  └────────────┘  └────────────┘  └────────────┘            │
└─────────────────────────────────────────────────────────────┘
                                  │
┌─────────────────────────────────▼───────────────────────────┐
│                    MCP Servers                              │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐            │
│  │  GitHub    │  │hexstrike-ai│  │ Filesystem │            │
│  └────────────┘  └────────────┘  └────────────┘            │
└─────────────────────────────────────────────────────────────┘
```

## 主な機能

### エージェント構成

| エージェント | 役割 |
|-------------|------|
| **Orchestrator** | 制御プレーン。フェーズ遷移、承認ゲート、状態管理を担当 |
| **Reconnaissance** | パッシブ/アクティブ情報収集（OSINT、Nmap、Shodan等） |
| **Enumeration** | サービス列挙、脆弱性候補の特定 |
| **Planner** | CVE調査、攻撃計画の立案、CVSS評価 |
| **Exploitation** | 承認された計画に基づくエクスプロイト実行 |

### 安全性機能

- **スコープ厳守**: すべての操作にscope_tagを付与し、スコープ外アクセスを防止
- **承認ゲート**: 危険な操作は人間の承認が必須
- **証跡管理**: すべての操作結果をEvidence Storeに追記保存
- **自動停止条件**: 連続エラー、DoS兆候検知時に自動停止

## 必要条件

- **Claude Code CLI** (最新版)
- **Docker** (MCP Server実行用)
- **Python 3.10+**
- **hexstrike-ai MCP Server** (ペネトレーションテストツール群)

## セットアップ

### 1. リポジトリのクローン

```bash
git clone https://github.com/cawa102/VibeHackAI.git
cd VibeHackAI
```

### 2. MCP設定

`.mcp.json.example` を `.mcp.json` にコピーし、適切に設定してください：

```bash
cp .mcp.json.example .mcp.json
```

必要な環境変数を設定:
- `GITHUB_PERSONAL_ACCESS_TOKEN`: GitHub API用トークン
- hexstrike-aiサーバーのエンドポイント設定

### 3. 依存関係のインストール

```bash
pip install -e .
```

## 使用方法

### セッションの開始

1. Claude Codeを起動
2. ターゲット情報（IP/CIDR/ドメイン）を提供
3. Orchestratorエージェントを呼び出し

```
pentest-orchestratorを起動してください。
ターゲット: example.com (192.168.1.0/24)
スコープ: Webアプリケーション診断
```

### ワークフロー

1. **Reconnaissance Phase**: 情報収集
2. **Enumeration Phase**: サービス・脆弱性の列挙
3. **Planning Phase**: 攻撃計画の立案
4. **Exploitation Phase**: 承認後のエクスプロイト実行
5. **Reporting**: 結果レポートの生成

各フェーズ間で人間の承認が必要です。

## ドキュメント

詳細なドキュメントは以下を参照してください：

| ドキュメント | 内容 |
|-------------|------|
| [CLAUDE.md](CLAUDE.md) | システムガイダンス（メイン） |
| [docs/001_shared_workspace.md](docs/001_shared_workspace.md) | Shared Workspace仕様 |
| [docs/002_common_schema.md](docs/002_common_schema.md) | 共通スキーマ定義 |
| [docs/003_passer.md](docs/003_passer.md) | 正規化エンジン仕様 |
| [docs/004_patch_protocol.md](docs/004_patch_protocol.md) | Patchプロトコル仕様 |
| [docs/tool_manifest.yaml](docs/tool_manifest.yaml) | 使用可能なツール一覧 |

### エージェント仕様

| エージェント | 仕様書 |
|-------------|--------|
| Orchestrator | [.claude/agents/pentest-orchestrator.md](.claude/agents/pentest-orchestrator.md) |
| Reconnaissance | [.claude/agents/reconnaissance-agent.md](.claude/agents/reconnaissance-agent.md) |
| Enumeration | [.claude/agents/enumeration-agent.md](.claude/agents/enumeration-agent.md) |
| Planner | [.claude/agents/planner-agent.md](.claude/agents/planner-agent.md) |
| Exploitation | [.claude/agents/exploitation-agent.md](.claude/agents/exploitation-agent.md) |

## 注意事項

- このシステムは**許可されたターゲット**に対してのみ使用してください
- すべてのペネトレーションテストは適切な承認を得た上で実施してください
- 無差別スキャン、DoS攻撃、データ持ち出しは禁止されています

## ライセンス

MIT License - 詳細は [LICENSE](LICENSE) を参照してください。

## コントリビューション

Issue報告やPull Requestを歓迎します。詳細は [CONTRIBUTING.md](CONTRIBUTING.md) を参照してください。
