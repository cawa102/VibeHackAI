# 003: Passer（正規化エンジン）

## 概要

各MCPサーバーの出力を共通スキーマに正規化するエンジンを実装する。

## 目的

- 異なるMCPの出力形式を統一されたスキーマに変換
- Agent/Orchestratorが一貫したデータ構造を扱えるようにする
- 出力の欠損・異常を検知

## スコープ

### インスコープ

- 各MCP出力の正規化ルール定義
- TargetProfile/Observationへの変換
- 欠損値・異常値のハンドリング

### アウトオブスコープ

- MCP呼び出し自体（各Adapterで実装）
- State更新（Patchプロトコルで実装）

## 対応MCP

| MCP | 主な出力 | 変換先スキーマ |
|-----|---------|---------------|
| filesystem | ファイル管理 | filesystem operations |
| GitHub | PoC/Exploit情報 | ExploitCandidate |
| hexstrike-ai| ツール実行結果 | ExecutionResult |

## 実装タスク

- [x] Passer基盤実装
  - [x] 正規化インターフェース定義
  - [x] MCP種別の自動判定
  - [x] エラーハンドリング共通処理
- [x] Nmap正規化
  - [x] XMLパース
  - [x] ポート/サービス/OS情報の抽出
  - [x] TargetProfile変換
- [x] Shodan正規化
  - [x] JSON応答パース
  - [x] ホスト/ポート/バナー情報抽出
  - [x] TargetProfile変換
- [x] OSINT正規化
  - [x] ドメイン情報抽出
  - [x] DNS/WHOIS情報抽出
  - [x] TargetProfile変換
- [x] Burpsuite正規化
  - [x] サイトマップ解析
  - [x] req/resペア抽出
  - [x] Observation/Evidence変換
- [x] Snyk正規化
  - [x] 脆弱性リスト解析
  - [x] CVSS/重大度マッピング
  - [x] VulnCandidate変換
- [x] CVE-research正規化
  - [x] CVE詳細解析
  - [x] 影響範囲/対策情報抽出
  - [x] VulnCandidate変換
- [x] GitHub/GitLab正規化
  - [x] リポジトリ/コード検索結果解析
  - [x] PoC/Exploit候補抽出
  - [x] ExploitCandidate変換
- [x] Metasploit正規化
  - [x] セッション/実行結果解析
  - [x] 成功/失敗判定
  - [x] ExecutionResult変換
- [x] Kali正規化
  - [x] コマンド出力解析
  - [x] ExecutionResult変換
- [x] 単体テスト
  - [x] 各MCP正規化のテスト（正常系）
  - [x] 欠損値ハンドリングテスト
  - [x] 異常値ハンドリングテスト

## 受け入れ基準

- [x] [AC-6] 各MCP出力がPasserで共通スキーマに正規化され、TargetProfile/Observationに反映される

## 依存関係

- 002_common_schema（変換先スキーマ）

## 関連ファイル

```
/src/passer/
  __init__.py
  base.py
  nmap_passer.py
  shodan_passer.py
  osint_passer.py
  burp_passer.py
  snyk_passer.py
  cve_passer.py
  github_passer.py
  msf_passer.py
  kali_passer.py

/tests/passer/
  __init__.py
  test_base.py
  test_nmap_passer.py
  test_shodan_passer.py
  test_snyk_passer.py
  test_github_passer.py
  test_msf_passer.py
  test_kali_passer.py
```

## メモ

- 各Passerはプラグイン形式で追加可能に
- 未知のフィールドは警告を出しつつ保持（情報損失防止）
- 正規化失敗時はエラーではなく部分的な結果を返す
