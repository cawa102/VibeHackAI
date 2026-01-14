# VibeHackAI 追加実装 依頼書（半自動対話型ペネトレーションテスト支援ツール）

## 1. 背景と目的
VibeHackAI は、人間（テスター）が絶対権限を保持し、Orchestrator と対話しながらペネトレーションテストを安全に進める半自動ツールである。実作業（計画詳細化、コマンド実行、証跡採取、レポート下書き）は AI エージェントが担当し、人間は監視・承認・停止判断を行う。

本依頼は、以下の運用方針を満たすために、現行の定義書・実装に対して追加実装（差分）を導入することを目的とする。

---

## 2. 本依頼で満たすべき運用方針（必須）
### 2.1 人間が絶対権限を持つ
- エージェントが安全理由やポリシー理由で「中止（停止）」した場合も、必ず人間へ報告する。
- 人間が許可した場合、停止した操作を **明示的な監査ログ（人間による Override）** を残した上で再開・実行できる。

### 2.2 承認粒度は「フェーズ遷移ごと」
- 人間は「コマンド個別」ではなく「フェーズ開始（次フェーズへ進む）」の単位で承認する。
- 目的は、誤った方向に自動で進むことの防止、およびトレーサビリティ向上。

### 2.3 Orchestrator は人間に“何をするか”を自然言語で説明（コマンド非表示）
- 例：人間提示は「Target IP に対してスキャンを行い開いているポートを確認します」等。
- 実際に実行したコマンド文字列は、監査・再現性のため Evidence として保存するが、通常UI/通常出力では人間に表示しない（必要時のみ詳細表示）。

### 2.4 レポートは OPTRS/OWASP 風 + CVSS 付き
- Findings は OPTRS/OWASP を意識した構造（再現手順、影響、対策、証拠、評価）を持つこと。
- CVSS（バージョンとベクタ）に基づく評価を必ず付与する。

### 2.5 Exploit 成功証明は「限定的なファイル読み取り」まで許可
- ただし、許可範囲（最大バイト数・対象パス制限等）をポリシー化し、逸脱時は停止→報告→人間判断とする。

### 2.6 テスト計画ファイルを単一の正本（Source of Truth）として運用
- Planner はテスト計画ファイル（Test Plan）を作成し、以降のテストは原則として当該計画に基づいて進行する。
- 各フェーズ結果（Recon/Enum/Exploit）を受けて Planner が計画を再構築する際は、Test Plan を随時更新し、更新履歴を監査可能な形で残す。

### 2.7 作成されたファイルは, ターゲットごとにフォルダ分け
-	同一プロジェクト内のエビデンス参照時の混乱を避けるために, ターゲットごとにフォルダ化し, その中に保存する

---

## 3. スコープ
### 3.1 対象コンポーネント
- Orchestrator（状態管理、フェーズ制御、承認、UI/対話、監査ログ）
- Planner（フェーズ計画の再構築、自然言語説明の生成ソース）
- Reconnaissance / Enumeration / Exploitation 各エージェント
- スキーマ（state.json / scope.json / evidence / findings / plan 等）
- レポート生成（reports/draft.md 等）

### 3.2 非対象（本依頼の非ゴール）
- 新規の攻撃技術・マルウェア開発機能の追加
- 権限のない対象へのテストを可能にする機能
- 既存外部ツール（Hexstrike 等）の内部実装改修（ただし設定・ガードレール連携は対象）

---

## 4. 共通定義（用語）
- **Phase（フェーズ）**：Planner / Recon / Enum / Exploit の単位。  
- **PhaseBrief（人間提示用）**：次フェーズで「何をするか」「なぜ」「リスク」「制約」を自然言語で示す要約。コマンド非表示。
- **PhasePlan（実行用計画）**：内部で実行に必要な抽象計画。ツール選択や制約を含む。
- **Evidence（証跡）**：実行ログ、出力、スクリーンショット参照、ハッシュ等。再現性の根拠。
- **Override（人間の上書き許可）**：停止・制限を解除して続行する明示的な許可。監査ログ必須。

---

## 5. 機能要件（Functional Requirements）
### FR-1：フェーズ境界承認フローの実装（必須）
- Orchestrator は、各フェーズ開始前に **必ず PhaseBrief を人間へ提示**し、承認/拒否/保留を取得する。
- 承認されるまで、当該フェーズのエージェント実行を開始しない。
- フェーズ完了時は、結果を state に反映→Planner に渡して次フェーズ PhasePlan を再構築→次フェーズ承認へ進む。

**受入条件**
- いかなるフェーズも、承認なしに開始されない。
- すべてのフェーズ開始に、承認記録（誰が、いつ、何を承認したか）が残る。

---

### FR-2：Orchestrator の「自然言語サマリ提示（コマンド非表示）」モード（必須）
- 人間への提示は PhaseBrief のみ（自然言語）。
- 実行コマンド、パラメータは Evidence/監査ログに保存するが、標準表示はしない。
- UI/出力に「詳細表示（監査用）」切替を用意し、必要時のみ Evidence 内のコマンドを参照可能にする。

**受入条件**
- 標準出力・標準UIではコマンド文字列が表示されない。
- 証跡としてはコマンドが保存され、再現可能性が担保される。

---

### FR-3：Policy Escalation（想定外の高リスク操作）時の停止・報告・追加承認（必須）
- フェーズ中に、PhaseBrief/PhasePlan に含まれない高リスク操作（例：強度の高いスキャン、侵襲が上がる行為、ファイル読み取り上限超え等）が必要になった場合：
  1) エージェントは Orchestrator に **Escalation** を通知  
  2) Orchestrator は実行を停止し、人間へ「追加の PhaseBrief（差分）」を提示  
  3) 人間が承認した場合のみ続行（拒否なら停止維持）
- 既存の `requires_approval` がある場合は、「コマンド逐次承認」ではなく **“逸脱時のエスカレーションフラグ”** として再定義する。

**受入条件**
- 逸脱操作は自動で実行されず、必ず停止→追加承認フローへ遷移する。

---

### FR-4：人間の絶対権限（Override）をシステム共通認識として実装（必須）
- エージェントが安全上の理由で停止した場合：
  - Orchestrator は停止理由・提案（代替案）・影響を自然言語で人間へ報告する。
  - 人間は「中止継続」または「Overrideして続行」を選べる。
- Override で続行する場合：
  - `override_approved=true`、承認者、承認時刻、対象操作カテゴリ、理由を state/監査ログへ保存する。
  - 続行した操作に紐づく Evidence にも、Override の参照IDを付ける。

**例外（Override 不可の最低限境界）**
- 明確な破壊的操作（データ破壊、サービス停止、永続的改変）
- スコープ外対象へのアクセス
- “マルウェア開発/配布”に該当する行為  
（※本ツールの目的は脆弱性の立証であり悪性コード開発ではない）

**受入条件**
- 停止は必ず人間へ報告される。
- Override 実施時は監査ログが残り、後から追跡可能である。

---

### FR-5：Proof-of-Access Policy（限定的ファイル読み取り）のポリシー化（必須）
- scope（例：scope.json）に Proof-of-Access Policy を追加し、Exploitation/Orchestrator が強制できるようにする。
- 例：最大ファイル数、最大バイト数、禁止パス/拡張子、優先カナリアファイル等。
- 超過・逸脱が必要になった場合は FR-3 の Escalation によって停止→人間判断。

**受入条件**
- 許可範囲内でのみ file read が実行される。
- 上限超過を検知して停止できる。

---

### FR-6：Planner の責務強化（フェーズごとの意思決定・説明生成）（必須）
- Planner は「Exploit計画」だけではなく、「ペネトレーションテスト全体の計画」を行い, **各フェーズ完了後に必ず次フェーズの PhasePlan を再構築**する。
- Planner の出力に、人間提示用の `human_summary`（自然言語）を追加し、Orchestrator の PhaseBrief のソースとする。
- Planner が直接ツール実行しない設計を明確化（tool指定があっても“実行は他エージェント”）。

**受入条件**
- 各フェーズ完了後、Planner が呼ばれて次フェーズの PhasePlan が更新される。
- PhaseBrief が Planner の意思決定に基づいて生成される。

---

### FR-7：CVSS を「version + vector + score」のオブジェクトとして実装（必須）
- VulnCandidate / FindingCandidate 等に `cvss` フィールドを追加（または既存を置換）：
  - `version`（例：3.1 / 4.0 等）
  - `vector`（例：CVSS:3.1/...）
  - `base_score`（数値）
- レポート生成において、各 Finding に CVSS を必ず表示する。
- Planner は **テスト計画ファイル（Test Plan）を生成・維持**する。
  - セッション開始時に初版を作成する（スコープ、目的、フェーズ順序、想定手段、制約、停止条件、証跡方針を含む）。
  - 各フェーズ完了後に結果を反映し、優先順位・次フェーズの目的・安全制約・未解決課題を更新する。
  - 計画更新は差分（Patch）で行い、更新履歴（誰が/いつ/何を/なぜ）を監査ログとして残す。
- Orchestrator はフェーズ承認時に、PhaseBrief と合わせて **Test Plan の「今回更新差分（変更点要約）」** を人間に提示する（コマンド非表示のまま）。

**受入条件**
- すべての最終 Findings に CVSS（version, vector, score）が付与される。
- 未確定時の扱い（暫定/要確認）もレポートに明記される。
- セッション開始時に Test Plan ファイルが生成される。
- 各フェーズ完了後、Test Plan が更新され、変更履歴が追跡できる。
- 次フェーズ承認時に、人間へ Test Plan の変更点要約が提示される。

---

### FR-8：OPTRS/OWASP 風レポート出力（必須）
- `reports/draft.md`（または同等）に以下の構造で出力：
  - Executive Summary（概要、スコープ、重要所見）
  - Methodology（フェーズ、使用ツール、承認モデル）
  - Findings（各脆弱性：概要、影響、再現手順、Evidence、CVSS、対策、検証条件）
  - Appendix（詳細ログ参照、Evidence ID 一覧、（任意）コマンド詳細）
- コマンドは標準では本文に出さず、Appendix で参照可能にする（または Evidence ID のみ）。

**受入条件**
- 上記章立てに準拠したドラフトが自動生成される。
- Findings には Evidence ID が紐づく。

---

## 6. データモデル／スキーマ変更（要点）
以下は「追加・変更」項目であるが, 実装は要検討すること。実際のファイル名は現行実装に合わせる。

1) `phase_plan`（新規または拡張）
- `phase`, `objective`, `human_summary[]`, `constraints{...}`, `risk_notes[]`

2) `phase_brief`（生成物：保存しても良い）
- `phase_to_approve`, `planned_actions[]`, `risk_notes[]`, `safety_limits{...}`, `evidence_policy`

3) `approval_log`（新規）
- `phase`, `brief_id`, `approved_by`, `approved_at`, `decision`, `notes`

4) `override_log`（新規）
- `override_id`, `reason`, `approved_by`, `approved_at`, `category`, `linked_evidence_ids[]`, `linked_phase`

5) `proof_of_access_policy`（scope 拡張）
- `allow_file_read`, `max_bytes`, `max_files`, `disallow_paths_regex[]`, `prefer_canary_file`

6) `cvss`（Finding/Vuln 拡張）
- `{version, vector, base_score}`

7) `test_plan`（新規：計画ファイル）
- `plan_id`, `version`, `updated_at`, `updated_by`
- `scope_summary`, `objectives`, `assumptions`, `constraints`, `stop_conditions`
- `phase_sequence[]`（フェーズ順序と目的）
- `open_questions[]`, `risks[]`
- `change_log[]`（差分要約、理由、関連Evidence/Findings）

---

## 7. UI/対話仕様（Orchestrator）
- 標準：自然言語のみ（PhaseBrief）
- オプション：「詳細表示」トグルで Evidence（コマンド含む）閲覧可能
- 停止イベント（AgentStop/Escalation）は必ず人間に通知し、選択肢を提示：
  - 中止（停止維持）
  - 追加承認（差分 PhaseBrief を承認して続行）
  - Override（許可可能カテゴリの場合のみ）

---

## 8. 監査・ログ・トレーサビリティ要件
- すべてのフェーズ承認・停止・Override は監査ログに残すこと（時刻、主体、理由、関連Evidence）
- レポートは Evidence ID を介して証跡へリンク可能な構造にする

---

## 9. テスト要件（受入テストの観点）
以下のシナリオが自動/手動で検証可能であること。

1) フェーズ開始が承認なしに走らない
2) フェーズ中に逸脱操作が要求された場合に停止→差分承認に遷移する
3) エージェント停止が必ず報告され、Override/継続中止を選べる
4) Override 実施時に監査ログと Evidence がリンクされる
5) Proof-of-Access Policy 上限超過がブロックされる
6) レポートに CVSS version/vector/score が出力される
7) レポートが OPTRS/OWASP 風構造を満たす

以上
