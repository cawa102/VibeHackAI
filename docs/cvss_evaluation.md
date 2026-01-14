**このドキュメントは、CVSS 3.1 に基づいた評価基準を示す**

---

## CVSS Evaluation Guidelines

### CVSS 3.1 評価ガイド

| メトリクス | 評価質問 | 値 |
|-----------|---------|-----|
| Attack Vector (AV) | 攻撃元はどこか？ | N=Network, A=Adjacent, L=Local, P=Physical |
| Attack Complexity (AC) | 特殊条件が必要か？ | L=Low, H=High |
| Privileges Required (PR) | 認証が必要か？ | N=None, L=Low, H=High |
| User Interaction (UI) | ユーザー操作が必要か？ | N=None, R=Required |
| Scope (S) | 影響範囲が変化するか？ | U=Unchanged, C=Changed |
| Confidentiality (C) | 機密性への影響 | N=None, L=Low, H=High |
| Integrity (I) | 完全性への影響 | N=None, L=Low, H=High |
| Availability (A) | 可用性への影響 | N=None, L=Low, H=High |

### 重大度スケール

| Base Score | 重大度 | 対応優先度 |
|------------|--------|-----------|
| 9.0 - 10.0 | Critical | 即時対応、最優先 |
| 7.0 - 8.9 | High | 優先対応 |
| 4.0 - 6.9 | Medium | 計画的対応 |
| 0.1 - 3.9 | Low | 機会があれば対応 |

---

## Feasibility Scoring

### スコア計算式

```
Feasibility Score =
    (Version Match × 0.30) +
    (PoC Availability × 0.25) +
    (Prerequisites Met × 0.20) +
    (Attack Complexity Inverse × 0.15) +
    (Impact × 0.10)
```

### 各要素の評価基準

| 要素 | 1.0 | 0.7 | 0.4 | 0.0 |
|------|-----|-----|-----|-----|
| Version Match | 完全一致 | 範囲内 | 近いバージョン | 範囲外 |
| PoC Availability | 動作確認済みPoC | 未確認PoC | 概念実証のみ | なし |
| Prerequisites Met | すべて満たす | 大部分満たす | 一部満たす | 満たさない |
| Attack Complexity | 自動化可能 | 手動で容易 | 専門知識必要 | 非常に困難 |
| Impact | Critical | High | Medium | Low |

### 優先度閾値

| スコア範囲 | 優先度 | アクション |
|-----------|--------|-----------|
| 0.80 - 1.00 | Critical | 即時ExecutionPlan作成 |
| 0.60 - 0.79 | High | ExecutionPlanに含める |
| 0.40 - 0.59 | Medium | 代替案として保留 |
| 0.00 - 0.39 | Low | 記録のみ |

