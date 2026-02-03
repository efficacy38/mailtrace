# Cluster Flow Conservation Check

## Overview

給定一個 cluster（一組 mail server hosts）和時間範圍，檢查每一封進入 cluster 的郵件是否都到達了 terminal state（成功送達或離開 cluster）。

核心原則：不是比較 inflow 數量 == outflow 數量（因為 maillist/.forward 會展開），而是確認**每封 inbound mail 都到達了 terminal state**。

## 術語定義

- **Inbound mail**: 從 cluster 外部進入 cluster 的郵件（由 `postfix/smtpd` 的 `client=hostname[ip]` 判斷，且 hostname/IP 不屬於 cluster 成員）
- **Complete flow**: 郵件到達 terminal state — 在 cluster 內 local delivery 或 relay 到 cluster 外部
- **Problematic flow**: 郵件未到達 terminal state — bounce、stuck in queue、dropped 或 trace lost

## Terminal State 分類

| Log Service | Message Pattern | State | Category |
|---|---|---|---|
| `postfix/local` | `status=sent` 或 `status=delivered` | Delivered locally | **Complete** |
| `postfix/virtual` | `status=sent` 或 `status=delivered` | Delivered locally | **Complete** |
| `postfix/smtp` 或 `postfix/lmtp` | `relay=<non-cluster-host>` + SMTP 250 | Relayed out | **Complete** |
| `postfix/bounce` | any | Bounced | **Problematic** |
| 以上皆非 | — | Incomplete | **Problematic** |

## Maillist / .forward 展開處理

當一封郵件觸發 maillist 或 `.forward`，一個 mail ID 可能會在同一台 host 上產生多個 outbound mail ID。

處理方式：
1. 查詢該 mail ID 的所有 log entries
2. 如果有多個 `postfix/smtp` 或 `postfix/lmtp` relay entries（各自有不同的 `queued as` ID），追蹤每一條分支
3. 形成 trace tree 而非 trace chain
4. Inbound mail 只有在**所有 leaf nodes 都到達 terminal state** 時才算 complete

需要新增 `do_trace_all()` 函數（收集所有 relay matches，不只第一個）。

## 介面設計

### MCP Tool

```python
mailtrace_check_flow(
    host: str,                     # cluster 名稱或單一 host
    time: str | None = None,       # 參考時間 "YYYY-MM-DD HH:MM:SS"，預設當前時間
    time_range: str = "1h",        # 時間範圍，預設 1h
    keywords: list[str] | None = None  # 可選：過濾特定 email/domain
)
```

### CLI Command

```bash
# 基本用法（使用當前時間，預設 1h）
mailtrace flow-check -h mx-cluster

# 指定時間範圍
mailtrace flow-check -h mx-cluster -r 2h

# 指定時間 + 範圍
mailtrace flow-check -h mx-cluster -t "2025-01-15 10:00:00" -r 1h

# 加上 keyword 過濾
mailtrace flow-check -h mx-cluster -t "2025-01-15 10:00:00" -r 1h -k user@example.com

# JSON 輸出
mailtrace flow-check -h mx-cluster --json
```

## 輸出格式

```json
{
  "cluster": "mx-cluster",
  "time": "2025-01-15 10:00:00",
  "time_range": "1h",
  "keywords": null,
  "out_of_window_mail_ids": ["JKL012", "XYZ789"],
  "summary": {
    "total_inbound": 10,
    "complete": 7,
    "problematic": 3
  },
  "complete_flows": [
    {
      "inbound_mail_id": "ABC123",
      "source": "external-sender.com",
      "terminal_state": "delivered_locally",
      "branches": 1
    }
  ],
  "problematic_flows": [
    {
      "inbound_mail_id": "DEF456",
      "source": "another-sender.com",
      "terminal_state": "bounced",
      "last_seen_host": "mail-relay-2",
      "last_seen_mail_id": "GHI789"
    },
    {
      "inbound_mail_id": "JKL012",
      "source": "sender.org",
      "terminal_state": "incomplete",
      "last_seen_host": "mail-delivery",
      "last_seen_mail_id": "MNO345",
      "expanded_branches": 3,
      "incomplete_branches": 1
    }
  ]
}
```

## 需要修改的檔案

### 新增

1. **`mailtrace/flow_check.py`** — 核心 flow conservation 邏輯
   - `identify_inbound_mails()`: 查詢 cluster 內所有 host 的 log，找出從外部進入的 mail IDs
   - `classify_terminal_state()`: 分析 mail ID 的 log entries，判斷 terminal state
   - `do_trace_all()`: 類似 `do_trace()` 但回傳所有 relay matches（處理展開）
   - `check_flow()`: 主函數 — 串接上述步驟，回傳 flow check 結果

### 修改

2. **`mailtrace/graph.py`** — 在 node 上加上 terminal state metadata
   - 新增 `add_terminal_node()` 方法，記錄 terminal state type

3. **`mailtrace/mcp/tools.py`** — 新增 `mailtrace_check_flow` tool 定義

4. **`mailtrace/cli.py`** — 新增 `flow-check` CLI 子命令

### 不修改

- `aggregator/__init__.py` 的現有 `do_trace()` — 保持不動
- `trace.py` 的現有 `trace_mail_flow()` — 保持不動
- `mcp/tools.py` 的現有 tools — 保持不動

## 實作步驟

1. 新增 `flow_check.py` with `identify_inbound_mails()`
   - 解析 `postfix/smtpd` log entries 中的 `client=hostname[ip]`
   - 比對 hostname/IP 是否屬於 cluster 成員
   - 回傳 inbound mail IDs + source info

2. 新增 `do_trace_all()` in `flow_check.py`
   - 修改自 `do_trace()` 邏輯，但收集所有 relay results 而非只回傳第一個
   - 支援 tree-based tracing

3. 新增 `classify_terminal_state()` in `flow_check.py`
   - 查詢 final mail ID 的 log entries
   - 根據 service + message pattern 判斷 state

4. 新增 `check_flow()` 主函數
   - 串接 identify → trace → classify
   - 產生結構化輸出

5. 修改 `graph.py` 加上 terminal state metadata

6. 新增 MCP tool `mailtrace_check_flow` in `mcp/tools.py`

7. 新增 CLI `flow-check` 子命令 in `cli.py`

## Edge Cases

- **Cluster 內部 relay**: mail 在 cluster 內 relay（host A → host B），不算 outflow，繼續追蹤
- **Maillist 展開**: 一封變多封，追蹤所有分支
- **`.forward` 展開**: 同 maillist 處理
- **Bounce**: 歸類為 problematic
- **Time range 外的 log**: 只追蹤 inbound 在時間範圍內的 mail，但 trace 本身可能跨出時間範圍（mail 在範圍內進入但稍後才 relay）。當追蹤過程中發現 log entries 超出指定的 time window 時，必須在輸出中加入 warning 提醒使用者，讓使用者知道部分結果可能不完整或需要擴大時間範圍重新查詢
- **Cluster 成員辨識**: 使用 config 中定義的 hostname + MX discovery 結果來判斷
