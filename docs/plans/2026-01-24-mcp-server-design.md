# Mailtrace MCP Server Design

## Overview

Add an MCP (Model Context Protocol) server to mailtrace, enabling LLM assistants (Claude, etc.) to search mail logs and trace mail flows during conversations.

## CLI Interface

**New subcommand: `mailtrace mcp`**

```bash
# stdio transport (default) - for Claude Code, Cursor, etc.
mailtrace mcp --config /path/to/config.yaml

# SSE transport - for remote/shared servers
mailtrace mcp --config /path/to/config.yaml --transport sse --port 8080
```

**Options:**

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--config` / `-c` | Yes* | - | Path to mailtrace YAML config file |
| `--transport` | No | `stdio` | Transport type: `stdio` or `sse` |
| `--port` | No | `8080` | Port for SSE transport |

*Falls back to `MAILTRACE_CONFIG` environment variable if not provided.

**Startup behavior:**

1. Load and validate config file (exit with error if invalid)
2. Initialize MCP server with configured transport
3. Register tools: `query_logs` and `trace_mail`
4. Start listening for JSON-RPC requests

## MCP Tools

### Tool 1: `query_logs`

Searches mail logs by keywords (email addresses, domains) with time filtering.

**Input Schema:**

```json
{
  "name": "query_logs",
  "description": "Search mail logs by email address or domain within a time range. Returns matching log entries that can be used to find mail IDs for tracing.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "host": {
        "type": "string",
        "description": "Mail server hostname to query (must be defined in config)"
      },
      "keywords": {
        "type": "array",
        "items": { "type": "string" },
        "description": "Email addresses or domains to search for"
      },
      "time": {
        "type": "string",
        "description": "Reference time for search (format: YYYY-MM-DD HH:MM:SS)"
      },
      "time_range": {
        "type": "string",
        "description": "Time range around reference time (e.g., '10h', '30m', '1d')"
      }
    },
    "required": ["host", "keywords"]
  }
}
```

**Response Format:**

```json
{
  "entries": [
    {
      "datetime": "2025-01-24T10:00:01+08:00",
      "hostname": "mail.example.com",
      "service": "postfix/smtp",
      "mail_id": "ABC123DEF",
      "message": "to=<user@example.com>, relay=mail2.example.com[192.168.1.10]:25, status=sent",
      "queued_as": "XYZ789",
      "relay_host": "mail2.example.com",
      "relay_ip": "192.168.1.10",
      "relay_port": 25,
      "smtp_code": 250
    }
  ],
  "count": 1,
  "query": {
    "host": "mail.example.com",
    "keywords": ["user@example.com"],
    "time": "2025-01-24 10:00:00",
    "time_range": "1h"
  }
}
```

### Tool 2: `trace_mail`

Follows a mail ID through relay chain, building the complete flow graph.

**Input Schema:**

```json
{
  "name": "trace_mail",
  "description": "Trace a mail ID through the relay chain, following hops until delivery or failure. Returns the complete mail flow as a Graphviz DOT graph plus structured edge data.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "host": {
        "type": "string",
        "description": "Starting mail server hostname"
      },
      "mail_id": {
        "type": "string",
        "description": "Mail queue ID to trace (obtained from query_logs)"
      },
      "time": {
        "type": "string",
        "description": "Reference time for log search"
      },
      "time_range": {
        "type": "string",
        "description": "Time range for log search"
      }
    },
    "required": ["host", "mail_id"]
  }
}
```

**Response Format:**

```json
{
  "graph_dot": "digraph mail_flow {\n  \"mail1.example.com\" -> \"mail2.example.com\" [label=\"ABC123DEF\"];\n  \"mail2.example.com\" -> \"mail3.example.com\" [label=\"XYZ789\"];\n}",
  "nodes": ["mail1.example.com", "mail2.example.com", "mail3.example.com"],
  "edges": [
    {"from": "mail1.example.com", "to": "mail2.example.com", "mail_id": "ABC123DEF"},
    {"from": "mail2.example.com", "to": "mail3.example.com", "mail_id": "XYZ789"}
  ],
  "hop_count": 2,
  "trace": {
    "start_host": "mail1.example.com",
    "mail_id": "ABC123DEF"
  }
}
```

## Error Handling

### Error Response Format

```json
{
  "error": {
    "code": "HOST_NOT_FOUND",
    "message": "Host 'unknown.example.com' not defined in config. Available hosts: mail1.example.com, mail2.example.com"
  }
}
```

### Early Validation Errors (before execution)

| Error Code | When Checked | Description |
|------------|--------------|-------------|
| `CONFIG_ERROR` | Server startup | Config file not found or invalid |
| `HOST_NOT_FOUND` | Tool call input | Host not defined in config |
| `INVALID_TIME_FORMAT` | Tool call input | Time string doesn't match expected format |
| `INVALID_MAIL_ID` | Tool call input | Mail ID format invalid |

### Runtime Errors (during execution)

| Error Code | When Occurs | Description |
|------------|-------------|-------------|
| `CONNECTION_FAILED` | SSH/OpenSearch connect | Network or auth failure |
| `TIMEOUT` | Query execution | Operation exceeded timeout |
| `NO_RESULTS` | After query | No matching logs found |

## File Structure

```
mailtrace/
├── mcp/
│   ├── __init__.py      # MCP module exports
│   ├── server.py        # MCP server setup, tool registration
│   └── tools.py         # Tool handler implementations
└── __main__.py          # Add 'mcp' subcommand (modify existing)
```

## Dependencies

Add to `pyproject.toml`:

```toml
dependencies = [
    # ... existing deps ...
    "mcp>=1.0.0",
]
```

## Implementation Notes

### `mcp/tools.py`

Wraps existing functions:
- `query_logs` → calls `query_logs_by_keywords()` from `trace.py`
- `trace_mail` → calls `trace_mail_flow()` from `trace.py`, converts `MailGraph` to DOT + JSON

### `mcp/server.py`

- Creates MCP `Server` instance
- Registers tools with schemas
- Handles transport selection (stdio vs SSE)
- Loads config once at startup, stores in server context

### `__main__.py`

- New `mcp` Click command
- `--config`, `--transport`, `--port` options
- Calls `mcp.server.run()`

## Example Usage

### LLM Interaction Flow

1. LLM calls `query_logs`:
```json
{
  "host": "mail.example.com",
  "keywords": ["user@example.com"],
  "time": "2025-01-24 10:00:00",
  "time_range": "2h"
}
```

2. LLM receives entries, identifies mail_id `ABC123DEF`

3. LLM calls `trace_mail`:
```json
{
  "host": "mail.example.com",
  "mail_id": "ABC123DEF",
  "time": "2025-01-24 10:00:00",
  "time_range": "2h"
}
```

4. LLM receives graph, explains mail flow to user

### MCP Client Configuration (Claude Code)

```json
{
  "mcpServers": {
    "mailtrace": {
      "command": "mailtrace",
      "args": ["mcp", "--config", "/path/to/config.yaml"]
    }
  }
}
```
