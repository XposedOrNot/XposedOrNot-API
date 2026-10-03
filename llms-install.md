# Installing the XposedOrNot MCP Server

XposedOrNot is a **hosted, remote MCP server** — there is nothing to download,
build, or run locally, and no API key or authentication is required. All tools
are read-only and rate-limited per IP.

- **Endpoint:** `https://api.xposedornot.com/mcp`
- **Transport:** Streamable HTTP (JSON-RPC 2.0 over POST)
- **Authentication:** none
- **Server card:** `https://api.xposedornot.com/.well-known/mcp/server-card.json`

## Tools

| Tool | What it does |
|------|--------------|
| `check_email_breaches` | Check if an email appears in known breaches (names only, never passwords) |
| `get_breach_analytics` | Detailed breach history, risk score and paste exposure for an email |
| `list_breaches` | Browse the breach catalog, filter by domain or breach ID |
| `domain_breach_summary` | Aggregate breach counts for a domain |
| `get_breach_metrics` | System-wide breach statistics |
| `get_recent_breaches` | Most recently added breaches, newest first |

## Cline

Add this to your `cline_mcp_settings.json` (MCP Servers → Configure MCP Servers):

```json
{
  "mcpServers": {
    "xposedornot": {
      "url": "https://api.xposedornot.com/mcp",
      "type": "streamableHttp"
    }
  }
}
```

## Claude Code

```bash
claude mcp add --transport http xposedornot https://api.xposedornot.com/mcp
```

Or open this repository — it ships a `.mcp.json` that offers the server
automatically.

## Cursor

Add to `.cursor/mcp.json` (project) or `~/.cursor/mcp.json` (global):

```json
{
  "mcpServers": {
    "xposedornot": {
      "url": "https://api.xposedornot.com/mcp"
    }
  }
}
```

## Gemini CLI

```bash
gemini extensions install https://github.com/XposedOrNot/XposedOrNot-API
```

## Any other MCP client

Point the client at `https://api.xposedornot.com/mcp` with the Streamable HTTP
transport. No environment variables, secrets, or local processes are needed.

## Verify it works

```bash
curl -X POST https://api.xposedornot.com/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

A successful install returns a JSON-RPC response listing the six tools above.

## Troubleshooting

- **HTTP 405 on GET** — expected; the endpoint only accepts POST.
- **HTTP 429** — per-IP rate limit reached; the JSON-RPC error includes a
  `retry_after` hint in seconds.
- **`-32700` parse error** — the request body was not valid JSON.
