# SnapTask MCP Server (for SnapTask Relay)

This repo provides a minimal **MCP-over-HTTP** JSON-RPC server that works with **SnapTask Relay**.

## What SnapTask Relay expects

SnapTask Relay tests connectivity using MCP-standard calls:
- `initialize`
- `tools/list`

And it runs task actions via:
- `tools/call` with tool names like `list_tasks`, `create_task`, `update_task`, `complete_task`.

This server exposes those via:

- **POST** `/mcp`  (JSON-RPC)

## Auth: x-api-key (ONLY on /mcp)

- If `MCP_API_KEY` is **set**, then `/mcp` requires header:
  - `x-api-key: <MCP_API_KEY>`
- If `MCP_API_KEY` is **empty**, `/mcp` is open.

Important: only `/mcp` is protected. The `/` route is just health info.

## Local development

```bash
npm install
cp .env.example .env
npm run dev
