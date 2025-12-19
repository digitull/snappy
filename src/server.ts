import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

// Base URL of your Snaptask Adaptive app
const SNAPTASK_BASE_URL =
  process.env.SNAPTASK_BASE_URL ?? "https://ma64ers93d.adaptive.ai";

// Optional default token (admin/operator can set on Alpic, but not required)
const DEFAULT_SNAPTASK_API_TOKEN = process.env.SNAPTASK_API_TOKEN;

// Store tokens per MCP session (scales to many users concurrently)
const tokenBySessionId = new Map<string, string>();

function maskToken(token: string) {
  const t = token.trim();
  if (t.length <= 8) return "********";
  return `${t.slice(0, 3)}…${t.slice(-4)}`;
}

function getHeaderValue(headers: any, key: string): string | undefined {
  if (!headers) return undefined;

  // Try a few shapes:
  // - plain object: headers["mcp-session-id"]
  // - Headers-like: headers.get("mcp-session-id")
  // - Node/Express-ish: headers["Mcp-Session-Id"] etc.
  const lowerKey = key.toLowerCase();

  if (typeof headers.get === "function") {
    const v = headers.get(key) ?? headers.get(lowerKey);
    return v ? String(v) : undefined;
  }

  // Plain object case-insensitive scan
  const entries = Object.entries(headers);
  for (const [k, v] of entries) {
    if (String(k).toLowerCase() === lowerKey) {
      if (Array.isArray(v)) return v[0] ? String(v[0]) : undefined;
      return v ? String(v) : undefined;
    }
  }

  return undefined;
}

function getSessionId(extra: any): string | undefined {
  const headers =
    extra?.requestInfo?.headers ??
    extra?.request?.headers ??
    extra?.headers ??
    undefined;

  // MCP session header names seen in the wild
  return (
    getHeaderValue(headers, "mcp-session-id") ||
    getHeaderValue(headers, "Mcp-Session-Id") ||
    getHeaderValue(headers, "mcp-sessionId") ||
    getHeaderValue(headers, "x-mcp-session-id")
  );
}

function getEffectiveToken(opts: { apiTokenOverride?: string; sessionId?: string }) {
  const override = opts.apiTokenOverride?.trim();
  if (override) return override;

  const sid = opts.sessionId;
  if (sid) {
    const sessionToken = tokenBySessionId.get(sid)?.trim();
    if (sessionToken) return sessionToken;
  }

  const envToken = DEFAULT_SNAPTASK_API_TOKEN?.trim();
  if (envToken) return envToken;

  return undefined;
}

function missingTokenError() {
  return new Error(
    [
      "SnapTask MCP needs your API token.",
      'Run the tool "set_snaptask_api_token" in ChatGPT and paste your token, then try again.',
    ].join(" "),
  );
}

// Helper for calling Snaptask RPCs
async function callSnaptaskRpc<T>(
  rpcName: string,
  params: unknown = {},
  opts: { apiTokenOverride?: string; sessionId?: string } = {},
): Promise<T> {
  const apiToken = getEffectiveToken(opts);
  if (!apiToken) throw missingTokenError();

  const url = new URL(`/api/rpc/${rpcName}`, SNAPTASK_BASE_URL);

  const baseParams =
    params && typeof params === "object" && !Array.isArray(params) ? params : {};

  const paramsWithToken = {
    ...(baseParams as Record<string, unknown>),
    apiToken,
  };

  const res = await fetch(url.toString(), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ params: [paramsWithToken] }),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(
      `Snaptask RPC ${rpcName} failed: ${res.status} ${res.statusText} ${text}`,
    );
  }

  return (await res.json()) as T;
}

export const getServer = (): McpServer => {
  const server = new McpServer(
    { name: "snaptask-mcp-server", version: "0.1.0" },
    { capabilities: {} },
  );

  // 1) User sets token once (stored per-session)
  server.tool(
    "set_snaptask_api_token",
    "Set your SnapTask API token for this ChatGPT session (saved only while the MCP server is running).",
    {
      apiToken: z
        .string()
        .min(10)
        .describe("Your SnapTask personal API token (paste it here)."),
    },
    async ({ apiToken }, extra: any): Promise<CallToolResult> => {
      const sessionId = getSessionId(extra) ?? "global";
      tokenBySessionId.set(sessionId, apiToken.trim());

      return {
        content: [
          {
            type: "text",
            text: `Saved your SnapTask token for this session (${sessionId === "global" ? "no session-id detected" : "session-id detected"}). Token: ${maskToken(apiToken)}`,
          },
        ],
      };
    },
  );

  server.tool(
    "clear_snaptask_api_token",
    "Clear your SnapTask API token for this ChatGPT session.",
    {},
    async (_args, extra: any): Promise<CallToolResult> => {
      const sessionId = getSessionId(extra) ?? "global";
      tokenBySessionId.delete(sessionId);

      return {
        content: [
          {
            type: "text",
            text: `Cleared SnapTask token for this session.`,
          },
        ],
      };
    },
  );

  // Optional token override field (rarely needed; useful for debugging)
  const optionalTokenField = {
    apiToken: z
      .string()
      .optional()
      .describe(
        "Optional SnapTask API token override for this call. If omitted, uses the token you set via set_snaptask_api_token.",
      ),
  };

  server.tool(
    "list_today_tasks",
    "List today's tasks from Snaptask for the current user",
    { ...optionalTokenField },
    async ({ apiToken }, extra: any): Promise<CallToolResult> => {
      const sessionId = getSessionId(extra);
      const tasks = await callSnaptaskRpc<unknown[]>(
        "mcpListTodayTasks",
        {},
        { apiTokenOverride: apiToken, sessionId },
      );

      return { content: [{ type: "text", text: JSON.stringify(tasks, null, 2) }] };
    },
  );

  server.tool(
    "list_week_overview",
    "Get a high-level overview of this week's tasks from Snaptask",
    { ...optionalTokenField },
    async ({ apiToken }, extra: any): Promise<CallToolResult> => {
      const sessionId = getSessionId(extra);
      const overview = await callSnaptaskRpc<unknown>(
        "mcpListWeekOverview",
        {},
        { apiTokenOverride: apiToken, sessionId },
      );

      return {
        content: [{ type: "text", text: JSON.stringify(overview, null, 2) }],
      };
    },
  );

  server.tool(
    "create_tasks_from_text",
    "Create one or more Snaptask tasks from a natural-language description",
    {
      ...optionalTokenField,
      text: z
        .string()
        .describe(
          "Natural language description of what needs to be done (can contain multiple tasks).",
        ),
    },
    async ({ text, apiToken }, extra: any): Promise<CallToolResult> => {
      const sessionId = getSessionId(extra);
      const created = await callSnaptaskRpc<unknown>(
        "mcpCreateTasksFromText",
        { text },
        { apiTokenOverride: apiToken, sessionId },
      );

      return {
        content: [{ type: "text", text: JSON.stringify(created, null, 2) }],
      };
    },
  );

  server.tool(
    "update_task_status",
    "Update the status of a Snaptask task",
    {
      ...optionalTokenField,
      taskId: z.string().describe("The Snaptask task ID to update"),
      status: z
        .enum(["TODO", "IN_PROGRESS", "DONE", "BLOCKED"])
        .describe("The new status for the task"),
    },
    async ({ taskId, status, apiToken }, extra: any): Promise<CallToolResult> => {
      const sessionId = getSessionId(extra);
      const result = await callSnaptaskRpc<unknown>(
        "mcpUpdateTaskStatus",
        { taskId, status },
        { apiTokenOverride: apiToken, sessionId },
      );

      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    },
  );

  server.tool(
    "suggest_next_tasks",
    "Ask Snaptask to suggest the best next tasks to work on",
    {
      ...optionalTokenField,
      limit: z
        .number()
        .int()
        .min(1)
        .max(20)
        .optional()
        .default(5)
        .describe("Maximum number of suggested tasks to return"),
    },
    async ({ limit, apiToken }, extra: any): Promise<CallToolResult> => {
      const sessionId = getSessionId(extra);
      const suggestions = await callSnaptaskRpc<unknown[]>(
        "mcpSuggestNextTasks",
        { limit },
        { apiTokenOverride: apiToken, sessionId },
      );

      return {
        content: [{ type: "text", text: JSON.stringify(suggestions, null, 2) }],
      };
    },
  );

  server.tool(
    "greet",
    "Simple greeting tool to verify the MCP server is working",
    { name: z.string().describe("Name to greet") },
    async ({ name }): Promise<CallToolResult> => {
      return {
        content: [
          { type: "text", text: `Hello, ${name}! The Snaptask MCP server is running.` },
        ],
      };
    },
  );

  return server;
};
