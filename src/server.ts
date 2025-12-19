import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

// Base URL of your Snaptask Adaptive app
const SNAPTASK_BASE_URL =
  process.env.SNAPTASK_BASE_URL ?? "https://ma64ers93d.adaptive.ai";

// Personal API token for SnapTask (per MCP server/user environment)
const SNAPTASK_API_TOKEN = process.env.SNAPTASK_API_TOKEN;

// Helper for calling Snaptask RPCs
async function callSnaptaskRpc<T>(
  rpcName: string,
  params: unknown = {},
): Promise<T> {
  if (!SNAPTASK_API_TOKEN) {
    throw new Error(
      "Missing SNAPTASK_API_TOKEN. Set it in your environment so MCP calls can authenticate to SnapTask.",
    );
  }

  const url = new URL(`/api/rpc/${rpcName}`, SNAPTASK_BASE_URL);

  const baseParams =
    params && typeof params === "object" && !Array.isArray(params) ? params : {};

  const paramsWithToken = {
    ...(baseParams as Record<string, unknown>),
    apiToken: SNAPTASK_API_TOKEN,
  };

  const res = await fetch(url.toString(), {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
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
    {
      name: "snaptask-mcp-server",
      version: "0.1.0",
    },
    { capabilities: {} },
  );

  // List today's tasks
  server.tool(
    "list_today_tasks",
    "List today's tasks from Snaptask for the current user",
    {},
    async (): Promise<CallToolResult> => {
      const tasks = await callSnaptaskRpc<unknown[]>("mcpListTodayTasks");

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(tasks, null, 2),
          },
        ],
      };
    },
  );

  // Week overview
  server.tool(
    "list_week_overview",
    "Get a high-level overview of this week's tasks from Snaptask",
    {},
    async (): Promise<CallToolResult> => {
      const overview = await callSnaptaskRpc<unknown>("mcpListWeekOverview");

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(overview, null, 2),
          },
        ],
      };
    },
  );

  // Create tasks from natural language
  server.tool(
    "create_tasks_from_text",
    "Create one or more Snaptask tasks from a natural-language description",
    {
      text: z
        .string()
        .describe(
          "Natural language description of what needs to be done (can contain multiple tasks).",
        ),
    },
    async ({ text }): Promise<CallToolResult> => {
      const created = await callSnaptaskRpc<unknown>("mcpCreateTasksFromText", {
        text,
      });

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(created, null, 2),
          },
        ],
      };
    },
  );

  // Update task status
  server.tool(
    "update_task_status",
    "Update the status of a Snaptask task",
    {
      taskId: z.string().describe("The Snaptask task ID to update"),
      status: z
        .enum(["TODO", "IN_PROGRESS", "DONE", "BLOCKED"])
        .describe("The new status for the task"),
    },
    async ({ taskId, status }): Promise<CallToolResult> => {
      const result = await callSnaptaskRpc<unknown>("mcpUpdateTaskStatus", {
        taskId,
        status,
      });

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    },
  );

  // Suggest next tasks
  server.tool(
    "suggest_next_tasks",
    "Ask Snaptask to suggest the best next tasks to work on",
    {
      limit: z
        .number()
        .int()
        .min(1)
        .max(20)
        .optional()
        .default(5)
        .describe("Maximum number of suggested tasks to return"),
    },
    async ({ limit }): Promise<CallToolResult> => {
      const suggestions = await callSnaptaskRpc<unknown[]>(
        "mcpSuggestNextTasks",
        { limit },
      );

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(suggestions, null, 2),
          },
        ],
      };
    },
  );

  // Simple sanity-check tool
  server.tool(
    "greet",
    "Simple greeting tool to verify the MCP server is working",
    {
      name: z.string().describe("Name to greet"),
    },
    async ({ name }): Promise<CallToolResult> => {
      return {
        content: [
          {
            type: "text",
            text: `Hello, ${name}! The Snaptask MCP server is running.`,
          },
        ],
      };
    },
  );

  return server;
};
