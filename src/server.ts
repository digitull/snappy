import express from "express";
import cors from "cors";
import { nanoid } from "nanoid";
import { z } from "zod";
import { MCP_API_KEY, PORT, REQUIRE_API_KEY } from "./config.js";

type JsonRpcRequest = {
  jsonrpc?: "2.0";
  id?: string | number | null;
  method?: string;
  params?: any;
};

type Task = {
  id: string;
  title: string;
  status: "open" | "completed";
  dueAt?: string | null;
  priority?: string | null;
  notes?: string | null;
  createdAt: string;
  updatedAt: string;
};

const tasksByNamespace = new Map<string, Task[]>();

function getNamespace(req: express.Request) {
  // We isolate tasks by token so different users/keys don’t share state.
  // If no auth is configured, we put everyone in a "public" namespace.
  if (!REQUIRE_API_KEY) return "public";
  const token = String(req.header("x-api-key") || "").trim();
  return token || "unknown";
}

function getTasks(ns: string) {
  const existing = tasksByNamespace.get(ns);
  if (existing) return existing;
  const created: Task[] = [];
  tasksByNamespace.set(ns, created);
  return created;
}

function jsonRpcResult(id: any, result: any) {
  return { jsonrpc: "2.0" as const, id, result };
}

function jsonRpcError(id: any, message: string, code = -32000) {
  return { jsonrpc: "2.0" as const, id, error: { code, message } };
}

const toolsList = [
  {
    name: "list_tasks",
    description: "List tasks by status (open or completed).",
    inputSchema: {
      type: "object",
      properties: {
        status: { type: "string", enum: ["open", "completed"] }
      },
      additionalProperties: true
    }
  },
  {
    name: "create_task",
    description: "Create a task with title and optional dueAt (ISO string).",
    inputSchema: {
      type: "object",
      properties: {
        title: { type: "string" },
        dueAt: { type: "string" }
      },
      required: ["title"],
      additionalProperties: true
    }
  },
  {
    name: "update_task",
    description: "Update task fields like title, dueAt, status, notes, priority.",
    inputSchema: {
      type: "object",
      properties: {
        taskId: { type: "string" },
        title: { type: "string" },
        dueAt: { type: "string" },
        status: { type: "string", enum: ["open", "completed"] },
        completed: { type: "boolean" },
        notes: { type: "string" },
        priority: { type: "string" }
      },
      required: ["taskId"],
      additionalProperties: true
    }
  },
  {
    name: "complete_task",
    description: "Mark a task completed by id.",
    inputSchema: {
      type: "object",
      properties: {
        taskId: { type: "string" }
      },
      required: ["taskId"],
      additionalProperties: true
    }
  }
] as const;

const toolCallSchema = z.object({
  name: z.string(),
  arguments: z.record(z.any()).optional()
});

function normalizeStatus(input: any): "open" | "completed" {
  const v = String(input || "").toLowerCase().trim();
  if (v === "completed" || v === "done") return "completed";
  return "open";
}

export function startServer() {
  const app = express();

  app.use(cors());
  app.use(express.json({ limit: "2mb" }));

  // Health endpoint (NOT protected)
  app.get("/", (_req: express.Request, res: express.Response) => {
    res.json({
      ok: true,
      service: "snaptask-mcp-server",
      mcpEndpoint: "/mcp",
      auth: REQUIRE_API_KEY ? "x-api-key required on /mcp" : "open (no auth)",
      time: new Date().toISOString()
    });
  });

  // Protect ONLY /mcp and only when MCP_API_KEY is set
  app.use("/mcp", (req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (!REQUIRE_API_KEY) return next();
    const token = String(req.header("x-api-key") || "").trim();
    if (!token || token !== MCP_API_KEY) {
      return res.status(401).json({
        error: "Unauthorized. Provide header x-api-key."
      });
    }
    next();
  });

  // MCP JSON-RPC endpoint (POST only)
  app.post("/mcp", async (req: express.Request, res: express.Response) => {
    const body = req.body as JsonRpcRequest;

    const id = body?.id ?? null;
    const method = body?.method;

    if (!method || typeof method !== "string") {
      return res.status(400).json(jsonRpcError(id, "Invalid JSON-RPC method", -32600));
    }

    const ns = getNamespace(req);
    const tasks = getTasks(ns);

    try {
      // Minimal MCP compatibility calls (used by SnapTask Relay “Test Connection”)
      if (method === "initialize") {
        return res.json(
          jsonRpcResult(id, {
            protocolVersion: "2024-11-05",
            serverInfo: {
              name: "snaptask-mcp-server",
              version: "1.0.0"
            },
            capabilities: {
              tools: {}
            }
          })
        );
      }

      if (method === "tools/list") {
        return res.json(jsonRpcResult(id, { tools: toolsList }));
      }

      if (method === "tools/call") {
        const parsed = toolCallSchema.safeParse(body?.params);
        if (!parsed.success) {
          return res.json(jsonRpcError(id, "Invalid tools/call params", -32602));
        }

        const toolName = parsed.data.name;
        const args = parsed.data.arguments ?? {};

        if (toolName === "list_tasks") {
          const status = args?.status ? normalizeStatus(args.status) : "open";
          const filtered =
            status === "completed"
              ? tasks.filter((t) => t.status === "completed")
              : tasks.filter((t) => t.status !== "completed");

          return res.json(jsonRpcResult(id, { tasks: filtered }));
        }

        if (toolName === "create_task") {
          const title = String(args?.title || "").trim();
          if (!title) return res.json(jsonRpcError(id, "title is required", -32602));

          const nowIso = new Date().toISOString();
          const t: Task = {
            id: nanoid(),
            title,
            status: "open",
            dueAt: args?.dueAt ? String(args.dueAt) : null,
            priority: args?.priority ? String(args.priority) : null,
            notes: args?.notes ? String(args.notes) : null,
            createdAt: nowIso,
            updatedAt: nowIso
          };

          tasks.unshift(t);
          return res.json(jsonRpcResult(id, { task: t }));
        }

        if (toolName === "update_task") {
          const taskId = String(args?.taskId || "").trim();
          if (!taskId) return res.json(jsonRpcError(id, "taskId is required", -32602));

          const found = tasks.find((t) => t.id === taskId);
          if (!found) return res.json(jsonRpcError(id, "Task not found", -32004));

          if (args?.title !== undefined) found.title = String(args.title);
          if (args?.dueAt !== undefined) found.dueAt = args.dueAt ? String(args.dueAt) : null;
          if (args?.priority !== undefined) found.priority = args.priority ? String(args.priority) : null;
          if (args?.notes !== undefined) found.notes = args.notes ? String(args.notes) : null;

          // Support both "status" and "completed" patterns
          if (args?.status !== undefined) {
            found.status = normalizeStatus(args.status);
          }
          if (args?.completed !== undefined) {
            found.status = args.completed ? "completed" : "open";
          }

          found.updatedAt = new Date().toISOString();
          return res.json(jsonRpcResult(id, { task: found }));
        }

        if (toolName === "complete_task") {
          const taskId = String(args?.taskId || "").trim();
          if (!taskId) return res.json(jsonRpcError(id, "taskId is required", -32602));

          const found = tasks.find((t) => t.id === taskId);
          if (!found) return res.json(jsonRpcError(id, "Task not found", -32004));

          found.status = "completed";
          found.updatedAt = new Date().toISOString();
          return res.json(jsonRpcResult(id, { task: found }));
        }

        return res.json(jsonRpcError(id, `Unknown tool: ${toolName}`, -32601));
      }

      return res.json(jsonRpcError(id, `Unknown method: ${method}`, -32601));
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Unknown error";
      return res.json(jsonRpcError(id, msg, -32000));
    }
  });

  app.listen(PORT, () => {
    console.log(
      `[snaptask-mcp-server] listening on :${PORT} | /mcp auth: ${
        REQUIRE_API_KEY ? "x-api-key required" : "open"
      }`
    );
  });
}
