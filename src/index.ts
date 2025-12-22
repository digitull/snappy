import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({
  name: "snappy",
  version: "1.0.0",
});

// Minimal tool so transport detection + tools/list works
server.tool(
  "ping",
  { message: z.string().optional() },
  async (args) => {
    const message = (args as any)?.message as string | undefined;
    return {
      content: [{ type: "text", text: message ? `pong: ${message}` : "pong" }],
    };
  }
);

await server.connect(new StdioServerTransport());
