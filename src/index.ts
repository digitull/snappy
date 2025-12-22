import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new Server(
  {
    name: "snappy",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  },
);

server.setRequestHandler("tools/list", async () => {
  return {
    tools: [
      {
        name: "ping",
        description: "Health check tool (returns pong).",
        inputSchema: {
          type: "object",
          properties: {},
          additionalProperties: false,
        },
      },
    ],
  };
});

server.setRequestHandler("tools/call", async (req: any) => {
  const name = String(req?.params?.name ?? "");
  const args = (req?.params?.arguments ?? {}) as unknown;

  if (name === "ping") {
    z.object({}).parse(args);
    return {
      content: [{ type: "text", text: "pong" }],
    };
  }

  return {
    content: [{ type: "text", text: `Unknown tool: ${name}` }],
  };
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});
