export const PORT = Number(process.env.PORT || 3000);

export const MCP_API_KEY = (process.env.MCP_API_KEY || "").trim();

// If MCP_API_KEY is set, require x-api-key on /mcp. If it's blank, allow unauthenticated.
export const REQUIRE_API_KEY = MCP_API_KEY.length > 0;
