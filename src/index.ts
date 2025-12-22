import { getServer } from "./server.js";
import { config } from "./config.js";

const app = getServer();

app.listen(config.MCP_HTTP_PORT, (error?: any) => {
  if (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
  console.log(`Server listening on port ${config.MCP_HTTP_PORT}`);
});
