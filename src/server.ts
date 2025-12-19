import express from "express";
import crypto from "crypto";
import Database from "better-sqlite3";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

// =========================
// Config
// =========================

const BASE_URL = (process.env.PUBLIC_BASE_URL ?? "https://snappy-91c33835.alpic.live").replace(
  /\/$/,
  "",
);

// Your Snaptask Adaptive app RPC base
const SNAPTASK_BASE_URL = (process.env.SNAPTASK_BASE_URL ?? "https://ma64ers93d.adaptive.ai").replace(
  /\/$/,
  "",
);

// Optional operator default (not recommended for production, but helpful for testing)
const DEFAULT_SNAPTASK_API_TOKEN = process.env.SNAPTASK_API_TOKEN?.trim() || undefined;

// Used to sign auth codes (anti-tamper) + cookies. MUST be set in prod.
const SERVER_SECRET = process.env.SERVER_SECRET || "dev-secret-change-me";

// Port
const PORT = Number(process.env.PORT ?? 3000);

// =========================
// DB (SQLite) - persistent storage
// =========================

const db = new Database(process.env.OAUTH_DB_PATH ?? "./oauth.sqlite");
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id TEXT PRIMARY KEY,
  redirect_uris TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS connected_accounts (
  id TEXT PRIMARY KEY,
  snaptask_token TEXT NOT NULL,
  manage_token TEXT NOT NULL,
  revoked_at INTEGER
);

CREATE TABLE IF NOT EXISTS auth_codes (
  code TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL,
  scope TEXT NOT NULL,
  account_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_tokens (
  access_token TEXT PRIMARY KEY,
  refresh_token_hash TEXT NOT NULL,
  account_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  access_expires_at INTEGER NOT NULL,
  revoked_at INTEGER,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_tokens_refresh_hash ON oauth_tokens(refresh_token_hash);
`);

// =========================
// Small helpers
// =========================

function nowMs() {
  return Date.now();
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function sha256Base64Url(input: string) {
  return crypto.createHash("sha256").update(input).digest("base64url");
}

function constantTimeEqual(a: string, b: string) {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function parseAuthHeader(headerValue?: string) {
  if (!headerValue) return undefined;
  const m = headerValue.match(/^Bearer\s+(.+)$/i);
  return m?.[1]?.trim();
}

function getHeader(req: any, key: string) {
  const k = key.toLowerCase();
  const v = req.headers?.[k];
  if (Array.isArray(v)) return v[0];
  return v ? String(v) : undefined;
}

function setNoStore(res: any) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
}

function getCookie(req: any, name: string): string | undefined {
  const raw = req.headers?.cookie;
  if (!raw) return undefined;
  const parts = raw.split(";").map((p: string) => p.trim());
  for (const p of parts) {
    const [k, ...rest] = p.split("=");
    if (k === name) return decodeURIComponent(rest.join("="));
  }
  return undefined;
}

function setCookie(res: any, name: string, value: string) {
  // HttpOnly for manage token cookie. SameSite=Lax is fine for oauth authorize page.
  res.setHeader(
    "Set-Cookie",
    `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Secure`,
  );
}

function clearCookie(res: any, name: string) {
  res.setHeader(
    "Set-Cookie",
    `${name}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax; Secure`,
  );
}

// =========================
// SnapTask RPC caller
// =========================

async function callSnaptaskRpc<T>(rpcName: string, params: Record<string, unknown>, snaptaskApiToken: string) {
  const url = new URL(`/api/rpc/${rpcName}`, SNAPTASK_BASE_URL);

  const res = await fetch(url.toString(), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ params: [{ ...params, apiToken: snaptaskApiToken }] }),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Snaptask RPC ${rpcName} failed: ${res.status} ${res.statusText} ${text}`);
  }

  return (await res.json()) as T;
}

// =========================
// OAuth: lookups + issuance
// =========================

function getAccountByManageToken(manageToken: string) {
  return db
    .prepare(`SELECT id, snaptask_token, revoked_at FROM connected_accounts WHERE manage_token = ?`)
    .get(manageToken) as { id: string; snaptask_token: string; revoked_at: number | null } | undefined;
}

function getAccountById(id: string) {
  return db
    .prepare(`SELECT id, snaptask_token, revoked_at FROM connected_accounts WHERE id = ?`)
    .get(id) as { id: string; snaptask_token: string; revoked_at: number | null } | undefined;
}

function revokeAccount(accountId: string) {
  db.prepare(`UPDATE connected_accounts SET revoked_at = ? WHERE id = ?`).run(nowMs(), accountId);
  db.prepare(`UPDATE oauth_tokens SET revoked_at = ? WHERE account_id = ?`).run(nowMs(), accountId);
}

function upsertSingleAccount(snaptaskToken: string) {
  // One account total per "ChatGPT user" is normally keyed by the OAuth client + refresh token set.
  // Since you chose "exactly one", we interpret it as: one active account per manage-token/browser session,
  // and when reconnecting, we overwrite that account and revoke previous tokens.

  // Create a brand new account each time; tokens get revoked via manage-token if user disconnects.
  const accountId = randomToken(18);
  const manageToken = randomToken(24);

  db.prepare(
    `INSERT INTO connected_accounts (id, snaptask_token, manage_token, revoked_at) VALUES (?, ?, ?, NULL)`,
  ).run(accountId, snaptaskToken, manageToken);

  return { accountId, manageToken };
}

function createAuthCode(input: {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  scope: string;
  accountId: string;
}) {
  const code = randomToken(32);
  const expiresAt = nowMs() + 5 * 60 * 1000; // 5 minutes

  db.prepare(
    `INSERT INTO auth_codes
     (code, client_id, redirect_uri, code_challenge, code_challenge_method, scope, account_id, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    code,
    input.clientId,
    input.redirectUri,
    input.codeChallenge,
    input.codeChallengeMethod,
    input.scope,
    input.accountId,
    expiresAt,
  );

  return code;
}

function exchangeAuthCode(input: {
  code: string;
  clientId: string;
  redirectUri: string;
  codeVerifier: string;
}) {
  const row = db.prepare(`SELECT * FROM auth_codes WHERE code = ?`).get(input.code) as
    | {
        code: string;
        client_id: string;
        redirect_uri: string;
        code_challenge: string;
        code_challenge_method: string;
        scope: string;
        account_id: string;
        expires_at: number;
      }
    | undefined;

  if (!row) throw new Error("Invalid authorization code");
  if (row.client_id !== input.clientId) throw new Error("Client mismatch");
  if (row.redirect_uri !== input.redirectUri) throw new Error("Redirect URI mismatch");
  if (row.expires_at < nowMs()) throw new Error("Authorization code expired");
  if (row.code_challenge_method !== "S256") throw new Error("Unsupported code_challenge_method");

  const expected = row.code_challenge;
  const actual = sha256Base64Url(input.codeVerifier);
  if (!constantTimeEqual(expected, actual)) throw new Error("PKCE verification failed");

  // consume code
  db.prepare(`DELETE FROM auth_codes WHERE code = ?`).run(input.code);

  // issue tokens
  const accessToken = randomToken(32);
  const refreshToken = randomToken(48);
  const refreshHash = sha256Base64Url(refreshToken);

  const accessExpiresAt = nowMs() + 15 * 60 * 1000; // 15 min

  db.prepare(
    `INSERT INTO oauth_tokens
     (access_token, refresh_token_hash, account_id, scope, access_expires_at, revoked_at, created_at, last_used_at)
     VALUES (?, ?, ?, ?, ?, NULL, ?, ?)`,
  ).run(accessToken, refreshHash, row.account_id, row.scope, accessExpiresAt, nowMs(), nowMs());

  return {
    accessToken,
    refreshToken,
    scope: row.scope,
    expiresIn: Math.floor((accessExpiresAt - nowMs()) / 1000),
  };
}

function refreshAccessToken(input: { refreshToken: string; clientId: string }) {
  const refreshHash = sha256Base64Url(input.refreshToken);

  const row = db
    .prepare(
      `SELECT * FROM oauth_tokens
       WHERE refresh_token_hash = ?
       ORDER BY created_at DESC
       LIMIT 1`,
    )
    .get(refreshHash) as
    | {
        access_token: string;
        refresh_token_hash: string;
        account_id: string;
        scope: string;
        access_expires_at: number;
        revoked_at: number | null;
      }
    | undefined;

  if (!row) throw new Error("Invalid refresh token");
  if (row.revoked_at) throw new Error("Refresh token revoked");

  const account = getAccountById(row.account_id);
  if (!account || account.revoked_at) throw new Error("Account revoked");

  // Rotate refresh token (recommended)
  const newAccessToken = randomToken(32);
  const newRefreshToken = randomToken(48);
  const newRefreshHash = sha256Base64Url(newRefreshToken);
  const accessExpiresAt = nowMs() + 15 * 60 * 1000;

  // Revoke old token row and create a new one
  db.prepare(`UPDATE oauth_tokens SET revoked_at = ?, last_used_at = ? WHERE access_token = ?`).run(
    nowMs(),
    nowMs(),
    row.access_token,
  );

  db.prepare(
    `INSERT INTO oauth_tokens
     (access_token, refresh_token_hash, account_id, scope, access_expires_at, revoked_at, created_at, last_used_at)
     VALUES (?, ?, ?, ?, ?, NULL, ?, ?)`,
  ).run(newAccessToken, newRefreshHash, row.account_id, row.scope, accessExpiresAt, nowMs(), nowMs());

  return {
    accessToken: newAccessToken,
    refreshToken: newRefreshToken,
    scope: row.scope,
    expiresIn: Math.floor((accessExpiresAt - nowMs()) / 1000),
  };
}

function validateBearerAccessToken(accessToken: string) {
  const row = db
    .prepare(
      `SELECT * FROM oauth_tokens WHERE access_token = ? LIMIT 1`,
    )
    .get(accessToken) as
    | {
        access_token: string;
        account_id: string;
        scope: string;
        access_expires_at: number;
        revoked_at: number | null;
      }
    | undefined;

  if (!row) return null;
  if (row.revoked_at) return null;
  if (row.access_expires_at < nowMs()) return null;

  const account = getAccountById(row.account_id);
  if (!account || account.revoked_at) return null;

  // touch
  db.prepare(`UPDATE oauth_tokens SET last_used_at = ? WHERE access_token = ?`).run(nowMs(), accessToken);

  return {
    accountId: row.account_id,
    scope: row.scope,
    snaptaskToken: account.snaptask_token,
  };
}

// =========================
// Well-known endpoints JSON
// =========================

function oauthProtectedResourceJson() {
  return {
    resource: BASE_URL,
    authorization_servers: [BASE_URL],
    bearer_methods_supported: ["header"],
    resource_documentation: `${BASE_URL}/connect`,
    scopes_supported: ["snaptask"],
  };
}

function oauthAuthorizationServerJson() {
  return {
    issuer: BASE_URL,
    authorization_endpoint: `${BASE_URL}/oauth/authorize`,
    token_endpoint: `${BASE_URL}/oauth/token`,
    registration_endpoint: `${BASE_URL}/oauth/register`,
    revocation_endpoint: `${BASE_URL}/oauth/revoke`,

    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],

    token_endpoint_auth_methods_supported: ["none"],
    code_challenge_methods_supported: ["S256"],

    scopes_supported: ["snaptask"],
  };
}

function wwwAuthenticateHeaderValue() {
  return `Bearer realm="snaptask", error="invalid_token", error_description="Missing or invalid access token", resource_metadata="${BASE_URL}/.well-known/oauth-protected-resource"`;
}

// =========================
// MCP server (tools)
// =========================

export const getServer = (): McpServer => {
  const server = new McpServer({ name: "snaptask-mcp-server", version: "0.2.0" }, { capabilities: {} });

  // All tools now require Bearer auth (validated in HTTP middleware).
  // The snaptask token is attached to extra.requestContext.snaptaskToken by our middleware.

  function requireSnaptaskToken(extra: any) {
    const token = extra?.requestContext?.snaptaskToken as string | undefined;
    if (token) return token;

    // fallback for local/testing only
    if (DEFAULT_SNAPTASK_API_TOKEN) return DEFAULT_SNAPTASK_API_TOKEN;

    const err: any = new Error("Unauthorized");
    err.code = "UNAUTHORIZED";
    throw err;
  }

  server.tool(
    "list_today_tasks",
    "List today's tasks from Snaptask for the connected user",
    {},
    async (_args, extra: any): Promise<CallToolResult> => {
      const snaptaskToken = requireSnaptaskToken(extra);
      const tasks = await callSnaptaskRpc<unknown[]>("mcpListTodayTasks", {}, snaptaskToken);
      return { content: [{ type: "text", text: JSON.stringify(tasks, null, 2) }] };
    },
  );

  server.tool(
    "list_week_overview",
    "Get a high-level overview of this week's tasks from Snaptask",
    {},
    async (_args, extra: any): Promise<CallToolResult> => {
      const snaptaskToken = requireSnaptaskToken(extra);
      const overview = await callSnaptaskRpc<unknown>("mcpListWeekOverview", {}, snaptaskToken);
      return { content: [{ type: "text", text: JSON.stringify(overview, null, 2) }] };
    },
  );

  server.tool(
    "create_tasks_from_text",
    "Create one or more Snaptask tasks from a natural-language description",
    {
      text: z.string().describe("Natural language description (can contain multiple tasks)."),
    },
    async ({ text }, extra: any): Promise<CallToolResult> => {
      const snaptaskToken = requireSnaptaskToken(extra);
      const created = await callSnaptaskRpc<unknown>("mcpCreateTasksFromText", { text }, snaptaskToken);
      return { content: [{ type: "text", text: JSON.stringify(created, null, 2) }] };
    },
  );

  server.tool(
    "update_task_status",
    "Update the status of a Snaptask task",
    {
      taskId: z.string().describe("The Snaptask task ID to update"),
      status: z.enum(["TODO", "IN_PROGRESS", "DONE", "BLOCKED"]).describe("The new status"),
    },
    async ({ taskId, status }, extra: any): Promise<CallToolResult> => {
      const snaptaskToken = requireSnaptaskToken(extra);
      const result = await callSnaptaskRpc<unknown>("mcpUpdateTaskStatus", { taskId, status }, snaptaskToken);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    },
  );

  server.tool(
    "suggest_next_tasks",
    "Ask Snaptask to suggest the best next tasks to work on",
    {
      limit: z.number().min(1).max(20).optional().default(5).describe("Max suggestions"),
    },
    async ({ limit }, extra: any): Promise<CallToolResult> => {
      const snaptaskToken = requireSnaptaskToken(extra);
      const suggestions = await callSnaptaskRpc<unknown[]>("mcpSuggestNextTasks", { limit }, snaptaskToken);
      return { content: [{ type: "text", text: JSON.stringify(suggestions, null, 2) }] };
    },
  );

  server.tool(
    "greet",
    "Simple greeting tool to verify the MCP server is working",
    { name: z.string().describe("Name to greet") },
    async ({ name }): Promise<CallToolResult> => {
      return { content: [{ type: "text", text: `Hello, ${name}! The Snaptask MCP server is running.` }] };
    },
  );

  return server;
};

// =========================
// HTTP server with OAuth + MCP endpoint
// =========================

export async function start() {
  const app = express();

  // token endpoint uses urlencoded typically; others json
  app.use(express.urlencoded({ extended: false }));
  app.use(express.json({ limit: "1mb" }));

  // --- Well-known endpoints ---
  app.get("/.well-known/oauth-protected-resource", (_req, res) => {
    setNoStore(res);
    res.type("application/json").send(oauthProtectedResourceJson());
  });

  app.get("/.well-known/oauth-authorization-server", (_req, res) => {
    setNoStore(res);
    res.type("application/json").send(oauthAuthorizationServerJson());
  });

  // --- Human landing page ---
  app.get("/connect", (req, res) => {
    const manage = getCookie(req, "snaptask_manage");
    const has = manage ? !!getAccountByManageToken(manage) : false;

    res.type("text/html").send(`
<!doctype html>
<html>
  <head><meta charset="utf-8"/><title>Connect SnapTask</title></head>
  <body style="font-family: system-ui; max-width: 720px; margin: 40px auto;">
    <h1>Connect SnapTask</h1>
    <p>This server is meant to be connected from ChatGPT via “Connect”.</p>
    <p>If ChatGPT sent you here, keep that tab open and complete the connection prompt there.</p>

    <h2>Status</h2>
    <p>${has ? "Connected in this browser." : "Not connected in this browser."}</p>

    ${has ? `
      <form method="post" action="/disconnect">
        <button type="submit">Disconnect</button>
      </form>
    ` : ""}
  </body>
</html>`);
  });

  // --- Dynamic Client Registration ---
  app.post("/oauth/register", (req, res) => {
    setNoStore(res);

    // Accept typical DCR fields; at minimum we need redirect_uris
    const redirectUris = Array.isArray(req.body?.redirect_uris) ? req.body.redirect_uris : [];
    if (!redirectUris.length) {
      return res.status(400).json({ error: "invalid_client_metadata", error_description: "redirect_uris required" });
    }

    const clientId = randomToken(18);
    db.prepare(`INSERT INTO oauth_clients (client_id, redirect_uris, created_at) VALUES (?, ?, ?)`).run(
      clientId,
      JSON.stringify(redirectUris),
      nowMs(),
    );

    return res.json({
      client_id: clientId,
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      redirect_uris: redirectUris,
    });
  });

  // --- Authorization endpoint (Connect page) ---
  app.get("/oauth/authorize", (req, res) => {
    setNoStore(res);

    const {
      response_type,
      client_id,
      redirect_uri,
      scope = "snaptask",
      state,
      code_challenge,
      code_challenge_method,
    } = req.query as Record<string, string>;

    if (response_type !== "code") return res.status(400).send("Invalid response_type");
    if (!client_id) return res.status(400).send("Missing client_id");
    if (!redirect_uri) return res.status(400).send("Missing redirect_uri");
    if (!state) return res.status(400).send("Missing state");
    if (!code_challenge || code_challenge_method !== "S256") return res.status(400).send("PKCE S256 required");

    const clientRow = db.prepare(`SELECT * FROM oauth_clients WHERE client_id = ?`).get(client_id) as
      | { client_id: string; redirect_uris: string }
      | undefined;

    if (!clientRow) return res.status(400).send("Unknown client_id");

    const allowed = JSON.parse(clientRow.redirect_uris) as string[];
    if (!allowed.includes(redirect_uri)) return res.status(400).send("redirect_uri not registered");

    const manage = getCookie(req, "snaptask_manage");
    const has = manage ? !!getAccountByManageToken(manage) : false;

    res.type("text/html").send(`
<!doctype html>
<html>
  <head><meta charset="utf-8"/><title>Connect SnapTask</title></head>
  <body style="font-family: system-ui; max-width: 720px; margin: 40px auto;">
    <h1>Connect SnapTask</h1>
    <p>Paste your SnapTask personal API token below. This will connect SnapTask to ChatGPT.</p>

    <form method="post" action="/oauth/authorize">
      <input type="hidden" name="response_type" value="${escapeHtml(response_type)}"/>
      <input type="hidden" name="client_id" value="${escapeHtml(client_id)}"/>
      <input type="hidden" name="redirect_uri" value="${escapeHtml(redirect_uri)}"/>
      <input type="hidden" name="scope" value="${escapeHtml(scope)}"/>
      <input type="hidden" name="state" value="${escapeHtml(state)}"/>
      <input type="hidden" name="code_challenge" value="${escapeHtml(code_challenge)}"/>
      <input type="hidden" name="code_challenge_method" value="${escapeHtml(code_challenge_method)}"/>

      <label>SnapTask API token</label><br/>
      <input name="snaptask_token" type="password" style="width: 100%; padding: 10px; font-size: 16px;" required /><br/><br/>
      <button type="submit" style="padding: 10px 14px; font-size: 16px;">Connect</button>
    </form>

    <hr style="margin: 24px 0;" />

    <h2>Disconnect</h2>
    <p>${has ? "You can disconnect from this browser below." : "No active connection found in this browser."}</p>
    ${has ? `
      <form method="post" action="/disconnect">
        <button type="submit" style="padding: 10px 14px; font-size: 16px;">Disconnect</button>
      </form>
    ` : ""}
  </body>
</html>`);
  });

  app.post("/oauth/authorize", (req, res) => {
    setNoStore(res);

    const {
      response_type,
      client_id,
      redirect_uri,
      scope = "snaptask",
      state,
      code_challenge,
      code_challenge_method,
      snaptask_token,
    } = req.body as Record<string, string>;

    if (response_type !== "code") return res.status(400).send("Invalid response_type");
    if (!client_id || !redirect_uri || !state) return res.status(400).send("Missing required fields");
    if (!code_challenge || code_challenge_method !== "S256") return res.status(400).send("PKCE S256 required");

    const token = String(snaptask_token || "").trim();
    if (token.length < 10) return res.status(400).send("Invalid SnapTask token");

    // Create a connected account (single account per connection session)
    const { accountId, manageToken } = upsertSingleAccount(token);
    setCookie(res, "snaptask_manage", manageToken);

    const code = createAuthCode({
      clientId: client_id,
      redirectUri: redirect_uri,
      codeChallenge: code_challenge,
      codeChallengeMethod: code_challenge_method,
      scope,
      accountId,
    });

    const redirect = new URL(redirect_uri);
    redirect.searchParams.set("code", code);
    redirect.searchParams.set("state", state);

    return res.redirect(redirect.toString());
  });

  // --- Token endpoint (code exchange + refresh) ---
  app.post("/oauth/token", (req, res) => {
    setNoStore(res);

    const grantType = String(req.body?.grant_type || "");

    try {
      if (grantType === "authorization_code") {
        const code = String(req.body?.code || "");
        const redirectUri = String(req.body?.redirect_uri || "");
        const clientId = String(req.body?.client_id || "");
        const verifier = String(req.body?.code_verifier || "");

        const out = exchangeAuthCode({ code, clientId, redirectUri, codeVerifier: verifier });

        return res.json({
          access_token: out.accessToken,
          token_type: "bearer",
          expires_in: out.expiresIn,
          refresh_token: out.refreshToken,
          scope: out.scope,
        });
      }

      if (grantType === "refresh_token") {
        const refreshToken = String(req.body?.refresh_token || "");
        const clientId = String(req.body?.client_id || "");
        if (!refreshToken || !clientId) throw new Error("Missing refresh_token or client_id");

        const out = refreshAccessToken({ refreshToken, clientId });

        return res.json({
          access_token: out.accessToken,
          token_type: "bearer",
          expires_in: out.expiresIn,
          refresh_token: out.refreshToken,
          scope: out.scope,
        });
      }

      return res.status(400).json({ error: "unsupported_grant_type" });
    } catch (e: any) {
      return res.status(400).json({ error: "invalid_request", error_description: e?.message || "token error" });
    }
  });

  // --- Revocation endpoint (ChatGPT disconnect) ---
  app.post("/oauth/revoke", (req, res) => {
    setNoStore(res);

    const token = String(req.body?.token || req.body?.refresh_token || "").trim();
    if (!token) return res.status(200).send("");

    const refreshHash = sha256Base64Url(token);
    const row = db
      .prepare(
        `SELECT * FROM oauth_tokens WHERE refresh_token_hash = ? ORDER BY created_at DESC LIMIT 1`,
      )
      .get(refreshHash) as { account_id: string } | undefined;

    if (row?.account_id) {
      // Revoke everything for that account
      revokeAccount(row.account_id);
    }

    return res.status(200).send("");
  });

  // --- Browser disconnect button (uses manage-token cookie) ---
  app.post("/disconnect", (req, res) => {
    setNoStore(res);

    const manage = getCookie(req, "snaptask_manage");
    if (manage) {
      const acct = getAccountByManageToken(manage);
      if (acct?.id) revokeAccount(acct.id);
    }

    clearCookie(res, "snaptask_manage");
    return res.redirect("/connect");
  });

  // =========================
  // MCP HTTP endpoint
  // =========================

  const mcpServer = getServer();

  // Auth middleware: every MCP call requires Bearer token
  app.post("/mcp", async (req, res) => {
    const auth = parseAuthHeader(getHeader(req, "authorization"));

    const validated = auth ? validateBearerAccessToken(auth) : null;
    if (!validated) {
      // Trigger ChatGPT "Connect"
      res.status(401);
      res.setHeader("WWW-Authenticate", wwwAuthenticateHeaderValue());
      return res.send("");
    }

    // Attach token for tool handlers
    const extra = {
      requestInfo: { headers: req.headers },
      requestContext: { snaptaskToken: validated.snaptaskToken },
    };

    // ---- MCP dispatch (SDK-dependent) ----
    // This assumes your McpServer instance supports handleRequest(requestJson, extra).
    // If your SDK uses a different method, only adjust this section.
    try {
      const result = await (mcpServer as any).handleRequest(req.body, extra);
      res.type("application/json").send(result);
    } catch (e: any) {
      // If a tool threw an UNAUTHORIZED error, convert to the required 401 header
      if (e?.code === "UNAUTHORIZED" || String(e?.message || "").toLowerCase().includes("unauthorized")) {
        res.status(401);
        res.setHeader("WWW-Authenticate", wwwAuthenticateHeaderValue());
        return res.send("");
      }

      res.status(500).json({ error: "mcp_error", message: e?.message || "Unknown error" });
    }
  });

  app.listen(PORT, () => {
    console.log(`SnapTask MCP+OAuth server listening on :${PORT}`);
    console.log(`Base URL: ${BASE_URL}`);
  });
}

// Minimal HTML escaping
function escapeHtml(s: string) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

// Auto-start if run directly
void start();
