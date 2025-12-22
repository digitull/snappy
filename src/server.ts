import express from "express";
import crypto from "crypto";
import path from "path";
import fs from "fs";

type OAuthCodeRow = {
  code: string;
  clientId: string;
  userId: string;
  redirectUri: string;
  scope: string;
  codeChallenge: string;
  codeChallengeMethod: "S256" | "plain";
  expiresAt: number;
};

type OAuthTokenRow = {
  accessTokenHash: string;
  refreshTokenHash: string;
  clientId: string;
  userId: string;
  scope: string;
  accessExpiresAt: number;
  refreshExpiresAt: number;
  createdAt: number;
};

type OAuthClientRow = {
  clientId: string;
  redirectUris: string[];
  createdAt: number;
  updatedAt: number;
};

type UserRow = {
  id: string;
  createdAt: number;
};

type UserSecretRow = {
  userId: string;
  githubTokenEnc: string;
  updatedAt: number;
};

type StoreShape = {
  users: Record<string, UserRow>;
  userSecrets: Record<string, UserSecretRow>;
  oauthClients: Record<string, OAuthClientRow>;
  oauthCodes: Record<string, OAuthCodeRow>;
  oauthTokensByAccessHash: Record<string, OAuthTokenRow>;
  oauthTokensByRefreshHash: Record<string, OAuthTokenRow>;
};

function nowMs() {
  return Date.now();
}

function base64Url(buf: Buffer) {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function sha256Base64Url(input: string) {
  const h = crypto.createHash("sha256").update(input).digest();
  return base64Url(h);
}

function randomToken(bytes = 32) {
  return base64Url(crypto.randomBytes(bytes));
}

function safeJsonParse<T>(s: string, fallback: T): T {
  try {
    return JSON.parse(s) as T;
  } catch {
    return fallback;
  }
}

/**
 * === REQUIRED ENV ===
 * PUBLIC_BASE_URL   e.g. https://snappy-8615fb5a.alpic.live
 * SERVER_SECRET     long random string (REQUIRED in production)
 *
 * === OPTIONAL ENV ===
 * OAUTH_STORE_PATH  default ./oauth-store.json
 * APP_NAME          default "Snappy MCP"
 * ALLOWED_REDIRECT_URI_PREFIXES comma-separated prefixes allowed (defaults include chatgpt.com + chat.openai.com)
 */
const BASE_URL = (process.env.PUBLIC_BASE_URL ?? "https://snappy-8615fb5a.alpic.live").replace(/\/$/, "");
const APP_NAME = process.env.APP_NAME ?? "Snappy MCP";
const STORE_PATH = process.env.OAUTH_STORE_PATH ?? path.join(process.cwd(), "oauth-store.json");

const ALLOWED_REDIRECT_URI_PREFIXES = (process.env.ALLOWED_REDIRECT_URI_PREFIXES ??
  "https://chat.openai.com/,https://chatgpt.com/")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const SERVER_SECRET = process.env.SERVER_SECRET ?? "";
if (!SERVER_SECRET || SERVER_SECRET.length < 32) {
  if (process.env.NODE_ENV === "production") {
    throw new Error("SERVER_SECRET must be set to a long random string in production.");
  }
}

function isAllowedRedirectUri(redirectUri: string) {
  return ALLOWED_REDIRECT_URI_PREFIXES.some((prefix) => redirectUri.startsWith(prefix));
}

function loadStore(): StoreShape {
  if (!fs.existsSync(STORE_PATH)) {
    return {
      users: {},
      userSecrets: {},
      oauthClients: {},
      oauthCodes: {},
      oauthTokensByAccessHash: {},
      oauthTokensByRefreshHash: {},
    };
  }

  const raw = fs.readFileSync(STORE_PATH, "utf8");
  const parsed = safeJsonParse<StoreShape>(raw, null as any);

  return (
    parsed ?? {
      users: {},
      userSecrets: {},
      oauthClients: {},
      oauthCodes: {},
      oauthTokensByAccessHash: {},
      oauthTokensByRefreshHash: {},
    }
  );
}

function saveStore(store: StoreShape) {
  const tmp = `${STORE_PATH}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(store, null, 2), "utf8");
  fs.renameSync(tmp, STORE_PATH);
}

function deriveKey() {
  return crypto.createHash("sha256").update(SERVER_SECRET || "dev-secret").digest();
}

function encryptString(plain: string) {
  const key = deriveKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plain, "utf8")), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${base64Url(iv)}.${base64Url(tag)}.${base64Url(ciphertext)}`;
}

function decryptString(enc: string) {
  const key = deriveKey();
  const [ivB64, tagB64, ctB64] = enc.split(".");
  if (!ivB64 || !tagB64 || !ctB64) throw new Error("Invalid encrypted payload");
  const iv = Buffer.from(ivB64.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  const tag = Buffer.from(tagB64.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  const ct = Buffer.from(ctB64.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
  return plain.toString("utf8");
}

/**
 * Minimal signed cookie session (no external deps).
 */
function signCookie(payload: object) {
  const json = JSON.stringify(payload);
  const mac = crypto.createHmac("sha256", SERVER_SECRET || "dev-secret").update(json).digest("base64url");
  return `${base64Url(Buffer.from(json, "utf8"))}.${mac}`;
}

function verifyCookie<T>(cookie: string): T | null {
  const [payloadB64, mac] = cookie.split(".");
  if (!payloadB64 || !mac) return null;
  const json = Buffer.from(payloadB64.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
  const expected = crypto.createHmac("sha256", SERVER_SECRET || "dev-secret").update(json).digest("base64url");
  if (!crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expected))) return null;
  return safeJsonParse<T>(json, null as any);
}

function getCookie(req: any, name: string) {
  const raw = req.headers.cookie as string | undefined;
  if (!raw) return null;
  const parts = raw.split(";").map((p) => p.trim());
  for (const p of parts) {
    const idx = p.indexOf("=");
    if (idx === -1) continue;
    const k = p.slice(0, idx);
    const v = p.slice(idx + 1);
    if (k === name) return decodeURIComponent(v);
  }
  return null;
}

function setCookie(res: any, name: string, value: string) {
  res.setHeader("Set-Cookie", `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Secure`);
}

function getSessionUserId(req: any): string | null {
  const c = getCookie(req, "mcp_session");
  if (!c) return null;
  const payload = verifyCookie<{ userId: string }>(c);
  return payload?.userId ?? null;
}

type McpRequest = {
  jsonrpc?: string;
  id?: string | number | null;
  method: string;
  params?: any;
};

function jsonRpcResult(id: any, result: any) {
  return { jsonrpc: "2.0", id: id ?? null, result };
}

function jsonRpcError(id: any, code: number, message: string, data?: any) {
  return { jsonrpc: "2.0", id: id ?? null, error: { code, message, data } };
}

function requireBearer(req: any) {
  const auth = (req.headers.authorization as string | undefined) ?? "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  return m?.[1] ?? null;
}

function hasScope(scopeStr: string, needed: "github.read" | "github.write") {
  const scopes = scopeStr.split(/\s+/).filter(Boolean);
  if (needed === "github.read") return scopes.includes("github.read") || scopes.includes("github.write");
  return scopes.includes("github.write");
}

async function githubFetch(store: StoreShape, userId: string, url: string, init?: RequestInit) {
  const secret = store.userSecrets[userId];
  if (!secret?.githubTokenEnc) throw new Error("No GitHub token connected. Visit /connect");

  const pat = decryptString(secret.githubTokenEnc);

  const resp = await fetch(url, {
    ...(init ?? {}),
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${pat}`,
      "User-Agent": "snappy-mcp",
      ...(init?.headers ?? {}),
    },
  });

  const text = await resp.text();
  let json: any = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = { raw: text };
  }

  if (!resp.ok) {
    throw new Error(`GitHub error ${resp.status}: ${json?.message ?? "Request failed"}`);
  }

  return json;
}

const tools = [
  {
    name: "github.search_repositories",
    description: "Search GitHub repositories by keyword.",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "Search query, e.g. 'mcp language:typescript'" },
        perPage: { type: "number", description: "Max results (1-50).", default: 10 },
      },
      required: ["query"],
    },
    requiredScope: "github.read" as const,
  },
  {
    name: "github.list_repo_issues",
    description: "List issues in a repo (can include PRs if GitHub marks them as issues).",
    inputSchema: {
      type: "object",
      properties: {
        owner: { type: "string" },
        repo: { type: "string" },
        state: { type: "string", enum: ["open", "closed", "all"], default: "open" },
        perPage: { type: "number", default: 20 },
      },
      required: ["owner", "repo"],
    },
    requiredScope: "github.read" as const,
  },
  {
    name: "github.list_repo_prs",
    description: "List pull requests in a repo.",
    inputSchema: {
      type: "object",
      properties: {
        owner: { type: "string" },
        repo: { type: "string" },
        state: { type: "string", enum: ["open", "closed", "all"], default: "open" },
        perPage: { type: "number", default: 20 },
      },
      required: ["owner", "repo"],
    },
    requiredScope: "github.read" as const,
  },
  {
    name: "github.get_file",
    description: "Get file contents from a repo path (base64 decoded).",
    inputSchema: {
      type: "object",
      properties: {
        owner: { type: "string" },
        repo: { type: "string" },
        path: { type: "string", description: "File path in the repo" },
        ref: { type: "string", description: "Branch/tag/sha (optional)" },
      },
      required: ["owner", "repo", "path"],
    },
    requiredScope: "github.read" as const,
  },
  {
    name: "github.create_issue",
    description: "Create a GitHub issue in a repo.",
    inputSchema: {
      type: "object",
      properties: {
        owner: { type: "string" },
        repo: { type: "string" },
        title: { type: "string" },
        body: { type: "string" },
        labels: { type: "array", items: { type: "string" } },
      },
      required: ["owner", "repo", "title"],
    },
    requiredScope: "github.write" as const,
  },
];

/**
 * IMPORTANT: index.ts expects this named export.
 */
export function getServer() {
  const store = loadStore();

  const app = express();

  app.use(express.json({ limit: "2mb" }));
  app.use(express.urlencoded({ extended: true }));

  function ensureUser(userId: string) {
    if (!store.users[userId]) {
      store.users[userId] = { id: userId, createdAt: nowMs() };
      saveStore(store);
    }
  }

  function requireConnectedUser(req: any) {
    const userId = getSessionUserId(req);
    if (!userId) return null;
    ensureUser(userId);
    const secret = store.userSecrets[userId];
    if (!secret?.githubTokenEnc) return null;
    return { userId, githubTokenEnc: secret.githubTokenEnc };
  }

  /**
   * === Public well-known docs for ChatGPT ===
   */
  app.get("/.well-known/oauth-protected-resource", (_req, res) => {
    res.json({
      resource: BASE_URL,
      authorization_servers: [`${BASE_URL}/.well-known/oauth-authorization-server`],
    });
  });

  app.get("/.well-known/oauth-authorization-server", (_req, res) => {
    res.json({
      issuer: BASE_URL,
      authorization_endpoint: `${BASE_URL}/oauth/authorize`,
      token_endpoint: `${BASE_URL}/oauth/token`,
      revocation_endpoint: `${BASE_URL}/oauth/revoke`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256", "plain"],
      token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
      scopes_supported: ["github.read", "github.write"],
    });
  });

  /**
   * === Connect screen ===
   */
  app.get("/connect", (req, res) => {
    const returnTo = (req.query.returnTo as string | undefined) ?? "/";
    const userId = getSessionUserId(req);
    const ok = req.query.ok === "1";

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(`
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>${APP_NAME} – Connect</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 24px; background:#0b0b0c; color:#fff; }
    .card { max-width: 720px; margin: 0 auto; background:#141416; border:1px solid #2a2a2f; border-radius: 14px; padding: 18px; }
    a { color: #8ab4ff; }
    input { width:100%; padding:12px; border-radius: 10px; border:1px solid #2a2a2f; background:#0f0f12; color:#fff; }
    button { padding: 12px 14px; border-radius: 10px; border: 0; background: #2b6cff; color:#fff; font-weight: 600; cursor:pointer; }
    .muted { color:#b7b7c2; font-size: 14px; line-height: 1.4; }
    .ok { background:#0f2a16; border:1px solid #1f7a3a; padding:10px 12px; border-radius: 10px; margin-bottom: 12px; }
    .warn { background:#2a1a0f; border:1px solid #a85a1a; padding:10px 12px; border-radius: 10px; margin-top: 12px; }
    code { background:#0f0f12; padding: 2px 6px; border-radius: 6px; }
  </style>
</head>
<body>
  <div class="card">
    <h2>${APP_NAME}: Connect GitHub</h2>
    <p class="muted">
      Paste a <strong>GitHub Personal Access Token</strong>.
      It is stored <strong>encrypted</strong> and used only after you approve access.
    </p>

    ${ok ? `<div class="ok">Saved. You can go back to ChatGPT and continue connecting.</div>` : ""}

    <form method="POST" action="/connect">
      <input type="hidden" name="returnTo" value="${encodeURIComponent(returnTo)}" />
      <label class="muted">GitHub Personal Access Token</label>
      <input name="githubToken" placeholder="ghp_..." autocomplete="off" />
      <div style="height: 12px"></div>
      <button type="submit">Save token</button>
    </form>

    <div class="warn">
      <div class="muted">
        Tip: Use the minimum scopes you need.
        Private repos usually need <code>repo</code>. Public-only may use <code>public_repo</code>.
      </div>
    </div>

    <div style="height: 10px"></div>
    <p class="muted">Session: ${userId ? `<code>${userId}</code>` : "not set yet"}</p>
  </div>
</body>
</html>
    `);
  });

  app.post("/connect", (req, res) => {
    const githubToken = (req.body.githubToken as string | undefined)?.trim() ?? "";
    const returnToEnc = (req.body.returnTo as string | undefined) ?? "%2F";
    const returnTo = decodeURIComponent(returnToEnc);

    if (!githubToken || githubToken.length < 20) {
      return res.status(400).send("Token missing or too short.");
    }

    const userId = getSessionUserId(req) ?? `u_${randomToken(12)}`;
    ensureUser(userId);

    const enc = encryptString(githubToken);

    store.userSecrets[userId] = {
      userId,
      githubTokenEnc: enc,
      updatedAt: nowMs(),
    };

    saveStore(store);
    setCookie(res, "mcp_session", signCookie({ userId }));
    res.redirect(`/connect?ok=1&returnTo=${encodeURIComponent(returnTo)}`);
  });

  /**
   * === OAuth authorize ===
   */
  app.get("/oauth/authorize", (req, res) => {
    const clientId = (req.query.client_id as string | undefined) ?? "";
    const redirectUri = (req.query.redirect_uri as string | undefined) ?? "";
    const responseType = (req.query.response_type as string | undefined) ?? "";
    const state = (req.query.state as string | undefined) ?? "";
    const scope = (req.query.scope as string | undefined) ?? "github.read";
    const codeChallenge = (req.query.code_challenge as string | undefined) ?? "";
    const codeChallengeMethod = ((req.query.code_challenge_method as string | undefined) ?? "S256") as
      | "S256"
      | "plain";

    if (!clientId || !redirectUri || responseType !== "code") {
      return res.status(400).send("Missing required OAuth parameters.");
    }
    if (!isAllowedRedirectUri(redirectUri)) {
      return res.status(400).send("redirect_uri not allowed.");
    }
    if (!codeChallenge || !["S256", "plain"].includes(codeChallengeMethod)) {
      return res.status(400).send("PKCE code_challenge is required (S256 or plain).");
    }

    const ts = nowMs();
    const existingClient = store.oauthClients[clientId];
    const redirectUris = new Set<string>(existingClient?.redirectUris ?? []);
    redirectUris.add(redirectUri);

    store.oauthClients[clientId] = {
      clientId,
      redirectUris: [...redirectUris],
      createdAt: existingClient?.createdAt ?? ts,
      updatedAt: ts,
    };
    saveStore(store);

    const connected = requireConnectedUser(req);
    if (!connected) {
      const fullReturn = `${BASE_URL}/oauth/authorize?${new URLSearchParams(req.query as any).toString()}`;
      return res.redirect(`/connect?returnTo=${encodeURIComponent(fullReturn)}`);
    }

    const scopes = scope.split(/\s+/).filter(Boolean);
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(`
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>${APP_NAME} – Approve</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 24px; background:#0b0b0c; color:#fff; }
    .card { max-width: 720px; margin: 0 auto; background:#141416; border:1px solid #2a2a2f; border-radius: 14px; padding: 18px; }
    .muted { color:#b7b7c2; font-size: 14px; line-height: 1.4; }
    .row { display:flex; gap:12px; margin-top: 14px; }
    button { flex:1; padding: 12px 14px; border-radius: 10px; border: 0; font-weight: 700; cursor:pointer; }
    .approve { background: #2b6cff; color:#fff; }
    .deny { background: #2a2a2f; color:#fff; }
    ul { margin: 8px 0 0 18px; }
    code { background:#0f0f12; padding: 2px 6px; border-radius: 6px; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Allow ChatGPT to access GitHub?</h2>
    <p class="muted">
      You are approving access from <code>${clientId}</code> via ${APP_NAME}.
    </p>

    <div class="muted" style="margin-top:10px;">
      Requested permissions:
      <ul>
        ${scopes.map((s) => `<li><code>${s}</code></li>`).join("")}
      </ul>
    </div>

    <div class="row">
      <form method="POST" action="/oauth/approve" style="flex:1">
        ${["client_id","redirect_uri","response_type","state","scope","code_challenge","code_challenge_method"]
          .map((k) => `<input type="hidden" name="${k}" value="${String((req.query as any)[k] ?? "")}" />`)
          .join("")}
        <button class="approve" type="submit">Approve</button>
      </form>

      <form method="POST" action="/oauth/deny" style="flex:1">
        ${["redirect_uri","state"].map((k) => `<input type="hidden" name="${k}" value="${String((req.query as any)[k] ?? "")}" />`).join("")}
        <button class="deny" type="submit">Deny</button>
      </form>
    </div>

    <p class="muted" style="margin-top:12px;">
      Tip: If you need write actions (create issues), request <code>github.write</code>.
    </p>
  </div>
</body>
</html>
    `);
  });

  app.post("/oauth/deny", (req, res) => {
    const redirectUri = (req.body.redirect_uri as string | undefined) ?? "";
    const state = (req.body.state as string | undefined) ?? "";
    if (!redirectUri) return res.status(400).send("Missing redirect_uri");
    const u = new URL(redirectUri);
    u.searchParams.set("error", "access_denied");
    if (state) u.searchParams.set("state", state);
    res.redirect(u.toString());
  });

  app.post("/oauth/approve", (req, res) => {
    const clientId = (req.body.client_id as string | undefined) ?? "";
    const redirectUri = (req.body.redirect_uri as string | undefined) ?? "";
    const state = (req.body.state as string | undefined) ?? "";
    const scope = (req.body.scope as string | undefined) ?? "github.read";
    const codeChallenge = (req.body.code_challenge as string | undefined) ?? "";
    const codeChallengeMethod = ((req.body.code_challenge_method as string | undefined) ?? "S256") as
      | "S256"
      | "plain";

    if (!clientId || !redirectUri || !codeChallenge) {
      return res.status(400).send("Missing OAuth params.");
    }
    if (!isAllowedRedirectUri(redirectUri)) {
      return res.status(400).send("redirect_uri not allowed.");
    }

    const connected = requireConnectedUser(req);
    if (!connected) {
      return res.status(400).send("Not connected. Go to /connect first.");
    }

    const code = `c_${randomToken(24)}`;
    const expiresAt = nowMs() + 5 * 60 * 1000;

    store.oauthCodes[code] = {
      code,
      clientId,
      userId: connected.userId,
      redirectUri,
      scope,
      codeChallenge,
      codeChallengeMethod,
      expiresAt,
    };
    saveStore(store);

    const u = new URL(redirectUri);
    u.searchParams.set("code", code);
    if (state) u.searchParams.set("state", state);
    res.redirect(u.toString());
  });

  /**
   * === OAuth token ===
   */
  app.post("/oauth/token", (req, res) => {
    const grantType = (req.body.grant_type as string | undefined) ?? "";
    const clientId = (req.body.client_id as string | undefined) ?? "";
    const code = (req.body.code as string | undefined) ?? "";
    const redirectUri = (req.body.redirect_uri as string | undefined) ?? "";
    const codeVerifier = (req.body.code_verifier as string | undefined) ?? "";
    const refreshToken = (req.body.refresh_token as string | undefined) ?? "";

    if (!clientId) return res.status(400).json({ error: "invalid_request" });

    if (grantType === "authorization_code") {
      if (!code || !redirectUri || !codeVerifier) {
        return res.status(400).json({ error: "invalid_request" });
      }

      const row = store.oauthCodes[code];
      if (!row) return res.status(400).json({ error: "invalid_grant" });
      if (row.clientId !== clientId) return res.status(400).json({ error: "invalid_grant" });
      if (row.redirectUri !== redirectUri) return res.status(400).json({ error: "invalid_grant" });
      if (nowMs() > row.expiresAt) return res.status(400).json({ error: "invalid_grant" });

      let expected = "";
      if (row.codeChallengeMethod === "plain") expected = codeVerifier;
      else expected = sha256Base64Url(codeVerifier);

      if (expected !== row.codeChallenge) return res.status(400).json({ error: "invalid_grant" });

      delete store.oauthCodes[code];

      const accessToken = `at_${randomToken(32)}`;
      const refresh = `rt_${randomToken(32)}`;

      const accessHash = sha256Base64Url(accessToken);
      const refreshHash = sha256Base64Url(refresh);

      const accessExpiresAt = nowMs() + 60 * 60 * 1000;
      const refreshExpiresAt = nowMs() + 30 * 24 * 60 * 60 * 1000;

      const tokenRow: OAuthTokenRow = {
        accessTokenHash: accessHash,
        refreshTokenHash: refreshHash,
        clientId,
        userId: row.userId,
        scope: row.scope,
        accessExpiresAt,
        refreshExpiresAt,
        createdAt: nowMs(),
      };

      store.oauthTokensByAccessHash[accessHash] = tokenRow;
      store.oauthTokensByRefreshHash[refreshHash] = tokenRow;
      saveStore(store);

      return res.json({
        token_type: "Bearer",
        access_token: accessToken,
        refresh_token: refresh,
        expires_in: 3600,
        scope: row.scope,
      });
    }

    if (grantType === "refresh_token") {
      if (!refreshToken) return res.status(400).json({ error: "invalid_request" });

      const refreshHash = sha256Base64Url(refreshToken);
      const row = store.oauthTokensByRefreshHash[refreshHash];
      if (!row) return res.status(400).json({ error: "invalid_grant" });
      if (row.clientId !== clientId) return res.status(400).json({ error: "invalid_grant" });
      if (nowMs() > row.refreshExpiresAt) return res.status(400).json({ error: "invalid_grant" });

      delete store.oauthTokensByRefreshHash[refreshHash];
      delete store.oauthTokensByAccessHash[row.accessTokenHash];

      const accessToken = `at_${randomToken(32)}`;
      const refresh = `rt_${randomToken(32)}`;

      const accessHash = sha256Base64Url(accessToken);
      const newRefreshHash = sha256Base64Url(refresh);

      const accessExpiresAt = nowMs() + 60 * 60 * 1000;
      const refreshExpiresAt = nowMs() + 30 * 24 * 60 * 60 * 1000;

      const newRow: OAuthTokenRow = {
        accessTokenHash: accessHash,
        refreshTokenHash: newRefreshHash,
        clientId,
        userId: row.userId,
        scope: row.scope,
        accessExpiresAt,
        refreshExpiresAt,
        createdAt: nowMs(),
      };

      store.oauthTokensByAccessHash[accessHash] = newRow;
      store.oauthTokensByRefreshHash[newRefreshHash] = newRow;
      saveStore(store);

      return res.json({
        token_type: "Bearer",
        access_token: accessToken,
        refresh_token: refresh,
        expires_in: 3600,
        scope: row.scope,
      });
    }

    return res.status(400).json({ error: "unsupported_grant_type" });
  });

  app.post("/oauth/revoke", (req, res) => {
    const token = (req.body.token as string | undefined) ?? "";
    if (!token) return res.status(200).send("");

    const hash = sha256Base64Url(token);

    const byAccess = store.oauthTokensByAccessHash[hash];
    if (byAccess) {
      delete store.oauthTokensByAccessHash[byAccess.accessTokenHash];
      delete store.oauthTokensByRefreshHash[byAccess.refreshTokenHash];
      saveStore(store);
      return res.status(200).send("");
    }

    const byRefresh = store.oauthTokensByRefreshHash[hash];
    if (byRefresh) {
      delete store.oauthTokensByAccessHash[byRefresh.accessTokenHash];
      delete store.oauthTokensByRefreshHash[byRefresh.refreshTokenHash];
      saveStore(store);
      return res.status(200).send("");
    }

    res.status(200).send("");
  });

  function getTokenRow(accessToken: string) {
    const hash = sha256Base64Url(accessToken);
    const row = store.oauthTokensByAccessHash[hash];
    if (!row) return null;
    if (nowMs() > row.accessExpiresAt) return null;
    return row;
  }

  /**
   * === MCP endpoint ===
   */
  app.post("/mcp", async (req, res) => {
    const bearer = requireBearer(req);
    if (!bearer) return res.status(401).json(jsonRpcError(req.body?.id, 401, "Missing Bearer token"));

    const tokenRow = getTokenRow(bearer);
    if (!tokenRow) return res.status(401).json(jsonRpcError(req.body?.id, 401, "Invalid or expired token"));

    const userId = tokenRow.userId as string;
    const scope = tokenRow.scope as string;

    const body = req.body as McpRequest;
    const id = body?.id ?? null;

    try {
      if (!body || !body.method) {
        return res.status(400).json(jsonRpcError(id, 400, "Invalid request"));
      }

      if (body.method === "tools/list") {
        return res.json(
          jsonRpcResult(id, {
            tools: tools.map((t) => ({
              name: t.name,
              description: t.description,
              inputSchema: t.inputSchema,
            })),
          }),
        );
      }

      if (body.method === "tools/call") {
        const toolName = body.params?.name as string | undefined;
        const args = body.params?.arguments ?? {};

        const tool = tools.find((t) => t.name === toolName);
        if (!tool) return res.status(404).json(jsonRpcError(id, 404, "Tool not found"));

        if (tool.requiredScope === "github.write" && !hasScope(scope, "github.write")) {
          return res.status(403).json(jsonRpcError(id, 403, "Missing scope github.write"));
        }
        if (tool.requiredScope === "github.read" && !hasScope(scope, "github.read")) {
          return res.status(403).json(jsonRpcError(id, 403, "Missing scope github.read"));
        }

        let result: any = null;

        if (toolName === "github.search_repositories") {
          const q = String(args.query ?? "");
          const perPage = Math.max(1, Math.min(50, Number(args.perPage ?? 10)));
          result = await githubFetch(
            store,
            userId,
            `https://api.github.com/search/repositories?q=${encodeURIComponent(q)}&per_page=${perPage}`,
          );
        } else if (toolName === "github.list_repo_issues") {
          const owner = String(args.owner ?? "");
          const repo = String(args.repo ?? "");
          const state = String(args.state ?? "open");
          const perPage = Math.max(1, Math.min(50, Number(args.perPage ?? 20)));
          result = await githubFetch(
            store,
            userId,
            `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues?state=${encodeURIComponent(
              state,
            )}&per_page=${perPage}`,
          );
        } else if (toolName === "github.list_repo_prs") {
          const owner = String(args.owner ?? "");
          const repo = String(args.repo ?? "");
          const state = String(args.state ?? "open");
          const perPage = Math.max(1, Math.min(50, Number(args.perPage ?? 20)));
          result = await githubFetch(
            store,
            userId,
            `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/pulls?state=${encodeURIComponent(
              state,
            )}&per_page=${perPage}`,
          );
        } else if (toolName === "github.get_file") {
          const owner = String(args.owner ?? "");
          const repo = String(args.repo ?? "");
          const filePath = String(args.path ?? "");
          const ref = args.ref ? `?ref=${encodeURIComponent(String(args.ref))}` : "";
          const json = await githubFetch(
            store,
            userId,
            `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${encodeURIComponent(
              filePath,
            )}${ref}`,
          );
          if (json?.content && json?.encoding === "base64") {
            const decoded = Buffer.from(String(json.content).replace(/\n/g, ""), "base64").toString("utf8");
            result = { ...json, decodedText: decoded };
          } else {
            result = json;
          }
        } else if (toolName === "github.create_issue") {
          const owner = String(args.owner ?? "");
          const repo = String(args.repo ?? "");
          const title = String(args.title ?? "");
          const bodyText = args.body ? String(args.body) : undefined;
          const labels = Array.isArray(args.labels) ? args.labels.map(String) : undefined;

          result = await githubFetch(store, userId, `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ title, body: bodyText, labels }),
          });
        } else {
          return res.status(400).json(jsonRpcError(id, 400, "Tool not implemented"));
        }

        return res.json(
          jsonRpcResult(id, {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
          }),
        );
      }

      if (body.method === "initialize") {
        return res.json(
          jsonRpcResult(id, {
            name: APP_NAME,
            version: "1.0.0",
            capabilities: { tools: {} },
          }),
        );
      }

      return res.status(404).json(jsonRpcError(id, 404, "Method not found"));
    } catch (e: any) {
      return res.status(500).json(jsonRpcError(id, 500, e?.message ?? "Server error"));
    }
  });

  app.get("/", (_req, res) => {
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.send(
      [
        `${APP_NAME} is running.`,
        ``,
        `Connect page: ${BASE_URL}/connect`,
        `MCP endpoint: POST ${BASE_URL}/mcp`,
        `OAuth metadata:`,
        `- ${BASE_URL}/.well-known/oauth-protected-resource`,
        `- ${BASE_URL}/.well-known/oauth-authorization-server`,
      ].join("\n"),
    );
  });

  return app;
}

// Optional default export (harmless, but convenient)
export default getServer;
