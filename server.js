#!/usr/bin/env node
"use strict";

/**
 * devin-search-mcp — an MCP (Model Context Protocol) stdio server exposing two
 * read-only Devin search tools to any MCP host (ZCode, Claude Desktop, ...).
 *
 *   web_search  : Devin cloud web search.
 *   code_search : cloud-planned, locally verified code search — Devin plans a
 *                 bounded sequence of read-only commands, this server runs them
 *                 READ-ONLY against the workspace (no shell, no subprocess) and
 *                 re-reads the final answer ranges before returning them.
 *
 * Port of leafmoes/pi-devin-search (MIT) from a PI-Desktop native plugin to a
 * standalone MCP server. The `lib/` search core is the upstream implementation,
 * unchanged; only the host glue is rewritten here. Host-API swaps:
 *
 *   PI-Desktop `pi.fs.*`            -> NodeFs (node:fs, workspace-relative)
 *   PI-Desktop `pi.net.fetch`       -> global `fetch` (netFetch)
 *   PI-Desktop `pi.workspace.get()` -> process.cwd() / $DEVIN_SEARCH_WORKSPACE
 *   PI-Desktop plugin data dir      -> ~/.devin-search-mcp / $DEVIN_SEARCH_CREDENTIALS_DIR
 *   PI-Desktop panel login          -> CLI: `node server.js login`
 *   PI-Desktop `pi.agent.registerTool` -> MCP `tools/list` + `tools/call`
 *
 * `code_search`'s cloud planning uses raw node:https (see lib/cloud.js) because
 * the Connect/protobuf frames are binary and cannot be carried as JSON.
 */

const fs = require("node:fs");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const readline = require("node:readline");
const { spawn } = require("node:child_process");

const {
  DevinError,
  fail,
  safeError,
  toDevinSessionToken,
  expiry,
  redact,
  isRateLimitStatus,
  rateLimitMessage,
  check,
  deadline,
} = require("./lib/core");
const { WindsurfCompletion } = require("./lib/cloud");
const { runCodeSearch } = require("./lib/code-search");

/* ------------------------------------------------------------ configuration */

/** Workspace root that code_search reads from. */
function workspacePath() {
  const fromEnv = process.env.DEVIN_SEARCH_WORKSPACE;
  if (fromEnv && fromEnv.trim()) return path.resolve(fromEnv.trim());
  return process.cwd();
}

/** Where credentials.json is stored. */
function credentialsDir() {
  const fromEnv = process.env.DEVIN_SEARCH_CREDENTIALS_DIR;
  if (fromEnv && fromEnv.trim()) return path.resolve(fromEnv.trim());
  return path.join(os.homedir(), ".devin-search-mcp");
}

function pkgVersion() {
  try {
    return require("./package.json").version;
  } catch {
    return "0.0.0";
  }
}

/* ---------------------------------------------------------- node:fs adapter */

/**
 * Read-only, workspace-relative file API matching the shape the code-search
 * sandbox expects from PI-Desktop's `pi.fs` (glob / readText / stat). Input and
 * output paths are workspace-relative and use forward slashes. Symlinks are
 * never followed, and nothing may resolve outside the workspace root.
 */
class NodeFs {
  constructor(root) {
    this.root = path.resolve(root);
  }

  /** Resolve a workspace-relative path to an absolute one, refusing escape. */
  _resolve(rel) {
    const cleaned = String(rel == null ? "" : rel).replace(/\\/g, "/").replace(/^\/+/, "");
    const absolute = path.resolve(this.root, cleaned);
    if (absolute !== this.root && !absolute.startsWith(this.root + path.sep)) {
      const e = new Error("Path escapes the workspace.");
      e.code = "ENOENT";
      throw e;
    }
    return absolute;
  }

  async stat(rel) {
    const absolute = this._resolve(rel);
    let info;
    try {
      info = await fsp.lstat(absolute);
    } catch {
      const e = new Error("Path not found in /codebase. Use tree or ls to discover available paths.");
      e.code = "ENOENT";
      throw e;
    }
    if (info.isSymbolicLink()) {
      const e = new Error("Symlinks are excluded from code_search.");
      e.code = "ENOTDIR";
      throw e;
    }
    return { size: info.size, isFile: info.isFile(), isDirectory: info.isDirectory() };
  }

  async readText(rel) {
    const absolute = this._resolve(rel);
    try {
      return await fsp.readFile(absolute, "utf8");
    } catch {
      const e = new Error("Path not found in /codebase. Use tree or ls to discover available paths.");
      e.code = "ENOENT";
      throw e;
    }
  }

  /**
   * Enumerate regular files under the workspace root (or a `base` subdir),
   * skipping symlinks, capped to a maximum entry count. Mirrors `pi.fs.glob`:
   * callers pass a star-slash-star pattern for the whole workspace (default) or
   * for a specific subdirectory. Returns workspace-relative forward-slash paths.
   */
  async glob(pattern) {
    const rel = String(pattern || "**/*");
    const base = rel.endsWith("/**/*") ? rel.slice(0, -"/**/*".length) : "";
    const baseAbs = base ? this._resolve(base) : this.root;

    let baseStat;
    try {
      baseStat = await fsp.lstat(baseAbs);
    } catch {
      return [];
    }
    if (baseStat.isSymbolicLink() || !baseStat.isDirectory()) return [];

    const out = [];
    const MAX_ENTRIES = 100000;
    let scanned = 0;

    const walk = async (dirAbs) => {
      if (scanned > MAX_ENTRIES) return;
      let entries;
      try {
        entries = await fsp.readdir(dirAbs, { withFileTypes: true });
      } catch {
        return;
      }
      for (const entry of entries) {
        scanned += 1;
        if (scanned > MAX_ENTRIES) return;
        const full = path.join(dirAbs, entry.name);
        let st;
        try {
          st = await fsp.lstat(full);
        } catch {
          continue;
        }
        if (st.isSymbolicLink()) continue; // never follow symlinks
        if (st.isDirectory()) {
          await walk(full);
        } else if (st.isFile()) {
          out.push(path.relative(this.root, full).split(path.sep).join("/"));
        }
      }
    };

    await walk(baseAbs);
    return out;
  }
}

/* --------------------------------------------------------------- credentials */

const CREDENTIAL_FILE = "credentials.json";
const MAX_GRANT_BYTES = 64 * 1024;
const EXPIRY_TIME_MIN = -8640000000000000;
const EXPIRY_TIME_MAX = 8640000000000000;

function normalizeGrant(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  if (value.version !== 1) return undefined;
  if (typeof value.token !== "string" || !value.token || value.token.length > 16384) return undefined;
  if (/[\s\x00-\x1f\x7f]/.test(value.token)) return undefined;
  if (typeof value.expiresAt !== "number" || !Number.isSafeInteger(value.expiresAt)) return undefined;
  if (value.expiresAt < EXPIRY_TIME_MIN || value.expiresAt > EXPIRY_TIME_MAX) return undefined;
  if (value.expirySource !== "jwt" && value.expirySource !== "fallback") return undefined;
  return {
    version: 1,
    token: value.token,
    expiresAt: value.expiresAt,
    expirySource: value.expirySource,
    ...(value.revoked === true ? { revoked: true } : {}),
  };
}

async function credentialFile() {
  const dir = credentialsDir();
  fs.mkdirSync(dir, { recursive: true });
  const stat = fs.lstatSync(dir);
  if (stat.isSymbolicLink() || !stat.isDirectory()) fail("storage", "Credential directory is unsafe.");
  return path.join(dir, CREDENTIAL_FILE);
}

async function readGrant() {
  let file;
  try {
    file = await credentialFile();
  } catch {
    return undefined;
  }
  let text;
  try {
    const stat = fs.lstatSync(file);
    if (stat.isSymbolicLink() || !stat.isFile() || stat.size > MAX_GRANT_BYTES) return undefined;
    text = fs.readFileSync(file, "utf8");
  } catch {
    return undefined;
  }
  try {
    return normalizeGrant(JSON.parse(text));
  } catch {
    return undefined;
  }
}

async function writeGrant(grant) {
  const file = await credentialFile();
  let dest;
  try {
    dest = fs.lstatSync(file);
  } catch {
    /* absent */
  }
  if (dest && (dest.isSymbolicLink() || !dest.isFile())) fail("storage", "Devin credential path is unsafe.");
  const temp = `${file}.${crypto.randomBytes(8).toString("hex")}.tmp`;
  let handle;
  try {
    handle = fs.openSync(
      temp,
      fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | (fs.constants.O_NOFOLLOW || 0),
      0o600,
    );
    fs.writeFileSync(handle, JSON.stringify(grant));
    fs.fsyncSync(handle);
  } catch (error) {
    if (handle !== undefined) {
      try {
        fs.closeSync(handle);
      } catch {
        /* ignore */
      }
    }
    try {
      fs.rmSync(temp, { force: true });
    } catch {
      /* ignore */
    }
    throw error;
  }
  try {
    fs.closeSync(handle);
  } catch {
    /* ignore */
  }
  try {
    fs.renameSync(temp, file);
  } catch (error) {
    try {
      fs.rmSync(temp, { force: true });
    } catch {
      /* ignore */
    }
    throw error;
  }
  try {
    fs.chmodSync(file, 0o600);
  } catch {
    /* best effort on Windows */
  }
  if (process.platform !== "win32") {
    try {
      const dirHandle = fs.openSync(path.dirname(file), fs.constants.O_RDONLY);
      try {
        fs.fsyncSync(dirHandle);
      } finally {
        fs.closeSync(dirHandle);
      }
    } catch {
      /* best effort */
    }
  }
}

async function clearGrant() {
  try {
    const file = await credentialFile();
    fs.rmSync(file, { force: true });
  } catch {
    /* nothing stored */
  }
}

function grantAvailable(grant) {
  return !!grant && !grant.revoked && grant.expiresAt > Date.now();
}

function statusText(grant) {
  if (!grant) return "Not logged in. Run: devin-search-mcp login";
  if (grant.revoked) return "Session rejected by provider; please log in again.";
  const when = new Date(grant.expiresAt).toISOString();
  return grantAvailable(grant)
    ? `Logged in. Expires ${when} (${grant.expirySource}, no auto-refresh).`
    : `Session expired; please log in again. Expires ${when} (${grant.expirySource}, no auto-refresh).`;
}

/* --------------------------------------------------------------------- net */

/**
 * Thin wrapper over global fetch returning the `{ status, text }` shape the
 * upstream code expects. Network failures raise a DevinError (callers in the
 * web_search loop catch it and try the next host).
 */
async function netFetch(url, { method = "GET", headers, body, timeoutMs = 20000 } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let response;
  try {
    response = await fetch(url, {
      method,
      headers,
      body: typeof body === "string" ? body : body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal,
      redirect: "manual",
    });
  } catch {
    fail("network", "Devin network request failed.");
  } finally {
    clearTimeout(timer);
  }
  const status = response && Number.isFinite(response.status) ? response.status : 0;
  let text = "";
  try {
    text = await response.text();
  } catch {
    text = "";
  }
  return { status, text };
}

/* ------------------------------------------------------------------- login */

const AUTH_BASE = "https://app.devin.ai/auth/cli/continue";
const TOKEN_URL = "https://api.devin.ai/auth/cli/token";

function validateCode(value) {
  if (typeof value !== "string" || value.length > 8192) fail("bounds", "Invalid Devin authorization code.");
  const code = value.trim();
  if (!code || /[\s\x00-\x1f\x7f]/.test(code)) fail("bounds", "Invalid Devin authorization code.");
  return code;
}

function buildAuthUrl() {
  const verifier = crypto.randomBytes(64).toString("base64url");
  const state = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  const url = new URL(AUTH_BASE);
  url.search = new URLSearchParams({
    state,
    prompt: "select_account",
    code_challenge: challenge,
    code_challenge_method: "S256",
  }).toString();
  return { url: url.toString(), verifier };
}

async function exchangeCode(code, verifier) {
  const response = await netFetch(TOKEN_URL, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ code, code_verifier: verifier }),
  });
  if (response.status < 200 || response.status >= 300) {
    fail("network", "Devin authorization code exchange failed; please retry login.");
  }
  let data;
  try {
    data = JSON.parse(response.text);
  } catch {
    fail("protocol", "Devin token exchange returned an invalid response.");
  }
  if (!data || typeof data.token !== "string" || !data.token || data.token.length > 16384) {
    fail("protocol", "Devin token exchange did not return a valid session.");
  }
  return data.token;
}

/** Best-effort open of a URL in the default browser; never fatal. */
function openBrowser(url) {
  let cmd;
  let args;
  if (process.platform === "darwin") {
    cmd = "open";
    args = [url];
  } else if (process.platform === "win32") {
    cmd = "cmd";
    args = ["/c", "start", "", url];
  } else {
    cmd = "xdg-open";
    args = [url];
  }
  try {
    const child = spawn(cmd, args, { stdio: "ignore", detached: true });
    child.on("error", () => {});
    child.unref();
  } catch {
    /* the URL is printed; the user can open it manually */
  }
}

async function runLogin() {
  const { url, verifier } = buildAuthUrl();
  process.stderr.write("\nDevin Search — login\n");
  process.stderr.write("1. Open this URL and sign in with your Devin account:\n\n");
  process.stderr.write(`   ${url}\n\n`);
  openBrowser(url);
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
  const answer = await new Promise((resolve) => rl.question("2. Paste the one-time code shown there: ", resolve));
  rl.close();
  const code = validateCode(answer);
  const token = toDevinSessionToken(await exchangeCode(code, verifier));
  await writeGrant({ version: 1, token, ...expiry(token) });
  completion?.invalidate();
  process.stderr.write(`\n${statusText(await readGrant())}\n`);
}

/* -------------------------------------------------------------- web_search */

const WEB_PATH = "/exa.api_server_pb.ApiServerService/GetWebSearchResults";
const WEB_HOSTS = ["https://server.codeium.com", "https://server.self-serve.windsurf.com"];
const WEB_TIMEOUT_MS = 20000;

async function webSearch(args) {
  const life = deadline(undefined, WEB_TIMEOUT_MS);
  const query = String((args && args.query) || "");
  if (!query.trim() || query.length > 8192) fail("bounds", "Devin query is empty or too long.");
  let limit = Math.trunc(Number((args && args.maxResults) !== undefined ? args.maxResults : 5));
  if (!Number.isFinite(limit)) fail("bounds", "Invalid Devin result count.");
  limit = Math.min(10, Math.max(1, limit));

  const grant = await readGrant();
  if (!grantAvailable(grant)) {
    fail("login", "Devin session missing, expired or revoked; please log in first (devin-search-mcp login).");
  }
  const token = toDevinSessionToken(grant.token);

  let authRejected = 0;
  let rateLimited = false;
  let hostsTried = 0;

  for (const host of WEB_HOSTS) {
    check(life);
    hostsTried += 1;
    let response;
    try {
      response = await netFetch(host + WEB_PATH, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "connect-protocol-version": "1",
          accept: "application/json",
          "user-agent": "windsurf/1.9600.41",
        },
        body: JSON.stringify({
          metadata: {
            apiKey: token,
            ideName: "windsurf",
            ideVersion: "1.9600.41",
            extensionName: "windsurf",
            extensionVersion: "1.9600.41",
            locale: "en",
          },
          query: query.trim(),
          limit,
        }),
      });
    } catch {
      continue;
    }

    if (response.status === 401 || response.status === 403) {
      authRejected += 1;
      continue;
    }
    if (isRateLimitStatus(response.status)) {
      rateLimited = true; // a 429/503 is account-level, but the second host is cheap — try it before reporting
      continue;
    }
    if (response.status < 200 || response.status >= 300) continue;

    let payload;
    try {
      payload = JSON.parse(response.text);
    } catch {
      fail("protocol", "Invalid Devin web search response.");
    }
    if (!payload || !Array.isArray(payload.results)) {
      fail("protocol", "Invalid Devin web search structure.");
    }

    const sources = [];
    let valid = 0;
    const first = (row, keys, cap) => {
      for (const key of keys) {
        const value = row[key];
        if (typeof value === "string" && value.trim()) return redact(value.trim().slice(0, cap), [token]);
      }
      return "";
    };
    for (const raw of payload.results) {
      if (!raw || typeof raw !== "object" || Array.isArray(raw)) continue;
      const url = first(raw, ["url", "sourceUrl", "webUrl", "link"], 4096);
      try {
        const parsed = new URL(url);
        if (!["https:", "http:"].includes(parsed.protocol) || parsed.username || parsed.password) continue;
      } catch {
        continue;
      }
      valid += 1;
      if (sources.length < limit) {
        sources.push({
          url,
          title: first(raw, ["title", "name", "webTitle"], 512),
          snippet: first(raw, ["snippet", "summary", "text", "content"], 4096),
        });
      }
    }
    const content = sources
      .map((source) => `${source.title || source.url}\n${source.url}\n${source.snippet || ""}`)
      .join("\n\n") || "No web results.";
    return { content, sources, truncated: valid > limit };
  }

  if (hostsTried > 0 && authRejected === hostsTried) {
    const current = await readGrant();
    if (current && toDevinSessionToken(current.token) === token) {
      await writeGrant({ ...current, revoked: true });
    }
    fail("login", "Devin session rejected; please log in again.");
  }
  if (rateLimited) {
    fail("ratelimit", rateLimitMessage());
  }
  fail("network", "Devin web search failed on all hosts.");
}

/* -------------------------------------------------------------- code_search */

let completion;

function getCompletion() {
  if (!completion) {
    completion = new WindsurfCompletion(
      async () => {
        const grant = await readGrant();
        if (!grantAvailable(grant)) {
          fail("login", "Devin session missing, expired or revoked; please log in first (devin-search-mcp login).");
        }
        return { token: toDevinSessionToken(grant.token) };
      },
      {
        onAuthRejected: async (token) => {
          const current = await readGrant();
          if (current && toDevinSessionToken(current.token) === token) {
            await writeGrant({ ...current, revoked: true });
          }
        },
      },
    );
  }
  return completion;
}

async function codeSearch(args) {
  const workspace = workspacePath();
  return runCodeSearch({
    searchTerm: args && args.search_term,
    subPath: args && args.path,
    fsApi: new NodeFs(workspace),
    workspacePath: workspace,
    completion: getCompletion(),
    signal: undefined,
  });
}

/* -------------------------------------------------------------------- tools */

const TOOL_DEFS = [
  {
    name: "web_search",
    description:
      "Read-only Devin/Windsurf web search. Query and results come from the Devin cloud; requires login (devin-search-mcp login).",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", maxLength: 8192, description: "The search query." },
        maxResults: {
          type: "integer",
          minimum: 1,
          maximum: 10,
          description: "Max number of sources to return, 1 to 10 (default 5).",
        },
      },
      required: ["query"],
      additionalProperties: false,
    },
  },
  {
    name: "code_search",
    description:
      "Cloud-planned, locally verified code search. Devin plans a bounded sequence of read-only commands that this server executes against the workspace (read-only, no shell, skips ignored/sensitive paths) and re-reads the final answer ranges. Requires login.",
    inputSchema: {
      type: "object",
      properties: {
        search_term: { type: "string", maxLength: 8192, description: "Literal code text to find." },
        path: { type: "string", description: "Optional workspace-relative subdirectory to narrow the search." },
      },
      required: ["search_term"],
      additionalProperties: false,
    },
  },
];

function textResult(text, isError = false) {
  const result = { content: [{ type: "text", text: String(text) }] };
  if (isError) result.isError = true;
  return result;
}

async function invokeTool(name, args) {
  try {
    if (name === "web_search") return textResult((await webSearch(args || {})).content);
    if (name === "code_search") return textResult((await codeSearch(args || {})).content);
    throw new Error(`Unknown tool: ${name}`);
  } catch (error) {
    return textResult(error instanceof DevinError ? error.message : safeError(error), true);
  }
}

/* -------------------------------------------------------------- MCP server */

async function runMcpServer() {
  const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
  const { StdioServerTransport } = require("@modelcontextprotocol/sdk/server/stdio.js");
  const { ListToolsRequestSchema, CallToolRequestSchema } = require("@modelcontextprotocol/sdk/types.js");

  const server = new Server(
    { name: "devin-search-mcp", version: pkgVersion() },
    {
      capabilities: { tools: {} },
      instructions:
        "Two read-only Devin search tools. web_search performs a Devin cloud web search. " +
        "code_search plans and verifies a code search inside the workspace. Both require " +
        "a prior login (node server.js login).",
    },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOL_DEFS }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    // invokeTool never throws: it wraps any failure as an MCP { isError } result.
    return await invokeTool(name, args || {});
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
  // stderr only — stdout is the MCP JSON-RPC channel.
  process.stderr.write(`[devin-search-mcp] ready (workspace: ${workspacePath()})\n`);
}

/* --------------------------------------------------------------------- CLI */

function printHelp() {
  process.stderr.write(
    [
      "devin-search-mcp — Devin search as an MCP stdio server.",
      "",
      "Usage:",
      "  node server.js                Run the MCP stdio server (default; used by MCP clients).",
      "  node server.js login          Log in to Devin (prints an auth URL, exchanges a one-time code).",
      "  node server.js status         Show login status.",
      "  node server.js logout         Clear stored Devin credentials.",
      "",
      "Environment:",
      "  DEVIN_SEARCH_WORKSPACE        Workspace root for code_search (default: process.cwd()).",
      "  DEVIN_SEARCH_CREDENTIALS_DIR  Credential store dir (default: ~/.devin-search-mcp).",
      "",
    ].join("\n"),
  );
}

async function main() {
  const cmd = process.argv[2];
  if (cmd === "login") {
    await runLogin();
    return;
  }
  if (cmd === "logout") {
    await clearGrant();
    process.stderr.write("Cleared local Devin credentials.\n");
    return;
  }
  if (cmd === "status") {
    process.stderr.write(`${statusText(await readGrant())}\n`);
    return;
  }
  if (cmd === "help" || cmd === "--help" || cmd === "-h") {
    printHelp();
    return;
  }
  if (cmd === undefined || cmd === "serve") {
    await runMcpServer();
    return;
  }
  process.stderr.write(`Unknown command: ${cmd}\n\n`);
  printHelp();
  process.exitCode = 1;
}

/* Exposed for tests (not part of the runtime API). */
module.exports = {
  NodeFs,
  workspacePath,
  credentialsDir,
  buildAuthUrl,
  statusText,
  normalizeGrant,
  _internal: { webSearch, codeSearch, netFetch, invokeTool, TOOL_DEFS },
};

/* Only run the CLI / MCP server when executed directly, not when required by tests. */
if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof DevinError ? error.message : (error && error.stack) || String(error)}\n`);
    process.exitCode = 1;
  });
}
