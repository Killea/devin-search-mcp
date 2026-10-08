"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const os = require("node:os");
const path = require("node:path");
const fsp = require("node:fs/promises");

const { NodeFs, buildAuthUrl, statusText, normalizeGrant, _internal } = require("../server");
const { wildcard, isForbiddenPath, parseAnswer, parseStructuredAnswer, command } = require("../lib/code-search");
const { loadIgnoreRules, isIgnored } = require("../lib/gitignore");
const { Writer, decode, stringField } = require("../lib/protobuf");
const { frame, streamText } = require("../lib/protocol");
const { redact, isRateLimitStatus, rateLimitMessage } = require("../lib/core");

/* ------------------------------------------------------------------ NodeFs */

test("NodeFs.glob lists files, skips symlinks, returns workspace-relative paths", async () => {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), "dsh-fs-"));
  try {
    await fsp.mkdir(path.join(root, "src"), { recursive: true });
    await fsp.writeFile(path.join(root, "README.md"), "# hi\n");
    await fsp.writeFile(path.join(root, "src", "a.js"), "needle_foo\n");
    await fsp.symlink(path.join(root, "src"), path.join(root, "link-to-src")); // dir symlink
    await fsp.symlink(path.join(root, "src", "a.js"), path.join(root, "b.js")); // file symlink

    const all = await new NodeFs(root).glob("**/*");
    assert.ok(all.includes("README.md"), "top-level file listed");
    assert.ok(all.includes("src/a.js"), "nested file listed");
    assert.ok(!all.includes("b.js"), "symlinked file is skipped");
    assert.ok(!all.some((p) => p.startsWith("link-to-src/")), "symlinked dir is not traversed");
    assert.ok(all.every((p) => !p.includes("\\")), "paths use forward slashes");

    const sub = await new NodeFs(root).glob("src/**/*");
    assert.deepEqual(sub, ["src/a.js"]);
  } finally {
    await fsp.rm(root, { recursive: true, force: true });
  }
});

test("NodeFs.readText/stat work; escaping the workspace is refused", async () => {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), "dsh-fs2-"));
  try {
    await fsp.writeFile(path.join(root, "x.txt"), "hello");
    const nfs = new NodeFs(root);
    assert.equal(await nfs.readText("x.txt"), "hello");
    const st = await nfs.stat("x.txt");
    assert.equal(st.size, 5);
    assert.equal(st.isFile, true);

    await assert.rejects(nfs.readText("../escape.txt"), /escap/i);
    await assert.rejects(nfs.stat("../../etc/passwd"), /escap/i);
    await assert.rejects(nfs.readText(""), /escap|not found/i);
  } finally {
    await fsp.rm(root, { recursive: true, force: true });
  }
});

/* ------------------------------------------------------- pure lib (no fs) */

test("wildcard: * crosses separators, ? is one char", () => {
  assert.ok(wildcard("*.js", "a.js"));
  assert.ok(wildcard("*.js", "src/a.js"));
  assert.ok(wildcard("a?c", "abc"));
  assert.ok(!wildcard("a?c", "abbc"));
  assert.ok(!wildcard("x.js", "a.js"));
});

test("isForbiddenPath rejects sensitive/generated segments", () => {
  assert.ok(isForbiddenPath("node_modules/x/index.js"));
  assert.ok(isForbiddenPath(".env"));
  assert.ok(isForbiddenPath("src/config/secret.yml"));
  assert.ok(isForbiddenPath("keys/id_rsa"));
  assert.ok(isForbiddenPath("certs/server.pem"));
  assert.ok(!isForbiddenPath("src/main.ts"));
  assert.ok(!isForbiddenPath("docs/readme.md"));
});

test("command: rg requires a nonempty pattern; ls/glob/readfile do not", () => {
  assert.throws(() => command({ op: "rg", path: "/codebase" }), /nonempty pattern/);
  assert.throws(() => command({ op: "rg", path: "/codebase", pattern: "   " }), /nonempty pattern/);
  assert.doesNotThrow(() => command({ op: "rg", path: "/codebase", pattern: "x" }));
  assert.doesNotThrow(() => command({ op: "ls", path: "/codebase" }));
  assert.doesNotThrow(() => command({ op: "glob", path: "/codebase", pattern: "*.js" }));
  assert.doesNotThrow(() => command({ op: "readfile", path: "/codebase/a.js", start: 1, end: 10 }));
});

test("parseAnswer (strict XML) extracts file ranges", () => {
  const xml = '<ANSWER><file path="/codebase/src/a.ts"><range>1-10</range></file></ANSWER>';
  assert.deepEqual(parseAnswer(xml), [{ path: "/codebase/src/a.ts", start: 1, end: 10 }]);
});

test("parseStructuredAnswer collects refs and rejects bad ranges", () => {
  assert.deepEqual(parseStructuredAnswer({ files: [] }), []);
  assert.deepEqual(
    parseStructuredAnswer({ files: [{ path: "/codebase/a.ts", ranges: [{ start: 2, end: 5 }] }] }),
    [{ path: "/codebase/a.ts", start: 2, end: 5 }],
  );
  assert.throws(() => parseStructuredAnswer({ files: [{ path: "a", ranges: [{ start: 5, end: 2 }] }] }), /range/i);
});

test("gitignore rules: load + isIgnored", async () => {
  const rules = await loadIgnoreRules(
    [".gitignore", "src/a.js", "a.log"],
    async (rel) => (rel === ".gitignore" ? "ignored.js\n*.log\n" : ""),
  );
  assert.ok(isIgnored(rules, "src/ignored.js"));
  assert.ok(isIgnored(rules, "a.log"));
  assert.ok(!isIgnored(rules, "src/a.js"));
});

test("protobuf Writer/decode round-trip", () => {
  const fields = decode(new Writer().int(1, 7).string(2, "hello").build());
  assert.equal(fields.find((f) => f.field === 1).value, 7);
  assert.equal(stringField(fields, 2), "hello");
});

test("protocol streamText decodes a text frame + trailer and strips the EOS </s>", () => {
  const textPayload = new Writer().string(2, "answer</s>").build();
  const trailerPayload = Buffer.from(JSON.stringify({}));
  const buffer = Buffer.concat([frame(textPayload, 0), frame(trailerPayload, 2)]);
  assert.equal(streamText(buffer), "answer");
});

test("redact hides session-secret fragments", () => {
  assert.equal(redact("hello abc123 world", ["devin-session-token$abc123"]), "hello [redacted] world");
});

test("isRateLimitStatus flags 429/503 (and only those); message says retry", () => {
  assert.ok(isRateLimitStatus(429));
  assert.ok(isRateLimitStatus(503));
  assert.ok(isRateLimitStatus("429")); // numeric string
  assert.ok(!isRateLimitStatus(200));
  assert.ok(!isRateLimitStatus(401)); // still an auth rejection, not a throttle
  assert.ok(!isRateLimitStatus(403));
  assert.ok(!isRateLimitStatus(404));
  assert.ok(!isRateLimitStatus(500));
  assert.ok(!isRateLimitStatus(0));
  assert.match(rateLimitMessage(), /throttl/i);
  assert.match(rateLimitMessage(), /retry/i);
});

/* ------------------------------------------------------------- login/CLI */

test("buildAuthUrl emits PKCE S256 params on the Devin auth host", () => {
  const { url, verifier } = buildAuthUrl();
  const u = new URL(url);
  assert.equal(u.origin, "https://app.devin.ai");
  assert.ok(u.searchParams.get("code_challenge"));
  assert.equal(u.searchParams.get("code_challenge_method"), "S256");
  assert.ok(u.searchParams.get("state"));
  assert.ok(verifier.length >= 32);
});

test("normalizeGrant round-trips a valid grant and rejects bad ones", () => {
  const now = Date.now();
  const grant = normalizeGrant({ version: 1, token: "abc.def.ghi", expiresAt: now + 3600000, expirySource: "fallback" });
  assert.ok(grant);
  assert.equal(grant.token, "abc.def.ghi");
  assert.match(statusText(grant), /Logged in/);
  assert.equal(normalizeGrant({ version: 2, token: "x", expiresAt: now, expirySource: "fallback" }), undefined);
});

/* ------------------------------------------- end-to-end tool (no network) */

test("web_search and code_search surface a clean login error when not logged in", async () => {
  const credDir = await fsp.mkdtemp(path.join(os.tmpdir(), "dsh-cred-"));
  const ws = await fsp.mkdtemp(path.join(os.tmpdir(), "dsh-ws-"));
  const oldCred = process.env.DEVIN_SEARCH_CREDENTIALS_DIR;
  const oldWs = process.env.DEVIN_SEARCH_WORKSPACE;
  process.env.DEVIN_SEARCH_CREDENTIALS_DIR = credDir;
  process.env.DEVIN_SEARCH_WORKSPACE = ws;
  try {
    await fsp.writeFile(path.join(ws, "a.js"), "needle_foo\n");

    const web = await _internal.invokeTool("web_search", { query: "hello" });
    assert.equal(web.isError, true);
    assert.match(web.content[0].text, /log in/i);

    const code = await _internal.invokeTool("code_search", { search_term: "needle_foo" });
    assert.equal(code.isError, true);
    assert.match(code.content[0].text, /log in/i);
  } finally {
    if (oldCred === undefined) delete process.env.DEVIN_SEARCH_CREDENTIALS_DIR;
    else process.env.DEVIN_SEARCH_CREDENTIALS_DIR = oldCred;
    if (oldWs === undefined) delete process.env.DEVIN_SEARCH_WORKSPACE;
    else process.env.DEVIN_SEARCH_WORKSPACE = oldWs;
    await fsp.rm(credDir, { recursive: true, force: true });
    await fsp.rm(ws, { recursive: true, force: true });
  }
});

test("web_search surfaces a clear rate-limit message when Devin throttles (429)", async () => {
  const credDir = await fsp.mkdtemp(path.join(os.tmpdir(), "dsh-cred429-"));
  const ws = await fsp.mkdtemp(path.join(os.tmpdir(), "dsh-ws429-"));
  const oldCred = process.env.DEVIN_SEARCH_CREDENTIALS_DIR;
  const oldWs = process.env.DEVIN_SEARCH_WORKSPACE;
  const realFetch = global.fetch;
  process.env.DEVIN_SEARCH_CREDENTIALS_DIR = credDir;
  process.env.DEVIN_SEARCH_WORKSPACE = ws;
  // A valid, unexpired grant so web_search clears the login gate before it fetches.
  const grant = normalizeGrant({
    version: 1,
    token: "test.jwt.token",
    expiresAt: Date.now() + 3600000,
    expirySource: "fallback",
  });
  try {
    await fsp.writeFile(path.join(credDir, "credentials.json"), JSON.stringify(grant));
    // Both Devin hosts answer 429 (rate limit / usage quota / capacity).
    global.fetch = async () => ({ status: 429, text: async () => "" });

    const web = await _internal.invokeTool("web_search", { query: "hello" });
    assert.equal(web.isError, true);
    assert.match(web.content[0].text, /throttl/i);
    assert.match(web.content[0].text, /retry/i);
    // The clear throttle message must replace the generic all-hosts failure.
    assert.doesNotMatch(web.content[0].text, /failed on all hosts/i);
  } finally {
    global.fetch = realFetch;
    if (oldCred === undefined) delete process.env.DEVIN_SEARCH_CREDENTIALS_DIR;
    else process.env.DEVIN_SEARCH_CREDENTIALS_DIR = oldCred;
    if (oldWs === undefined) delete process.env.DEVIN_SEARCH_WORKSPACE;
    else process.env.DEVIN_SEARCH_WORKSPACE = oldWs;
    await fsp.rm(credDir, { recursive: true, force: true });
    await fsp.rm(ws, { recursive: true, force: true });
  }
});
