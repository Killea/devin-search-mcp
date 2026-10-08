# devin-search-mcp

An [MCP](https://modelcontextprotocol.io) (Model Context Protocol) **stdio server** that
exposes two read-only **Devin** search tools to any MCP host (ZCode, Claude Desktop,
Cursor, …):

- **`web_search`** — Devin cloud web search.
- **`code_search`** — cloud-planned, locally verified code search. Devin plans a bounded
  sequence of read-only commands; this server executes them **read-only** against your
  workspace (no shell, no subprocess), then re-reads the final answer ranges before
  returning them.

This is a port of [`leafmoes/pi-devin-search`](https://github.com/leafmoes/pi-devin-search)
(which itself ports `mimimaster/dsh-devin-search`) from a PI-Desktop native plugin to a
standalone MCP server, so the tools work with any MCP host — not just PI-Desktop.

## How it differs from the PI-Desktop plugin

| Concern | PI-Desktop plugin | this MCP server |
| --- | --- | --- |
| File access | `pi.fs.*` (host-gated) | `node:fs` via a workspace-relative adapter |
| Network (login, web) | `pi.net.fetch` (domain-fenced) | global `fetch` |
| Network (code planning) | raw `node:https` | raw `node:https` (unchanged) |
| Workspace | active PI-Desktop workspace | server working directory / `DEVIN_SEARCH_WORKSPACE` |
| Login | in-app panel | CLI: `node server.js login` |
| Tool registration | `pi.agent.registerTool` | MCP `tools/list` + `tools/call` |

The `lib/` search core (protocol, protobuf, cloud client, sandbox, gitignore, core) is the
upstream implementation kept **byte-for-byte identical**, so the ported surface is
trivially diffable against the reference. Only the host glue (`main.js` in the plugin)
was rewritten here as `server.js`.

## Security model

- **Credentials.** A Devin session token is stored in `~/.devin-search-mcp/credentials.json`
  (mode `0600`, atomic temp+rename+fsync, symlink-rejecting). Override the directory with
  `DEVIN_SEARCH_CREDENTIALS_DIR`. The token is never written to config or model context and
  is redacted out of every result.
- **Network.** Login token-exchange and `web_search` call `api.devin.ai` / `server.codeium.com` /
  `server.self-serve.windsurf.com` via `fetch`. `code_search`'s cloud planning uses a
  Connect/protobuf stream (raw `node:https`) because the binary frames can't be carried as JSON.
- **Local execution is sandboxed.** `code_search` only *reads* files under the workspace, never
  follows symlinks, skips generated and secret-looking paths (`.git`, `node_modules`, `dist`,
  `.env*`, `*secret*`, `id_rsa`, `*.pem`, …), honors `.gitignore`, and enforces byte/line
  budgets. It never spawns a shell and never writes.

> An MCP server is a local process your MCP client spawns. It runs with your user's
> privileges and makes network calls to Devin's endpoints. Review it before running, and only
> point it at workspaces you're comfortable having searched.

## Install

Requires Node.js **>= 18.17** (uses global `fetch`).

```sh
git clone https://github.com/Killea/devin-search-mcp
cd devin-search-mcp
npm install
```

## Login

The search tools require a Devin account.

```sh
node server.js login      # prints an auth URL; open it, sign in, paste the one-time code
node server.js status     # show login state / expiry
node server.js logout     # clear local credentials
```

There is no automatic token refresh — re-run `login` when the session expires.

## Configure

### ZCode

Add a stdio MCP server to `~/.zcode/cli/config.json`:

```json5
{
  "mcp": {
    "servers": {
      "devin-search": {
        "type": "stdio",
        // use an ABSOLUTE path to node — ZCode's spawn PATH may be minimal
        "command": "/abs/path/to/node",
        "args": ["/abs/path/to/devin-search-mcp/server.js"],
        // keep this above code_search's 90 s internal deadline (MCP default is 30 s)
        "timeoutMs": 120000
      }
    }
  }
}
```

- **`cwd` is optional (and usually better left out).** When omitted, `code_search` searches
  the **active ZCode project** — the server inherits its working directory from the client,
  so it follows whatever folder you're working in. Set `cwd` (or `DEVIN_SEARCH_WORKSPACE` in
  `env`) only to pin the search to one specific directory.
- **`timeoutMs` must exceed `code_search`'s 90 s internal deadline.** ZCode's default MCP
  tool timeout is 30 s, which would cut long code searches short.
- ZCode loads MCP servers at startup, so **quit and reopen ZCode** after adding the entry.
  The tools then appear as `mcp__devin-search__web_search` and
  `mcp__devin-search__code_search`.

### Any other MCP client

Same shape — a stdio command `node <path>/server.js`. For example, Claude Desktop's
`claude_desktop_config.json`:

```json
{ "mcpServers": { "devin-search": { "command": "node", "args": ["/abs/path/server.js"], "env": { "DEVIN_SEARCH_WORKSPACE": "/abs/project" } } } }
```

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `DEVIN_SEARCH_WORKSPACE` | `process.cwd()` | Workspace root for `code_search`. |
| `DEVIN_SEARCH_CREDENTIALS_DIR` | `~/.devin-search-mcp` | Where `credentials.json` is stored. |

## Tools

### `web_search`

| arg | type | required | notes |
| --- | --- | --- | --- |
| `query` | string | yes | the search query (≤ 8192 chars) |
| `maxResults` | integer | no | 1–10 (default 5) |

Returns formatted `title / url / snippet` blocks as text.

### `code_search`

| arg | type | required | notes |
| --- | --- | --- | --- |
| `search_term` | string | yes | literal code text to find (≤ 8192 chars) |
| `path` | string | no | workspace-relative subdirectory to narrow the search |

Runs up to 8 cloud-planned turns (6 command turns + 2), a 90 s deadline, single-concurrent,
and verifies every cited file/range against the workspace before returning it.

## Rate limits & errors

Both tools surface distinct, actionable errors instead of a generic failure:

- **Rate limit / quota.** If Devin throttles the account (HTTP `429`) or its upstream is over
  capacity (`503`), the tools report a clear throttle message:

  > *Devin is throttling requests right now (rate limit / usage quota / upstream capacity).
  > Wait a moment and retry — the free tier has unpublished daily/weekly quotas, so this is
  > usually transient.*

  This replaces the previous generic "failed on all hosts" / "completion request failed" text,
  so a throttle is obvious at a glance. The free Devin tier has daily/weekly usage quotas whose
  size is not published per account; the fast model these tools use (`swe-1-6-fast`) is
  normally unmetered, so throttling is usually transient.
- **Session rejected.** A `401`/`403` is treated as an auth rejection — the stored grant is
  marked revoked and you're told to run `login` again.
- **Not logged in / expired.** Run `node server.js login`.

## Tests

```sh
npm test        # node --test
```

Covers the host-agnostic core (protobuf/protocol/sandbox primitives), the `node:fs`
adapter (including symlink-skip and workspace-escape refusal), and the full
`tools/call` path's not-logged-in error. The Devin cloud calls themselves require a real
login and are not covered by unit tests.

## License

[MIT](./LICENSE). See [NOTICE](./NOTICE) — ported from MIT-licensed upstream work.
