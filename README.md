# Collision

An open-source, modular harness for building local AI install agents (like `npx @posthog/wizard`) for any developer tool.

Collision separates **reusable install-agent infrastructure** from **vendor-specific knowledge** (prompts, skills, docs, MCP servers, and CLI tools) so any devtool company can ship a reliable, branded `npx @your-org/install` CLI backed by a fast Go gateway.

## Architecture

```text
packages/
  detect/    Deterministic framework & package-manager detection (Next.js, Vite, Express, FastAPI, Go, Rust, + custom)
  core/      Pi local coding-agent loop, dependency-aware task graph, .env* read fence, secret vault, skills/docs loader, MCP client
  tui/       Interactive Ink (React) terminal UI host
  cli/       `npx collision` binary, headless CI host, and `createInstaller(config)` factory
gateway/     Zero-dependency Go SSE streaming proxy (OpenAI, Anthropic, OpenRouter) + short-lived tokens + anti-spam & turn budgets
template/    Vendor-neutral starter pack (config, skills, branded CLI entry)
```

### How a run works

1. **Local execution:** Everything runs inside the user's terminal (`npx`). Only files/snippets the agent explicitly reads are sent to the model.
2. **Detection (`@collision/detect`):** Detects ecosystem, framework, variant (e.g. Next.js App vs Pages Router), and package manager before spending LLM tokens.
3. **Skills & Docs (`@collision/core`):** Loads matching Markdown skills from local directories, URLs, or a remote JSON skill menu, and lets the agent fetch vendor docs on demand.
4. **MCP & CLI:** Auto-connects the vendor's remote HTTP or stdio MCP server during the run and optionally registers it in Cursor, Claude Code, and VS Code.
5. **Task Graph + Pi Loop:** Runs a dependency-ordered task graph (`install` -> `configure` -> `verify` -> `report`) via `@earendil-works/pi-coding-agent` with parallel waves for independent tasks.
6. **Client-side Security:** Hard-blocks `.env*` and credential file reads (including `grep`/`find`/`ls`), exposes `check_env_keys` + `set_env_values` so secrets stay local, keeps user-entered secrets in an in-memory `SecretVault` (`secret:<uuid>` handles), enforces a bash allowlist, scans remote skills/docs/tool outputs for prompt-injection patterns, and redacts leaked key patterns.
7. **Go Gateway (`gateway/`):** Proxies OpenAI, Anthropic, and OpenRouter streams behind HMAC-signed short-lived run tokens, disposable-email blocking, system-prompt hash admission, model allowlists, per-IP/per-user rate limits, concurrency caps, and per-run turn budgets (default `100`).

## What Collision Handles vs. What You Bring

Collision intentionally stays vendor-neutral. It provides the local agent harness, security boundaries, and LLM gateway, while leaving product auth and backend logic to your stack:

| Concern | Handled by Collision | Built & hosted by you |
|---|---|---|
| **Local agent & TUI** | Pi loop, task graph, per-task model routing (`provider.taskModels`), Ink TUI + headless CI | Branded wrapper via `createInstaller(config)` (e.g. `npx @your-org/install`) |
| **Detection & skills** | Framework/package-manager detection, local/URL/menu Markdown skill loader, `fetch_doc` | Your framework skills, prompts, and `llms.txt` / docs URLs |
| **Auth & login screen** | Optional OAuth PKCE CLI helper (`auth: { type: "oauth-pkce" }`) with local callback + paste-code fallback; accepts `gatewayToken` + per-server `mcpTokens` in `runCollision()` | Your OAuth / device-flow login screen & backend that mints gateway tokens via `POST /v1/tokens` |
| **Product MCP / CLI** | Connects HTTP/stdio MCP servers during the run & installs them into Cursor/Claude Code/VS Code | Your remote MCP server & product-specific tools (e.g. creating projects, dashboards, API keys) |
| **LLM gateway & anti-spam** | Go proxy (`gateway/`), rate limits, turn budgets, prompt-hash & model allowlists, disposable-email block | Hosting the gateway binary + supplying upstream OpenAI/Anthropic/OpenRouter keys |

### Vendor Setup Checklist

1. **Copy `template/`** and customize `collision.config.json` (vendor metadata, `provider.model` / `provider.taskModels`, `skills.sources`, `mcp.servers`, and `prompts.tasks`).
2. **Add your own OAuth / login flow** (if you want zero-copy-paste project tokens or hosted LLM access): set `provider.kind` to `"gateway"` (direct `"openai"`/`"anthropic"`/`"openrouter"` ignores `gatewayToken`), configure `auth: { type: "oauth-pkce", authorizeUrl, tokenUrl, clientId, gatewayExchangeUrl }` (or pass `gatewayToken` / `mcpTokens` directly into `runCollision()`), and have your backend mint short-lived tokens via `POST /v1/tokens` on the Collision Go gateway using `COLLISION_ADMIN_KEY`.
3. **Wire your MCP server (optional):** expose tools for creating product resources (projects, dashboards, webhooks) and list the server under `mcp.servers` with `auth: "bearer"` (or `"none"` for public docs MCPs).
4. **Publish your branded CLI** using `createInstaller(config)` from `collision` (see `template/installer.ts`).

## Quick Start

```bash
pnpm install
pnpm build
pnpm test
```

Run a dry-run against any local repository using the starter template:

```bash
node packages/cli/dist/bin.js run --config ./template/collision.config.json --dir . --dry-run
```

## Running the Go Gateway

```bash
cd gateway
export COLLISION_TOKEN_SECRET="replace-with-32-byte-secret"
export COLLISION_ADMIN_KEY="replace-with-admin-key"
export ANTHROPIC_API_KEY="sk-ant-..."   # and/or OPENAI_API_KEY, OPENROUTER_API_KEY
go run ./cmd/collision-gateway
```

Mint a short-lived run token (called by your backend after OAuth/device login):

```bash
curl -X POST http://localhost:8787/v1/tokens \
  -H "Authorization: Bearer $COLLISION_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"run_id":"run-123","user_id":"user-456","email":"dev@company.com","vendor_id":"your-product"}'
```

## License

MIT
