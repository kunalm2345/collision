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
6. **Client-side Security:** Hard-blocks `.env*` and credential file reads, keeps user-entered secrets in an in-memory `SecretVault` (`secret:<uuid>` handles), enforces a bash allowlist, and redacts leaked key patterns from tool output.
7. **Go Gateway (`gateway/`):** Proxies OpenAI, Anthropic, and OpenRouter streams behind HMAC-signed short-lived run tokens, disposable-email blocking, system-prompt hash admission, model allowlists, per-IP/per-user rate limits, concurrency caps, and per-run turn budgets.

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
