# Collision Vendor Template

Copy this folder to create an install agent for your own developer tool.

## Quick start (dry run)

```bash
npx collision run --config ./collision.config.json --dir /path/to/target-repo --dry-run
```

## Quick start (BYOK)

```bash
export OPENAI_API_KEY="sk-..." # or ANTHROPIC_API_KEY / OPENROUTER_API_KEY
npx collision run --config ./collision.config.json --dir /path/to/target-repo
```

## Branded CLI (`npx @your-org/install`)

Use `installer.ts` as the entry point for your own npm package and point `provider.kind` to `"gateway"` once you deploy `gateway/`.
