import { createInstaller } from 'collision';

/**
 * Copy this template to publish your own branded `npx @your-org/install` CLI.
 * Point `provider.kind` to `"gateway"` in production so your users never need
 * to supply their own LLM API key.
 */
export const installer = createInstaller({
  vendor: {
    id: 'your-product',
    name: 'Your Product',
    tagline: 'Automated SDK & integration setup',
    docsUrl: 'https://docs.example.com',
    llmsTxtUrl: 'https://docs.example.com/llms.txt',
  },
  provider: {
    // Supported: "gateway" | "openai" | "anthropic" | "openrouter"
    kind: 'gateway',
    model: 'claude-sonnet-4-5',
    gatewayUrl: process.env.COLLISION_GATEWAY_URL ?? 'https://gateway.example.com',
  },
  prompts: {
    system:
      'Integrate Your Product cleanly following existing project conventions. Keep changes minimal and verify builds.',
  },
  skills: {
    sources: [{ type: 'local', dir: './skills' }],
  },
  mcp: {
    servers: [
      {
        id: 'your-product-mcp',
        name: 'Your Product MCP',
        transport: 'http',
        url: 'https://mcp.example.com/mcp',
        installInEditors: true,
      },
    ],
    installIntoEditors: true,
  },
  cli: {
    binary: 'your-cli',
    installCommand: 'npm install -g @your-org/cli',
    allowedSubcommands: ['init', 'status'],
  },
});

if (import.meta.url === `file://${process.argv[1]}`) {
  installer.run().then((res) => {
    process.exitCode = res.ok ? 0 : 1;
  });
}
