#!/usr/bin/env node
import { createInstaller, detectProject, loadConfigFile } from './index.js';

function printHelp(): void {
  process.stdout.write(
    [
      'collision — open-source install-agent harness',
      '',
      'Usage:',
      '  collision run --config <path> [--dir <path>] [--dry-run] [--headless] [--json]',
      '  collision detect [--dir <path>]',
      '',
      'Options:',
      '  --config <path>         Path to collision.config.json or .mjs/.js',
      '  --dir <path>            Target repository directory (default: cwd)',
      '  --gateway-url <url>     Override Collision gateway URL',
      '  --gateway-token <tok>   Override short-lived gateway run token',
      '  --dry-run               Detect project, load skills, print task plan without calling LLM',
      '  --headless              Force non-TTY output (auto-enabled in CI)',
      '  --json                  Emit NDJSON events in headless mode',
      '  -h, --help              Show this help',
    ].join('\n') + '\n',
  );
}

function parseArgs(argv: string[]) {
  const command = argv[0];
  const flags: Record<string, string | boolean> = {};
  for (let i = 1; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '-h' || arg === '--help') {
      flags.help = true;
    } else if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const next = argv[i + 1];
      if (next && !next.startsWith('--')) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    }
  }
  return { command, flags };
}

async function main(): Promise<void> {
  const { command, flags } = parseArgs(process.argv.slice(2));
  if (!command || flags.help || command === '--help' || command === '-h') {
    printHelp();
    return;
  }

  const dir = typeof flags.dir === 'string' ? flags.dir : process.cwd();

  if (command === 'detect') {
    const profile = await detectProject(dir);
    process.stdout.write(`${JSON.stringify(profile, null, 2)}\n`);
    return;
  }

  if (command === 'run') {
    const configPath =
      typeof flags.config === 'string' ? flags.config : 'collision.config.json';
    const config = await loadConfigFile(configPath);
    const installer = createInstaller(config);
    const result = await installer.run({
      projectDir: dir,
      dryRun: Boolean(flags['dry-run']),
      headless: Boolean(flags.headless),
      json: Boolean(flags.json),
      gatewayUrl:
        typeof flags['gateway-url'] === 'string' ? flags['gateway-url'] : undefined,
      gatewayToken:
        typeof flags['gateway-token'] === 'string' ? flags['gateway-token'] : undefined,
    });
    process.exitCode = result.ok ? 0 : 1;
    return;
  }

  process.stderr.write(`Unknown command: ${command}\n`);
  printHelp();
  process.exitCode = 1;
}

main().catch((err) => {
  process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 1;
});
