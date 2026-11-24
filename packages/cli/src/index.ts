import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { pathToFileURL } from 'node:url';
import {
  CollisionConfigSchema,
  defineConfig,
  runCollision,
  type CollisionConfig,
  type CollisionConfigInput,
  type CollisionEvent,
  type OAuthPkceLoginOptions,
  type RunCollisionOptions,
  type RunCollisionResult,
} from '@collision/core';
import { detectProject } from '@collision/detect';
import { runTui } from '@collision/tui';

export interface InstallerCliOptions {
  projectDir?: string;
  headless?: boolean;
  json?: boolean;
  dryRun?: boolean;
  gatewayUrl?: string;
  gatewayToken?: string;
  apiKey?: string;
  installEditorMcp?: boolean;
  oauthOptions?: OAuthPkceLoginOptions;
}

export async function runHeadless(
  config: CollisionConfig,
  options: RunCollisionOptions & { json?: boolean } = {},
): Promise<RunCollisionResult> {
  const onEvent = (ev: CollisionEvent) => {
    options.onEvent?.(ev);
    if (options.json) {
      process.stdout.write(`${JSON.stringify(ev)}\n`);
      return;
    }
    switch (ev.type) {
      case 'phase':
        process.stdout.write(`[collision] ${ev.message}\n`);
        break;
      case 'detected':
        process.stdout.write(
          `[collision] Detected ${ev.profile.framework?.name ?? 'generic'} (${ev.profile.packageManager})\n`,
        );
        break;
      case 'task_start':
        process.stdout.write(`[task] -> ${ev.label}\n`);
        break;
      case 'task_complete':
        process.stdout.write(`[task] ok ${ev.label}\n`);
        break;
      case 'task_error':
        process.stderr.write(`[task] err ${ev.label}: ${ev.error}\n`);
        break;
      case 'tool_blocked':
        process.stderr.write(`[security] blocked ${ev.tool}: ${ev.reason}\n`);
        break;
      case 'log':
        process.stdout.write(`[collision] ${ev.message}\n`);
        break;
      case 'report':
        process.stdout.write(`\n${ev.markdown}\n`);
        break;
      case 'done':
        if (!ev.ok && ev.error) {
          process.stderr.write(`[collision] failed: ${ev.error}\n`);
        }
        break;
    }
  };

  return runCollision(config, { ...options, onEvent });
}

/**
 * Factory so any devtool company can ship a branded `npx @acme/install` CLI
 * in ~10 lines of TypeScript.
 */
export function createInstaller(configInput: CollisionConfigInput) {
  const config = defineConfig(configInput);

  return {
    config,
    async run(cliOpts: InstallerCliOptions = {}): Promise<RunCollisionResult> {
      const useHeadless =
        cliOpts.headless ||
        cliOpts.json ||
        !process.stdout.isTTY ||
        process.env.CI === 'true';

      const isRemoteSession = Boolean(
        process.env.SSH_CONNECTION || process.env.SSH_CLIENT || process.env.SSH_TTY,
      );
      const headlessPromptForCode =
        useHeadless && !cliOpts.json && process.stdin.isTTY && isRemoteSession
          ? async (_authorizeUrl: string) =>
              new Promise<string | null>((resolve) => {
                const rl = readline.createInterface({
                  input: process.stdin,
                  output: process.stdout,
                });
                rl.question('Paste the OAuth callback URL or authorization code: ', (answer) => {
                  rl.close();
                  resolve(answer.trim() || null);
                });
              })
          : undefined;

      const runOpts: RunCollisionOptions = {
        projectDir: cliOpts.projectDir ?? process.cwd(),
        dryRun: cliOpts.dryRun,
        gatewayUrl: cliOpts.gatewayUrl,
        gatewayToken: cliOpts.gatewayToken,
        apiKey: cliOpts.apiKey,
        installEditorMcp: cliOpts.installEditorMcp,
        oauthOptions:
          cliOpts.oauthOptions || headlessPromptForCode
            ? {
                ...cliOpts.oauthOptions,
                promptForCode:
                  cliOpts.oauthOptions?.promptForCode ?? headlessPromptForCode,
              }
            : undefined,
      };

      if (useHeadless) {
        return runHeadless(config, { ...runOpts, json: cliOpts.json });
      }
      return runTui(config, runOpts);
    },
  };
}

export async function loadConfigFile(configPath: string): Promise<CollisionConfig> {
  const abs = path.resolve(configPath);
  if (!fs.existsSync(abs)) {
    throw new Error(`Config file not found: ${abs}`);
  }
  const configDir = path.dirname(abs);
  let config: CollisionConfig;
  if (abs.endsWith('.json')) {
    const raw = JSON.parse(fs.readFileSync(abs, 'utf8'));
    config = CollisionConfigSchema.parse(raw);
  } else {
    const mod = (await import(pathToFileURL(abs).href)) as {
      default?: CollisionConfigInput;
    };
    if (!mod.default) {
      throw new Error(`Config module ${abs} must export a default CollisionConfig`);
    }
    config = defineConfig(mod.default);
  }
  return {
    ...config,
    skills: {
      ...config.skills,
      sources: config.skills.sources.map((src) =>
        src.type === 'local' && !path.isAbsolute(src.dir)
          ? { ...src, dir: path.resolve(configDir, src.dir) }
          : src,
      ),
    },
  };
}

export { defineConfig, detectProject, runCollision, runTui };
