import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { ProjectProfile } from '@collision/detect';
import { installCommandFor } from '@collision/detect';
import type { CollisionConfig, TaskDefinition } from '../config.js';
import type { AskUserHandler, CollisionEventHandler } from '../events.js';
import type { ConnectedMcpTool } from '../mcp/client.js';
import {
  checkBashCommand,
  isPathBlockedForModelRead,
  redactSecretsInOutput,
  type SecurityPolicy,
} from '../security/fence.js';
import type { SecretVault } from '../security/secret-vault.js';
import type { SkillRegistry } from '../skills/loader.js';
import { resolveProvider } from './provider.js';

export interface PiTaskInput {
  config: CollisionConfig;
  profile: ProjectProfile;
  task: TaskDefinition;
  priorHandoffs: Array<{ taskId: string; summary: string }>;
  skills: SkillRegistry;
  mcpTools: ConnectedMcpTool[];
  vault: SecretVault;
  onEvent: CollisionEventHandler;
  askUser?: AskUserHandler;
  gatewayToken?: string;
  apiKey?: string;
  gatewayUrl?: string;
  signal?: AbortSignal;
}

export function buildSystemPrompt(
  config: CollisionConfig,
  profile: ProjectProfile,
  skills: SkillRegistry,
): string {
  const skillIndex = skills
    .listAvailable()
    .map((s) => `- ${s.id}: ${s.description}`)
    .join('\n');

  const lines = [
    `You are the ${config.vendor.name} installation agent powered by Collision.`,
    `Your job is to cleanly integrate ${config.vendor.name} into the user's local repository.`,
    '',
    '## Detected Project Profile',
    `- Directory: ${profile.projectDir}`,
    `- Framework: ${profile.framework ? `${profile.framework.name} (${profile.framework.id}${profile.framework.variant ? ` / ${profile.framework.variant}` : ''}${profile.framework.version ? ` @ ${profile.framework.version}` : ''})` : 'Unknown (inspect files directly)'}`,
    `- Ecosystem: ${profile.ecosystem}`,
    `- Package manager: ${profile.packageManager} (example install: \`${installCommandFor(profile.packageManager, ['<pkg>'])}\`)`,
    `- TypeScript: ${profile.hasTypeScript ? 'yes' : 'no'}`,
    `- Monorepo: ${profile.isMonorepo ? 'yes' : 'no'}`,
    `- Existing .env files: ${profile.envFiles.length ? profile.envFiles.join(', ') : 'none'}`,
    '',
    '## Hard Rules',
    '- NEVER hardcode API keys, tokens, or secrets in source files. Always write them via `set_env_values`.',
    '- NEVER try to read `.env` files directly; they are fenced to protect user secrets.',
    '- Read existing files before editing them and match the repository style.',
    '- Never run `git push` or destructive commands.',
  ];

  if (config.vendor.docsUrl) {
    lines.push(`- Official docs: ${config.vendor.docsUrl}`);
  }
  if (config.vendor.llmsTxtUrl) {
    lines.push(`- Machine-readable docs (llms.txt): ${config.vendor.llmsTxtUrl} (use fetch_doc)`);
  }
  if (config.cli.binary) {
    lines.push(
      `- Vendor CLI: \`${config.cli.binary}\`${config.cli.installCommand ? ` (install via \`${config.cli.installCommand}\`)` : ''}`,
    );
  }
  if (skillIndex) {
    lines.push('', '## Available Skills (call `load_skill` before editing)', skillIndex);
  }
  if (config.prompts.system) {
    lines.push('', '## Vendor Instructions', config.prompts.system);
  }
  if (config.prompts.extraRules.length > 0) {
    lines.push(
      '',
      '## Extra Vendor Rules',
      ...config.prompts.extraRules.map((r) => `- ${r}`),
    );
  }

  return lines.join('\n');
}

export function hashPrompt(prompt: string): string {
  return crypto.createHash('sha256').update(prompt).digest('hex');
}

function upsertEnvFile(
  projectDir: string,
  envFileName: string,
  entries: Record<string, string>,
  vault: SecretVault,
): string[] {
  const safeName = path.basename(envFileName);
  if (!safeName.startsWith('.env')) {
    throw new Error('set_env_values only writes to .env* files');
  }
  const target = path.join(projectDir, safeName);
  const existing = fs.existsSync(target) ? fs.readFileSync(target, 'utf8') : '';
  const lines = existing ? existing.split(/\r?\n/) : [];
  const writtenKeys: string[] = [];

  for (const [key, rawVal] of Object.entries(entries)) {
    const resolved = vault.resolve(rawVal);
    const formatted = `${key}=${resolved}`;
    const idx = lines.findIndex((l) => l.startsWith(`${key}=`));
    if (idx >= 0) {
      lines[idx] = formatted;
    } else {
      lines.push(formatted);
    }
    writtenKeys.push(key);
  }

  const content = `${lines.filter((l, i, arr) => !(i === arr.length - 1 && l === '')).join('\n')}\n`;
  fs.writeFileSync(target, content, 'utf8');
  return writtenKeys;
}

export async function runTaskWithPi(input: PiTaskInput): Promise<string> {
  const {
    config,
    profile,
    task,
    priorHandoffs,
    skills,
    mcpTools,
    vault,
    onEvent,
    askUser,
  } = input;

  const systemPrompt = buildSystemPrompt(config, profile, skills);
  const promptHash = hashPrompt(systemPrompt);
  const provider = resolveProvider(config, {
    gatewayToken: input.gatewayToken,
    apiKey: input.apiKey,
    gatewayUrl: input.gatewayUrl,
    model: task.model,
    promptHash,
  });

  const policy: SecurityPolicy = {
    projectDir: profile.projectDir,
    allowBash: config.security.allowBash,
    extraBlockedPaths: config.security.extraBlockedPaths,
    allowedBashPrefixes: [
      ...config.security.allowedBashPrefixes,
      ...(config.cli.binary ? [`${config.cli.binary} `] : []),
    ],
  };

  // Dynamic import keeps @collision/core light for non-runtime callers (tests, config inspection)
  const pi = await import('@earendil-works/pi-coding-agent');
  const { Type } = await import('@sinclair/typebox').catch(() => ({
    Type: null as unknown as Record<string, (...args: unknown[]) => unknown>,
  }));

  const { createAgentSession, DefaultResourceLoader, SessionManager, ModelRegistry } =
    pi as unknown as {
      createAgentSession: (opts: Record<string, unknown>) => Promise<{
        session: {
          prompt: (text: string) => Promise<void>;
          getLastAssistantText: () => string;
          subscribe: (fn: (ev: Record<string, unknown>) => void) => () => void;
          dispose: () => void;
          abort?: () => void;
        };
      }>;
      DefaultResourceLoader: new (opts?: Record<string, unknown>) => unknown;
      SessionManager: { inMemory: (cwd: string) => unknown };
      ModelRegistry?: new () => {
        registerProvider: (name: string, spec: Record<string, unknown>) => void;
        find: (provider: string, id: string) => unknown;
      };
    };

  const modelSpec = {
    id: provider.modelId,
    name: `${provider.modelId} (${provider.providerName})`,
    api: provider.api,
    provider: provider.providerName,
    baseUrl: provider.baseUrl,
    reasoning: false,
    input: ['text' as const],
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    contextWindow: 200_000,
    maxTokens: 16_384,
    headers: provider.headers,
  };

  let modelRegistry: unknown;
  if (ModelRegistry) {
    const reg = new ModelRegistry();
    reg.registerProvider(provider.providerName, {
      baseUrl: provider.baseUrl,
      apiKey: provider.apiKey,
      api: provider.api,
      headers: provider.headers,
      models: [modelSpec],
    });
    modelRegistry = reg;
  }

  const schemaObj = (properties: Record<string, unknown>, required: string[] = []) =>
    Type
      ? (Type as { Object: (p: unknown) => unknown }).Object(properties)
      : { type: 'object', properties, required };

  // Collision-owned tools: skill loader, docs fetcher, env writer, ask_user, and auto-connected MCP tools
  const customTools: Array<Record<string, unknown>> = [
    {
      name: 'load_skill',
      label: 'Load Skill',
      description: 'Load a framework or integration markdown skill by id.',
      parameters: schemaObj({ id: { type: 'string' } }, ['id']),
      async execute(_id: string, params: { id: string }) {
        onEvent({ type: 'tool_call', taskId: task.id, tool: 'load_skill', detail: params.id });
        const skill = await skills.get(params.id);
        if (!skill) {
          return {
            content: [{ type: 'text', text: `Skill "${params.id}" not found.` }],
            details: {},
          };
        }
        return {
          content: [{ type: 'text', text: skill.content }],
          details: { source: skill.source },
        };
      },
    },
    {
      name: 'fetch_doc',
      label: 'Fetch Documentation',
      description: 'Fetch vendor documentation or llms.txt from an allowlisted HTTPS URL.',
      parameters: schemaObj({ url: { type: 'string' } }, ['url']),
      async execute(_id: string, params: { url: string }) {
        onEvent({ type: 'tool_call', taskId: task.id, tool: 'fetch_doc', detail: params.url });
        const allowedHosts = new Set<string>();
        for (const u of [config.vendor.docsUrl, config.vendor.llmsTxtUrl, config.vendor.website]) {
          if (u) allowedHosts.add(new URL(u).host);
        }
        const parsed = new URL(params.url);
        if (parsed.protocol !== 'https:' || (allowedHosts.size > 0 && !allowedHosts.has(parsed.host))) {
          const reason = `URL host "${parsed.host}" is not in the vendor's allowed docs hosts`;
          onEvent({ type: 'tool_blocked', taskId: task.id, tool: 'fetch_doc', reason });
          return { content: [{ type: 'text', text: `Blocked: ${reason}` }], details: {} };
        }
        const res = await fetch(params.url);
        const text = (await res.text()).slice(0, 24_000);
        return { content: [{ type: 'text', text }], details: { status: res.status } };
      },
    },
    {
      name: 'set_env_values',
      label: 'Set Environment Variables',
      description:
        'Write key/value pairs to a .env file locally. Accepts secret:<uuid> handles returned by ask_user.',
      parameters: schemaObj(
        {
          file: { type: 'string', description: 'Target env file, e.g. .env.local' },
          values: { type: 'object', additionalProperties: { type: 'string' } },
        },
        ['file', 'values'],
      ),
      async execute(
        _id: string,
        params: { file: string; values: Record<string, string> },
      ) {
        onEvent({ type: 'tool_call', taskId: task.id, tool: 'set_env_values', detail: params.file });
        const keys = upsertEnvFile(profile.projectDir, params.file, params.values, vault);
        return {
          content: [
            {
              type: 'text',
              text: `Updated ${params.file} with keys: ${keys.join(', ')} (values kept local).`,
            },
          ],
          details: { keys },
        };
      },
    },
    {
      name: 'ask_user',
      label: 'Ask User',
      description:
        'Ask the user a clarifying question or request a secret value. Secret answers are returned as opaque secret:<uuid> handles.',
      parameters: schemaObj(
        {
          question: { type: 'string' },
          secret: { type: 'boolean' },
        },
        ['question'],
      ),
      async execute(_id: string, params: { question: string; secret?: boolean }) {
        if (!askUser) {
          return {
            content: [{ type: 'text', text: 'Non-interactive mode: proceed with sensible defaults.' }],
            details: {},
          };
        }
        const answer = await askUser({ question: params.question, secret: params.secret });
        const safeValue = params.secret ? vault.store(answer) : answer;
        return { content: [{ type: 'text', text: safeValue }], details: {} };
      },
    },
  ];

  // Register auto-connected MCP server tools
  for (const mcpTool of mcpTools) {
    customTools.push({
      name: mcpTool.name,
      label: mcpTool.name,
      description: mcpTool.description,
      parameters: mcpTool.inputSchema,
      async execute(_id: string, params: Record<string, unknown>) {
        onEvent({ type: 'tool_call', taskId: task.id, tool: mcpTool.name });
        const raw = await mcpTool.call(params);
        const { sanitized } = redactSecretsInOutput(vault.redact(raw));
        return { content: [{ type: 'text', text: sanitized }], details: {} };
      },
    });
  }

  // Security extension enforcing .env* read fence, bash allowlist, and secret redaction
  const securityExtension = {
    name: 'collision-security',
    onToolCall(event: { toolName: string; input?: Record<string, unknown> }) {
      const name = event.toolName.toLowerCase();
      if (name === 'read' || name === 'view') {
        const target = String(event.input?.path ?? event.input?.file_path ?? '');
        const blocked = isPathBlockedForModelRead(target, policy);
        if (blocked) {
          onEvent({ type: 'tool_blocked', taskId: task.id, tool: event.toolName, reason: blocked });
          return { block: true, reason: blocked };
        }
      }
      if (name === 'bash' || name === 'exec') {
        const cmd = String(event.input?.command ?? '');
        const blocked = checkBashCommand(cmd, policy);
        if (blocked) {
          onEvent({ type: 'tool_blocked', taskId: task.id, tool: event.toolName, reason: blocked });
          return { block: true, reason: blocked };
        }
      }
      onEvent({ type: 'tool_call', taskId: task.id, tool: event.toolName });
      return undefined;
    },
  };

  const resourceLoader = new DefaultResourceLoader({
    cwd: profile.projectDir,
    systemPromptOverride: () => systemPrompt,
    extensions: [securityExtension],
  });

  const { session } = await createAgentSession({
    model: modelSpec,
    modelRegistry,
    thinkingLevel: task.thinkingLevel ?? config.provider.thinkingLevel,
    cwd: profile.projectDir,
    sessionManager: SessionManager.inMemory(profile.projectDir),
    resourceLoader,
    customTools,
  });

  const onAbort = () => session.abort?.();
  input.signal?.addEventListener('abort', onAbort, { once: true });

  const unsubscribe = session.subscribe((ev) => {
    if (ev.type === 'message_update' && typeof ev.delta === 'string') {
      onEvent({ type: 'assistant_delta', taskId: task.id, text: ev.delta });
    }
  });

  try {
    const preloadedSkills: string[] = [];
    for (const skillId of task.skills) {
      const loaded = await skills.get(skillId);
      if (loaded) {
        preloadedSkills.push(`### Skill: ${loaded.id}\n${loaded.content}`);
      }
    }

    const handoffBlock = priorHandoffs.length
      ? [
          '## Handoffs from completed tasks',
          ...priorHandoffs.map((h) => `### ${h.taskId}\n${h.summary}`),
        ].join('\n\n')
      : '';

    const taskPrompt = [
      `## Current Task: ${task.label} (${task.id})`,
      task.prompt,
      preloadedSkills.join('\n\n'),
      handoffBlock,
    ]
      .filter(Boolean)
      .join('\n\n');

    await session.prompt(taskPrompt);
    const raw = session.getLastAssistantText() || `Completed task: ${task.label}`;
    return redactSecretsInOutput(vault.redact(raw)).sanitized;
  } finally {
    unsubscribe();
    input.signal?.removeEventListener('abort', onAbort);
    session.dispose();
  }
}
