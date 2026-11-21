import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { ProjectProfile } from '@collision/detect';
import { installCommandFor } from '@collision/detect';
import type {
  ExtensionFactory,
  ToolDefinition,
} from '@earendil-works/pi-coding-agent';
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
  const { Type } = await import('@sinclair/typebox');

  const modelRuntime = await pi.ModelRuntime.create({ refreshOnCreate: false });
  modelRuntime.registerProvider(provider.providerName, {
    baseUrl: provider.baseUrl,
    apiKey: provider.apiKey,
    api: provider.api as Parameters<typeof modelRuntime.registerProvider>[1]['api'],
    headers: provider.headers,
    models: [
      {
        id: provider.modelId,
        name: `${provider.modelId} (${provider.providerName})`,
        api: provider.api as Parameters<typeof modelRuntime.registerProvider>[1]['api'],
        reasoning: false,
        input: ['text'],
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
        contextWindow: 200_000,
        maxTokens: 16_384,
      },
    ],
  });

  const model = modelRuntime.getModel(provider.providerName, provider.modelId);
  if (!model) {
    throw new Error(
      `Failed to resolve model "${provider.modelId}" on provider "${provider.providerName}"`,
    );
  }

  // Collision-owned tools: skill loader, docs fetcher, env writer, ask_user, and auto-connected MCP tools
  const customTools: ToolDefinition[] = [
    {
      name: 'load_skill',
      label: 'Load Skill',
      description: 'Load a framework or integration markdown skill by id.',
      parameters: Type.Object({
        id: Type.String({ description: 'Skill identifier from the Available Skills list' }),
      }),
      async execute(_id, rawParams) {
        const params = rawParams as { id: string };
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
      parameters: Type.Object({
        url: Type.String({ description: 'HTTPS documentation URL on an allowlisted vendor host' }),
      }),
      async execute(_id, rawParams) {
        const params = rawParams as { url: string };
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
      parameters: Type.Object({
        file: Type.String({ description: 'Target env file, e.g. .env.local' }),
        values: Type.Record(Type.String(), Type.String()),
      }),
      async execute(_id, rawParams) {
        const params = rawParams as { file: string; values: Record<string, string> };
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
      parameters: Type.Object({
        question: Type.String({ description: 'Question to ask the user' }),
        secret: Type.Optional(Type.Boolean({ description: 'Mask input and store in local secret vault' })),
      }),
      async execute(_id, rawParams) {
        const params = rawParams as { question: string; secret?: boolean };
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
      parameters: mcpTool.inputSchema as unknown as ToolDefinition['parameters'],
      async execute(_id, params) {
        const raw = await mcpTool.call((params ?? {}) as Record<string, unknown>);
        const { sanitized } = redactSecretsInOutput(vault.redact(raw));
        return { content: [{ type: 'text', text: sanitized }], details: {} };
      },
    });
  }

  // Pi 1.6 ExtensionFactory enforcing .env* read fence, bash allowlist, and output secret redaction
  const securityExtensionFactory: ExtensionFactory = (extApi) => {
    extApi.on('tool_call', (event) => {
      const name = event.toolName.toLowerCase();
      const inputObj = (event.input ?? {}) as Record<string, unknown>;
      if (name === 'read' || name === 'view' || name === 'grep' || name === 'find' || name === 'ls') {
        const target = String(inputObj.path ?? inputObj.file_path ?? '');
        if (target) {
          const blocked = isPathBlockedForModelRead(target, policy);
          if (blocked) {
            onEvent({ type: 'tool_blocked', taskId: task.id, tool: event.toolName, reason: blocked });
            return { block: true, reason: blocked };
          }
        }
      }
      if (name === 'bash' || name === 'exec') {
        const cmd = String(inputObj.command ?? '');
        const blocked = checkBashCommand(cmd, policy);
        if (blocked) {
          onEvent({ type: 'tool_blocked', taskId: task.id, tool: event.toolName, reason: blocked });
          return { block: true, reason: blocked };
        }
      }
      const detail =
        typeof inputObj.path === 'string'
          ? inputObj.path
          : typeof inputObj.command === 'string'
            ? inputObj.command
            : typeof inputObj.id === 'string'
              ? inputObj.id
              : typeof inputObj.url === 'string'
                ? inputObj.url
                : typeof inputObj.file === 'string'
                  ? inputObj.file
                  : undefined;
      onEvent({ type: 'tool_call', taskId: task.id, tool: event.toolName, detail });
      return undefined;
    });

    extApi.on('tool_result', (event) => {
      if (!Array.isArray(event.content)) return undefined;
      let changed = false;
      const sanitizedContent = event.content.map((part) => {
        if (part.type === 'text' && typeof part.text === 'string') {
          const { sanitized } = redactSecretsInOutput(vault.redact(part.text));
          if (sanitized !== part.text) {
            changed = true;
            return { ...part, text: sanitized };
          }
        }
        return part;
      });
      return changed ? { content: sanitizedContent } : undefined;
    });
  };

  const resourceLoader = new pi.DefaultResourceLoader({
    cwd: profile.projectDir,
    agentDir: pi.getAgentDir(),
    noExtensions: true,
    noSkills: true,
    noPromptTemplates: true,
    noThemes: true,
    extensionFactories: [securityExtensionFactory],
    systemPromptOverride: () => systemPrompt,
  });
  await resourceLoader.reload();

  const { session } = await pi.createAgentSession({
    model,
    modelRuntime,
    thinkingLevel: task.thinkingLevel ?? config.provider.thinkingLevel,
    cwd: profile.projectDir,
    sessionManager: pi.SessionManager.inMemory(profile.projectDir),
    resourceLoader,
    customTools,
  });

  const onAbort = () => {
    void session.abort();
  };
  input.signal?.addEventListener('abort', onAbort, { once: true });

  const unsubscribe = session.subscribe((ev) => {
    if (
      ev.type === 'message_update' &&
      'assistantMessageEvent' in ev &&
      ev.assistantMessageEvent.type === 'text_delta'
    ) {
      onEvent({
        type: 'assistant_delta',
        taskId: task.id,
        text: ev.assistantMessageEvent.delta,
      });
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

    const lastMsg = [...session.messages]
      .reverse()
      .find((m) => m.role === 'assistant');
    if (
      lastMsg &&
      'stopReason' in lastMsg &&
      lastMsg.stopReason === 'error'
    ) {
      const errMsg =
        'errorMessage' in lastMsg && typeof lastMsg.errorMessage === 'string'
          ? lastMsg.errorMessage
          : 'Model returned an error response';
      throw new Error(errMsg);
    }

    const raw = session.getLastAssistantText() || `Completed task: ${task.label}`;
    return redactSecretsInOutput(vault.redact(raw)).sanitized;
  } finally {
    unsubscribe();
    input.signal?.removeEventListener('abort', onAbort);
    session.dispose();
  }
}
