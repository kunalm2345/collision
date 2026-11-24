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
  scanUntrustedContent,
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
    '- NEVER try to read `.env` files directly; they are fenced to protect user secrets. Use `check_env_keys` to check if keys already exist.',
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

function parseEnvValueUncommented(rawValue: string): string {
  const trimmed = rawValue.trim();
  if (!trimmed) return '';
  const quote = trimmed[0];
  if (quote === '"' || quote === "'") {
    const endIdx = trimmed.indexOf(quote, 1);
    return endIdx >= 1 ? trimmed.slice(1, endIdx) : trimmed.slice(1);
  }
  const commentIdx = trimmed.search(/(?:^|\s)#/);
  return (commentIdx >= 0 ? trimmed.slice(0, commentIdx) : trimmed).trim();
}

export function checkEnvKeysInProject(
  projectDir: string,
  keys: string[],
  envFileName?: string,
): Record<string, Array<{ file: string; status: 'present' | 'empty' }>> {
  const realRoot = fs.existsSync(projectDir) ? fs.realpathSync(projectDir) : path.resolve(projectDir);
  const candidates: string[] = [];

  const isSafeRegularEnvFile = (fileName: string): boolean => {
    const safeName = path.basename(fileName);
    if (!safeName.toLowerCase().startsWith('.env')) return false;
    const full = path.join(realRoot, safeName);
    try {
      const lstat = fs.lstatSync(full);
      if (lstat.isSymbolicLink() || !lstat.isFile()) return false;
      const realFull = fs.realpathSync(full);
      const rel = path.relative(realRoot, realFull);
      return !rel.startsWith('..') && !path.isAbsolute(rel);
    } catch {
      return false;
    }
  };

  if (envFileName) {
    const safeName = path.basename(envFileName);
    if (!safeName.toLowerCase().startsWith('.env')) {
      throw new Error('check_env_keys only inspects .env* files');
    }
    if (isSafeRegularEnvFile(safeName)) {
      candidates.push(safeName);
    }
  } else if (fs.existsSync(realRoot)) {
    for (const entry of fs.readdirSync(realRoot, { withFileTypes: true })) {
      if (entry.name.toLowerCase().startsWith('.env') && isSafeRegularEnvFile(entry.name)) {
        candidates.push(entry.name);
      }
    }
  }

  const found = new Map<string, Array<{ file: string; status: 'present' | 'empty' }>>();
  for (const key of keys) found.set(key, []);

  for (const file of candidates.sort()) {
    const raw = fs.readFileSync(path.join(realRoot, file), 'utf8');
    for (const line of raw.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const eq = trimmed.indexOf('=');
      if (eq === -1) continue;
      const k = trimmed.slice(0, eq).replace(/^export\s+/, '').trim();
      const bucket = found.get(k);
      if (!bucket) continue;
      const v = parseEnvValueUncommented(trimmed.slice(eq + 1));
      bucket.push({ file, status: v.length > 0 ? 'present' : 'empty' });
    }
  }
  return Object.fromEntries(found.entries());
}

export function filterSearchOutput(
  toolName: string,
  text: string,
  policy: SecurityPolicy,
): { filtered: string; omittedCount: number } {
  const lower = toolName.toLowerCase();
  if (lower !== 'grep' && lower !== 'find' && lower !== 'ls') {
    return { filtered: text, omittedCount: 0 };
  }
  const lines = text.split(/\r?\n/);
  const kept: string[] = [];
  let omittedCount = 0;

  for (const line of lines) {
    let candidate: string | null = null;
    if (lower === 'grep') {
      const m = line.match(/^([^:\r\n]+?)(?::\d+[: -]|-\d+-)/);
      if (m) candidate = m[1].trim();
    } else {
      const trimmed = line.trim().replace(/\/+$/, '');
      if (trimmed) candidate = trimmed;
    }

    if (candidate && isPathBlockedForModelRead(candidate, policy)) {
      omittedCount++;
      continue;
    }
    kept.push(line);
  }

  if (omittedCount > 0) {
    kept.push(`[Collision filtered ${omittedCount} protected path line(s) from ${toolName} output]`);
  }
  return { filtered: kept.join('\n'), omittedCount };
}

export async function fetchAllowlistedDoc(
  initialUrl: string,
  allowedHosts: Set<string>,
  maxRedirects = 5,
): Promise<{ ok: true; text: string; status: number } | { ok: false; reason: string }> {
  if (allowedHosts.size === 0) {
    return { ok: false, reason: 'No vendor documentation hosts configured in config.vendor' };
  }

  let currentUrl = initialUrl;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    let parsed: URL;
    try {
      parsed = new URL(currentUrl);
    } catch {
      return { ok: false, reason: `Invalid URL "${currentUrl}"` };
    }
    if (parsed.protocol !== 'https:' || !allowedHosts.has(parsed.host)) {
      return {
        ok: false,
        reason: `URL host "${parsed.host}" is not in the vendor's allowed docs hosts`,
      };
    }

    const res = await fetch(parsed.toString(), { redirect: 'manual' });
    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get('location');
      if (!location) {
        return { ok: false, reason: `Redirect from "${parsed.host}" missing Location header` };
      }
      currentUrl = new URL(location, parsed).toString();
      continue;
    }

    const text = (await res.text()).slice(0, 24_000);
    return { ok: true, text, status: res.status };
  }

  return { ok: false, reason: `Exceeded maximum redirects (${maxRedirects})` };
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
  const mappedTaskModel =
    config.provider.taskModels &&
    Object.prototype.hasOwnProperty.call(config.provider.taskModels, task.id)
      ? config.provider.taskModels[task.id]
      : undefined;
  const taskModel = task.model ?? mappedTaskModel;
  const provider = resolveProvider(config, {
    gatewayToken: input.gatewayToken,
    apiKey: input.apiKey,
    gatewayUrl: input.gatewayUrl,
    model: taskModel,
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
        try {
          const skill = await skills.get(params.id, {
            scanRemoteContent: config.security.scanRemoteContent,
          });
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
        } catch (err) {
          const reason = err instanceof Error ? err.message : String(err);
          onEvent({ type: 'tool_blocked', taskId: task.id, tool: 'load_skill', reason });
          return { content: [{ type: 'text', text: `Blocked: ${reason}` }], details: {} };
        }
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
        const fetched = await fetchAllowlistedDoc(params.url, allowedHosts);
        if (!fetched.ok) {
          onEvent({ type: 'tool_blocked', taskId: task.id, tool: 'fetch_doc', reason: fetched.reason });
          return { content: [{ type: 'text', text: `Blocked: ${fetched.reason}` }], details: {} };
        }
        const text = fetched.text;
        if (config.security.scanRemoteContent) {
          const scan = scanUntrustedContent(text);
          if (!scan.safe) {
            const reason = `Remote doc from "${params.url}" failed security scan (${scan.findings.join(', ')})`;
            onEvent({ type: 'tool_blocked', taskId: task.id, tool: 'fetch_doc', reason });
            return { content: [{ type: 'text', text: `Blocked: ${reason}` }], details: {} };
          }
        }
        return { content: [{ type: 'text', text }], details: { status: fetched.status } };
      },
    },
    {
      name: 'check_env_keys',
      label: 'Check Environment Variable Keys',
      description:
        'Check whether specific environment variable keys exist in .env* files without ever revealing their values.',
      parameters: Type.Object({
        keys: Type.Array(Type.String({ description: 'Environment variable names to check' })),
        file: Type.Optional(
          Type.String({ description: 'Optional specific .env* file (defaults to scanning all .env* files)' }),
        ),
      }),
      async execute(_id, rawParams) {
        const params = rawParams as { keys: string[]; file?: string };
        const results = checkEnvKeysInProject(profile.projectDir, params.keys, params.file);
        const lines = Object.entries(results).map(([k, matches]) =>
          matches.length
            ? `${k}: ${matches.map((m) => `${m.file} (${m.status})`).join(', ')}`
            : `${k}: missing`,
        );
        return {
          content: [{ type: 'text', text: lines.join('\n') || 'No keys requested.' }],
          details: { results },
        };
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
        const candidates = [
          inputObj.path,
          inputObj.file_path,
          inputObj.glob,
          inputObj.pattern,
        ]
          .filter((v): v is string => typeof v === 'string' && v.trim().length > 0);
        for (const target of candidates) {
          const blocked = isPathBlockedForModelRead(target, policy);
          if (blocked) {
            onEvent({ type: 'tool_blocked', taskId: task.id, tool: event.toolName, reason: blocked });
            return { block: true, reason: blocked };
          }
          if ((name === 'grep' || name === 'find') && /(^|[/\\*])\.env(\b|\.)/i.test(target) && !/\.example\b|\.sample\b|\.template\b/i.test(target)) {
            const reason = `Searching "${target}" is blocked to keep .env secrets off the LLM`;
            onEvent({ type: 'tool_blocked', taskId: task.id, tool: event.toolName, reason });
            return { block: true, reason };
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
          let nextText = part.text;
          const searchFiltered = filterSearchOutput(event.toolName, nextText, policy);
          if (searchFiltered.omittedCount > 0) {
            onEvent({
              type: 'tool_blocked',
              taskId: task.id,
              tool: event.toolName,
              reason: `Filtered ${searchFiltered.omittedCount} protected path line(s) from ${event.toolName} output`,
            });
            nextText = searchFiltered.filtered;
          }
          nextText = redactSecretsInOutput(vault.redact(nextText)).sanitized;
          if (nextText !== part.text) {
            changed = true;
            return { ...part, text: nextText };
          }
        }
        return part;
      });

      if (config.security.scanRemoteContent) {
        const combinedText = sanitizedContent
          .filter((p): p is { type: 'text'; text: string } => p.type === 'text' && typeof p.text === 'string')
          .map((p) => p.text)
          .join('\n');
        const scan = scanUntrustedContent(combinedText);
        if (!scan.safe) {
          const reason = `Blocked suspicious content in ${event.toolName} output (${scan.findings.join(', ')})`;
          onEvent({ type: 'tool_blocked', taskId: task.id, tool: event.toolName, reason });
          return {
            content: [{ type: 'text' as const, text: `Blocked: ${reason}` }],
          };
        }
      }

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

  const allToolNames = [
    'read',
    'bash',
    'edit',
    'write',
    'grep',
    'find',
    'ls',
    ...customTools.map((t) => t.name),
  ];
  let enabledTools = allToolNames;
  if (task.allowedTools !== undefined) {
    const allowedSet = new Set(task.allowedTools);
    const unknown = task.allowedTools.filter((name) => !allToolNames.includes(name));
    if (unknown.length > 0) {
      onEvent({
        type: 'log',
        level: 'warn',
        message: `Task "${task.id}" references unknown tool(s) in allowedTools: ${unknown.join(', ')}`,
      });
    }
    enabledTools = allToolNames.filter((name) => allowedSet.has(name));
  }

  const { session } = await pi.createAgentSession({
    model,
    modelRuntime,
    thinkingLevel: task.thinkingLevel ?? config.provider.thinkingLevel,
    cwd: profile.projectDir,
    sessionManager: pi.SessionManager.inMemory(profile.projectDir),
    resourceLoader,
    tools: enabledTools,
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
      try {
        const loaded = await skills.get(skillId, {
          scanRemoteContent: config.security.scanRemoteContent,
        });
        if (loaded) {
          preloadedSkills.push(`### Skill: ${loaded.id}\n${loaded.content}`);
        }
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        onEvent({ type: 'tool_blocked', taskId: task.id, tool: 'load_skill', reason });
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
