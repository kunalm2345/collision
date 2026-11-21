import path from 'node:path';
import { detectProject, type ProjectProfile } from '@collision/detect';
import type { CollisionConfig } from '../config.js';
import type { AskUserHandler, CollisionEventHandler } from '../events.js';
import {
  connectMcpServer,
  installMcpIntoEditors,
  type ConnectedMcpServer,
} from '../mcp/client.js';
import { SecretVault } from '../security/secret-vault.js';
import { SkillRegistry } from '../skills/loader.js';
import {
  defaultInstallTasks,
  planTaskWaves,
  type TaskResult,
} from '../tasks/graph.js';
import { runTaskWithPi } from './pi-runner.js';

export interface RunCollisionOptions {
  projectDir?: string;
  gatewayToken?: string;
  gatewayUrl?: string;
  apiKey?: string;
  dryRun?: boolean;
  installEditorMcp?: boolean;
  onEvent?: CollisionEventHandler;
  askUser?: AskUserHandler;
  signal?: AbortSignal;
}

export interface RunCollisionResult {
  ok: boolean;
  profile: ProjectProfile;
  tasks: TaskResult[];
  reportMarkdown: string;
  durationMs: number;
  error?: string;
}

export async function runCollision(
  config: CollisionConfig,
  options: RunCollisionOptions = {},
): Promise<RunCollisionResult> {
  const startedAt = Date.now();
  const projectDir = path.resolve(options.projectDir ?? process.cwd());
  const emit: CollisionEventHandler = options.onEvent ?? (() => {});
  const vault = new SecretVault();
  const connectedMcp: ConnectedMcpServer[] = [];
  const taskResults: TaskResult[] = [];

  try {
    emit({ type: 'phase', phase: 'detecting', message: `Inspecting ${projectDir}` });
    const profile = await detectProject(projectDir, config.detectors ?? []);
    emit({ type: 'detected', profile });

    emit({ type: 'phase', phase: 'loading_skills', message: 'Loading vendor skills & docs' });
    const skills = new SkillRegistry();
    await skills.loadSources(config.skills.sources, profile);
    const available = skills.listAvailable();
    emit({
      type: 'skills_loaded',
      count: available.length,
      ids: available.map((s) => s.id),
    });

    if (config.mcp.servers.length > 0 && !options.dryRun) {
      emit({
        type: 'phase',
        phase: 'connecting_mcp',
        message: `Connecting ${config.mcp.servers.length} MCP server(s)`,
      });
      for (const server of config.mcp.servers) {
        try {
          const conn = await connectMcpServer(server, options.gatewayToken);
          connectedMcp.push(conn);
          emit({
            type: 'mcp_connected',
            serverId: server.id,
            toolCount: conn.tools.length,
          });
        } catch (err) {
          emit({
            type: 'mcp_failed',
            serverId: server.id,
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }
    }

    const tasks = config.prompts.tasks ?? defaultInstallTasks(config.vendor.name);
    const waves = planTaskWaves(tasks);

    if (options.dryRun) {
      const planMarkdown = [
        `# ${config.vendor.name} — Dry Run Plan`,
        `- Framework: ${profile.framework?.name ?? 'Unknown'} (${profile.packageManager})`,
        `- Skills matched: ${available.map((s) => s.id).join(', ') || 'none'}`,
        `- Task waves: ${waves.map((w, i) => `Wave ${i + 1}: ${w.map((t) => t.id).join(', ')}`).join(' → ')}`,
      ].join('\n');
      const durationMs = Date.now() - startedAt;
      emit({ type: 'report', markdown: planMarkdown });
      emit({ type: 'done', ok: true, durationMs });
      return {
        ok: true,
        profile,
        tasks: [],
        reportMarkdown: planMarkdown,
        durationMs,
      };
    }

    emit({
      type: 'phase',
      phase: 'running',
      message: `Executing ${tasks.length} task(s) across ${waves.length} wave(s)`,
    });

    const mcpTools = connectedMcp.flatMap((c) => c.tools);

    for (const wave of waves) {
      const waveResults = await Promise.all(
        wave.map(async (task) => {
          emit({ type: 'task_start', taskId: task.id, label: task.label });
          try {
            const summary = await runTaskWithPi({
              config,
              profile,
              task,
              priorHandoffs: taskResults.map((r) => ({
                taskId: r.taskId,
                summary: r.summary,
              })),
              skills,
              mcpTools,
              vault,
              onEvent: emit,
              askUser: options.askUser,
              gatewayToken: options.gatewayToken,
              gatewayUrl: options.gatewayUrl,
              apiKey: options.apiKey,
              signal: options.signal,
            });
            emit({ type: 'task_complete', taskId: task.id, label: task.label, summary });
            return { taskId: task.id, label: task.label, summary };
          } catch (err) {
            const message = err instanceof Error ? err.message : String(err);
            emit({ type: 'task_error', taskId: task.id, label: task.label, error: message });
            throw err;
          }
        }),
      );
      taskResults.push(...waveResults);
    }

    if ((options.installEditorMcp ?? config.mcp.installIntoEditors) && config.mcp.servers.length) {
      const installed = installMcpIntoEditors(config.mcp.servers, projectDir);
      for (const item of installed) {
        if (item.updated) {
          emit({
            type: 'log',
            level: 'info',
            message: `Registered MCP in ${item.editor} (${item.configPath})`,
          });
        }
      }
    }

    const reportMarkdown =
      taskResults[taskResults.length - 1]?.summary ??
      `Finished ${config.vendor.name} installation.`;

    const durationMs = Date.now() - startedAt;
    emit({ type: 'phase', phase: 'completed', message: 'Installation complete' });
    emit({ type: 'report', markdown: reportMarkdown });
    emit({ type: 'done', ok: true, durationMs });

    return {
      ok: true,
      profile,
      tasks: taskResults,
      reportMarkdown,
      durationMs,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const durationMs = Date.now() - startedAt;
    emit({ type: 'phase', phase: 'error', message });
    emit({ type: 'done', ok: false, durationMs, error: message });
    return {
      ok: false,
      profile: {
        projectDir,
        framework: null,
        ecosystem: 'unknown',
        packageManager: 'unknown',
        isMonorepo: false,
        hasTypeScript: false,
        envFiles: [],
        allMatches: [],
      },
      tasks: taskResults,
      reportMarkdown: '',
      durationMs,
      error: message,
    };
  } finally {
    vault.clear();
    await Promise.allSettled(connectedMcp.map((c) => c.close()));
  }
}
