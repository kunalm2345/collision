import type { ProjectProfile } from '@collision/detect';

export type CollisionPhase =
  | 'detecting'
  | 'authenticating'
  | 'loading_skills'
  | 'connecting_mcp'
  | 'running'
  | 'reporting'
  | 'completed'
  | 'error';

export type CollisionEvent =
  | { type: 'phase'; phase: CollisionPhase; message: string }
  | { type: 'detected'; profile: ProjectProfile }
  | { type: 'skills_loaded'; count: number; ids: string[] }
  | { type: 'mcp_connected'; serverId: string; toolCount: number }
  | { type: 'mcp_failed'; serverId: string; error: string }
  | { type: 'task_start'; taskId: string; label: string }
  | { type: 'task_complete'; taskId: string; label: string; summary: string }
  | { type: 'task_error'; taskId: string; label: string; error: string }
  | { type: 'tool_call'; taskId: string; tool: string; detail?: string }
  | { type: 'tool_blocked'; taskId: string; tool: string; reason: string }
  | { type: 'assistant_delta'; taskId: string; text: string }
  | { type: 'log'; level: 'info' | 'warn' | 'error'; message: string }
  | { type: 'report'; markdown: string; filePath?: string }
  | { type: 'done'; ok: boolean; durationMs: number; error?: string };

export type CollisionEventHandler = (event: CollisionEvent) => void;

export interface AskUserPrompt {
  question: string;
  secret?: boolean;
  choices?: string[];
  defaultValue?: string;
}

export type AskUserHandler = (prompt: AskUserPrompt) => Promise<string>;
