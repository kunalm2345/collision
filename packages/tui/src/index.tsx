import React, { useEffect, useState } from 'react';
import { Box, Text, render, useApp, useInput } from 'ink';
import type {
  AskUserPrompt,
  CollisionConfig,
  CollisionEvent,
  RunCollisionOptions,
  RunCollisionResult,
} from '@collision/core';
import { runCollision } from '@collision/core';

interface TaskRow {
  id: string;
  label: string;
  status: 'running' | 'done' | 'error';
  detail?: string;
}

interface PendingQuestion {
  prompt: AskUserPrompt;
  resolve: (answer: string) => void;
}

interface AppProps {
  config: CollisionConfig;
  options: RunCollisionOptions;
  onComplete: (result: RunCollisionResult) => void;
}

function CollisionApp({ config, options, onComplete }: AppProps) {
  const { exit } = useApp();
  const [phase, setPhase] = useState('Starting...');
  const [detected, setDetected] = useState<string | null>(null);
  const [tasks, setTasks] = useState<TaskRow[]>([]);
  const [logs, setLogs] = useState<string[]>([]);
  const [report, setReport] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [question, setQuestion] = useState<PendingQuestion | null>(null);
  const [draft, setDraft] = useState('');

  useInput(
    (input, key) => {
      if (!question) return;
      if (key.return) {
        const answer = draft.trim() || question.prompt.defaultValue || '';
        const resolver = question.resolve;
        setQuestion(null);
        setDraft('');
        resolver(answer);
        return;
      }
      if (key.backspace || key.delete) {
        setDraft((prev) => prev.slice(0, -1));
        return;
      }
      if (!key.ctrl && !key.meta && input) {
        setDraft((prev) => prev + input);
      }
    },
    { isActive: Boolean(question) },
  );

  useEffect(() => {
    let active = true;

    const handleEvent = (ev: CollisionEvent) => {
      if (!active) return;
      options.onEvent?.(ev);

      switch (ev.type) {
        case 'phase':
          setPhase(ev.message);
          break;
        case 'detected':
          setDetected(
            `${ev.profile.framework?.name ?? 'Generic project'} (${ev.profile.packageManager})`,
          );
          break;
        case 'mcp_connected':
          setLogs((prev) => [
            ...prev.slice(-6),
            `MCP connected: ${ev.serverId} (${ev.toolCount} tools)`,
          ]);
          break;
        case 'mcp_failed':
          setLogs((prev) => [
            ...prev.slice(-6),
            `MCP skipped (${ev.serverId}): ${ev.error}`,
          ]);
          break;
        case 'task_start':
          setTasks((prev) => [
            ...prev.filter((t) => t.id !== ev.taskId),
            { id: ev.taskId, label: ev.label, status: 'running' },
          ]);
          break;
        case 'tool_call':
          setTasks((prev) =>
            prev.map((t) =>
              t.id === ev.taskId
                ? { ...t, detail: `${ev.tool}${ev.detail ? `(${ev.detail})` : ''}` }
                : t,
            ),
          );
          break;
        case 'tool_blocked':
          setLogs((prev) => [
            ...prev.slice(-6),
            `Blocked ${ev.tool}: ${ev.reason}`,
          ]);
          break;
        case 'task_complete':
          setTasks((prev) =>
            prev.map((t) =>
              t.id === ev.taskId ? { ...t, status: 'done', detail: undefined } : t,
            ),
          );
          break;
        case 'task_error':
          setTasks((prev) =>
            prev.map((t) =>
              t.id === ev.taskId ? { ...t, status: 'error', detail: ev.error } : t,
            ),
          );
          break;
        case 'report':
          setReport(ev.markdown);
          break;
        case 'done':
          if (!ev.ok && ev.error) setError(ev.error);
          break;
        case 'log':
          setLogs((prev) => [...prev.slice(-6), ev.message]);
          break;
      }
    };

    const askUser = (prompt: AskUserPrompt) =>
      new Promise<string>((resolve) => {
        setQuestion({ prompt, resolve });
      });

    void runCollision(config, {
      ...options,
      onEvent: handleEvent,
      askUser: options.askUser ?? askUser,
    }).then((result) => {
      onComplete(result);
      setTimeout(() => exit(), 50);
    });

    return () => {
      active = false;
    };
  }, []);

  return (
    <Box flexDirection="column" padding={1}>
      <Box borderStyle="round" borderColor="cyan" paddingX={1} flexDirection="column">
        <Text bold color="cyan">
          {config.vendor.name} Installer · powered by Collision
        </Text>
        <Text dimColor>{config.vendor.tagline ?? phase}</Text>
      </Box>

      {detected && (
        <Box marginTop={1}>
          <Text>
            <Text bold>Detected: </Text>
            <Text color="green">{detected}</Text>
          </Text>
        </Box>
      )}

      {tasks.length > 0 && (
        <Box flexDirection="column" marginTop={1}>
          {tasks.map((t) => (
            <Text key={t.id}>
              <Text
                color={
                  t.status === 'done'
                    ? 'green'
                    : t.status === 'error'
                      ? 'red'
                      : 'yellow'
                }
              >
                {t.status === 'done' ? '[ok]' : t.status === 'error' ? '[err]' : '[..]'}
              </Text>{' '}
              {t.label}
              {t.detail ? <Text dimColor> · {t.detail}</Text> : null}
            </Text>
          ))}
        </Box>
      )}

      {question && (
        <Box
          marginTop={1}
          borderStyle="single"
          borderColor="yellow"
          paddingX={1}
          flexDirection="column"
        >
          <Text bold color="yellow">
            Input needed: {question.prompt.question}
          </Text>
          <Text>
            &gt; {question.prompt.secret ? '*'.repeat(draft.length) : draft}
          </Text>
        </Box>
      )}

      {logs.length > 0 && (
        <Box flexDirection="column" marginTop={1}>
          {logs.map((line, i) => (
            <Text key={i} dimColor>
              {line}
            </Text>
          ))}
        </Box>
      )}

      {error && (
        <Box marginTop={1}>
          <Text color="red">Error: {error}</Text>
        </Box>
      )}

      {report && (
        <Box marginTop={1} flexDirection="column">
          <Text bold color="green">
            Summary
          </Text>
          <Text>{report}</Text>
        </Box>
      )}
    </Box>
  );
}

export async function runTui(
  config: CollisionConfig,
  options: RunCollisionOptions = {},
): Promise<RunCollisionResult> {
  let finalResult: RunCollisionResult | null = null;
  const instance = render(
    <CollisionApp
      config={config}
      options={options}
      onComplete={(res) => {
        finalResult = res;
      }}
    />,
  );
  await instance.waitUntilExit();
  if (!finalResult) {
    throw new Error('Collision TUI exited before producing a result');
  }
  return finalResult;
}
