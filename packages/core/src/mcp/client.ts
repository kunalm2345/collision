import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import type { McpServerConfig } from '../config.js';

export interface ConnectedMcpTool {
  serverId: string;
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  call(args: Record<string, unknown>): Promise<string>;
}

export interface ConnectedMcpServer {
  config: McpServerConfig;
  tools: ConnectedMcpTool[];
  close(): Promise<void>;
}

export async function connectMcpServer(
  server: McpServerConfig,
  authToken?: string,
): Promise<ConnectedMcpServer> {
  const client = new Client({
    name: 'collision-harness',
    version: '0.1.0',
  });

  if (server.transport === 'http') {
    if (!server.url) {
      throw new Error(`MCP server "${server.id}" requires a url for http transport`);
    }
    const parsedUrl = new URL(server.url);
    const headers: Record<string, string> = { ...(server.headers ?? {}) };
    if (authToken && !headers.Authorization) {
      const isLocalhost =
        parsedUrl.hostname === '127.0.0.1' || parsedUrl.hostname === 'localhost';
      if (parsedUrl.protocol !== 'https:' && !isLocalhost) {
        throw new Error(
          `Refusing to send bearer token to non-HTTPS MCP server "${server.id}" (${parsedUrl.protocol}//${parsedUrl.host})`,
        );
      }
      headers.Authorization = `Bearer ${authToken}`;
    }
    const transport = new StreamableHTTPClientTransport(parsedUrl, {
      requestInit: { headers },
    });
    await client.connect(transport);
  } else {
    if (!server.command) {
      throw new Error(`MCP server "${server.id}" requires a command for stdio transport`);
    }
    const transport = new StdioClientTransport({
      command: server.command,
      args: server.args ?? [],
    });
    await client.connect(transport);
  }

  const listed = await client.listTools();
  const tools: ConnectedMcpTool[] = listed.tools.map((tool) => ({
    serverId: server.id,
    name: `mcp_${server.id}_${tool.name}`.replace(/[^a-zA-Z0-9_-]/g, '_'),
    description: `[MCP:${server.name}] ${tool.description ?? tool.name}`,
    inputSchema: (tool.inputSchema ?? { type: 'object', properties: {} }) as Record<
      string,
      unknown
    >,
    async call(args: Record<string, unknown>): Promise<string> {
      const res = await client.callTool({
        name: tool.name,
        arguments: args,
      });
      return JSON.stringify(res.content ?? res, null, 2);
    },
  }));

  return {
    config: server,
    tools,
    async close() {
      await client.close();
    },
  };
}

export interface EditorMcpInstallResult {
  editor: string;
  configPath: string;
  updated: boolean;
}

/**
 * Registers vendor MCP servers in common AI editors (Cursor, Claude Code, VS Code)
 * when their config directory already exists on the user's machine.
 */
export function installMcpIntoEditors(
  servers: McpServerConfig[],
  projectDir: string,
): EditorMcpInstallResult[] {
  const eligible = servers.filter(
    (s) => s.installInEditors && (s.url || s.command),
  );
  if (eligible.length === 0) return [];

  const home = os.homedir();
  const targets: Array<{
    editor: string;
    dir: string;
    file: string;
    key: string;
    includeHttpType: boolean;
  }> = [
    {
      editor: 'Cursor',
      dir: path.join(home, '.cursor'),
      file: path.join(home, '.cursor', 'mcp.json'),
      key: 'mcpServers',
      includeHttpType: false,
    },
    {
      editor: 'Claude Code',
      dir: projectDir,
      file: path.join(projectDir, '.mcp.json'),
      key: 'mcpServers',
      includeHttpType: true,
    },
    {
      editor: 'VS Code',
      dir: path.join(projectDir, '.vscode'),
      file: path.join(projectDir, '.vscode', 'mcp.json'),
      key: 'servers',
      includeHttpType: true,
    },
  ];

  const results: EditorMcpInstallResult[] = [];
  for (const target of targets) {
    if (!fs.existsSync(target.dir)) continue;

    let current: Record<string, unknown> = {};
    if (fs.existsSync(target.file)) {
      try {
        current = JSON.parse(fs.readFileSync(target.file, 'utf8')) as Record<
          string,
          unknown
        >;
      } catch {
        current = {};
      }
    }

    const bucket =
      (current[target.key] as Record<string, unknown> | undefined) ?? {};
    let changed = false;

    for (const s of eligible) {
      if (!bucket[s.id]) {
        if (s.transport === 'stdio' && s.command) {
          bucket[s.id] = { command: s.command, args: s.args ?? [] };
        } else if (s.url) {
          bucket[s.id] = target.includeHttpType
            ? { type: 'http', url: s.url }
            : { url: s.url };
        }
        changed = true;
      }
    }

    if (changed) {
      current[target.key] = bucket;
      fs.writeFileSync(target.file, `${JSON.stringify(current, null, 2)}\n`, 'utf8');
    }

    results.push({
      editor: target.editor,
      configPath: target.file,
      updated: changed,
    });
  }

  return results;
}
