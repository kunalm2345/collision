import { z } from 'zod';
import type { FrameworkDetector } from '@collision/detect';

export const ProviderKindSchema = z.enum([
  'gateway',
  'openai',
  'anthropic',
  'openrouter',
]);

export const SkillSourceSchema = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('local'),
    dir: z.string(),
  }),
  z.object({
    type: z.literal('url'),
    id: z.string(),
    description: z.string(),
    url: z.string().url(),
    match: z.record(z.string()).optional(),
  }),
  z.object({
    type: z.literal('menu'),
    menuUrl: z.string().url(),
  }),
]);

export const McpServerConfigSchema = z.object({
  id: z.string(),
  name: z.string(),
  transport: z.enum(['http', 'stdio']).default('http'),
  url: z.string().url().optional(),
  command: z.string().optional(),
  args: z.array(z.string()).optional(),
  headers: z.record(z.string()).optional(),
  installInEditors: z.boolean().default(true),
});

export const TaskDefinitionSchema = z.object({
  id: z.string(),
  label: z.string(),
  prompt: z.string(),
  dependsOn: z.array(z.string()).default([]),
  model: z.string().optional(),
  thinkingLevel: z.enum(['off', 'minimal', 'low', 'medium', 'high']).optional(),
  skills: z.array(z.string()).default([]),
  allowedTools: z.array(z.string()).optional(),
});

export const CollisionConfigSchema = z.object({
  vendor: z.object({
    id: z.string().min(1),
    name: z.string().min(1),
    tagline: z.string().optional(),
    website: z.string().url().optional(),
    docsUrl: z.string().url().optional(),
    llmsTxtUrl: z.string().url().optional(),
  }),
  provider: z
    .object({
      kind: ProviderKindSchema.default('gateway'),
      model: z.string().default('anthropic/claude-sonnet-4-5'),
      gatewayUrl: z.string().url().optional(),
      apiKeyEnv: z.string().optional(),
      thinkingLevel: z
        .enum(['off', 'minimal', 'low', 'medium', 'high'])
        .default('medium'),
    })
    .default({}),
  prompts: z
    .object({
      system: z.string().optional(),
      extraRules: z.array(z.string()).default([]),
      tasks: z.array(TaskDefinitionSchema).optional(),
    })
    .default({}),
  skills: z
    .object({
      sources: z.array(SkillSourceSchema).default([]),
    })
    .default({}),
  mcp: z
    .object({
      servers: z.array(McpServerConfigSchema).default([]),
      installIntoEditors: z.boolean().default(true),
    })
    .default({}),
  cli: z
    .object({
      binary: z.string().optional(),
      installCommand: z.string().optional(),
      allowedSubcommands: z.array(z.string()).default([]),
    })
    .default({}),
  security: z
    .object({
      allowBash: z.boolean().default(true),
      extraBlockedPaths: z.array(z.string()).default([]),
      allowedBashPrefixes: z.array(z.string()).default([]),
    })
    .default({}),
});

export type CollisionConfigInput = z.input<typeof CollisionConfigSchema> & {
  detectors?: FrameworkDetector[];
};

export type CollisionConfig = z.output<typeof CollisionConfigSchema> & {
  detectors?: FrameworkDetector[];
};

export type SkillSource = z.output<typeof SkillSourceSchema>;
export type McpServerConfig = z.output<typeof McpServerConfigSchema>;
export type TaskDefinition = z.output<typeof TaskDefinitionSchema>;

export function defineConfig(input: CollisionConfigInput): CollisionConfig {
  const parsed = CollisionConfigSchema.parse(input);
  return {
    ...parsed,
    detectors: input.detectors,
  };
}
