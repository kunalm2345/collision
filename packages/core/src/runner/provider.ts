import type { CollisionConfig } from '../config.js';

export type TransportApi =
  | 'anthropic-messages'
  | 'openai-completions'
  | 'openai-responses';

export interface ResolvedProvider {
  providerName: string;
  api: TransportApi;
  baseUrl: string;
  apiKey: string;
  modelId: string;
  headers: Record<string, string>;
}

export function inferTransportApi(
  kind: CollisionConfig['provider']['kind'],
  modelId: string,
): TransportApi {
  if (kind === 'anthropic') return 'anthropic-messages';
  if (kind === 'openai') return 'openai-responses';
  if (kind === 'openrouter') return 'openai-completions';
  // Gateway routes OpenAI models via responses/completions and Anthropic via messages
  if (modelId.startsWith('anthropic/') || modelId.startsWith('claude')) {
    return 'anthropic-messages';
  }
  return 'openai-completions';
}

export function resolveProvider(
  config: CollisionConfig,
  overrides?: {
    gatewayToken?: string;
    apiKey?: string;
    gatewayUrl?: string;
    model?: string;
    promptHash?: string;
  },
): ResolvedProvider {
  const kind = config.provider.kind;
  const modelId = overrides?.model ?? config.provider.model;
  const api = inferTransportApi(kind, modelId);

  if (kind === 'gateway') {
    const gatewayUrl = (
      overrides?.gatewayUrl ??
      config.provider.gatewayUrl ??
      process.env.COLLISION_GATEWAY_URL ??
      'http://localhost:8787'
    ).replace(/\/$/, '');
    const apiKey =
      overrides?.gatewayToken ??
      overrides?.apiKey ??
      process.env.COLLISION_GATEWAY_TOKEN ??
      '';
    if (!apiKey) {
      throw new Error(
        'Missing gateway token. Authenticate with the Collision gateway or set COLLISION_GATEWAY_TOKEN.',
      );
    }
    const headers: Record<string, string> = {
      'X-Collision-Vendor': config.vendor.id,
    };
    if (overrides?.promptHash) {
      headers['X-Collision-Prompt-Hash'] = overrides.promptHash;
    }
    let gatewayModelId = modelId;
    if (modelId.startsWith('openrouter/')) {
      headers['X-Collision-Provider'] = 'openrouter';
      gatewayModelId = modelId.slice('openrouter/'.length);
    } else if (modelId.startsWith('anthropic/')) {
      headers['X-Collision-Provider'] = 'anthropic';
      gatewayModelId = modelId.slice('anthropic/'.length);
    } else if (modelId.startsWith('openai/')) {
      headers['X-Collision-Provider'] = 'openai';
      gatewayModelId = modelId.slice('openai/'.length);
    }
    return {
      providerName: 'collision-gateway',
      api,
      baseUrl: api === 'anthropic-messages' ? gatewayUrl : `${gatewayUrl}/v1`,
      apiKey,
      modelId: gatewayModelId,
      headers,
    };
  }

  if (kind === 'openrouter') {
    const envName = config.provider.apiKeyEnv ?? 'OPENROUTER_API_KEY';
    const apiKey = overrides?.apiKey ?? process.env[envName] ?? '';
    if (!apiKey) {
      throw new Error(`Missing OpenRouter API key (set ${envName}).`);
    }
    return {
      providerName: 'collision-openrouter',
      api: 'openai-completions',
      baseUrl: 'https://openrouter.ai/api/v1',
      apiKey,
      modelId,
      headers: {
        'HTTP-Referer': config.vendor.website ?? 'https://github.com/kunalm2345/collision',
        'X-Title': `Collision (${config.vendor.name})`,
      },
    };
  }

  if (kind === 'openai') {
    const envName = config.provider.apiKeyEnv ?? 'OPENAI_API_KEY';
    const apiKey = overrides?.apiKey ?? process.env[envName] ?? '';
    if (!apiKey) {
      throw new Error(`Missing OpenAI API key (set ${envName}).`);
    }
    return {
      providerName: 'collision-openai',
      api: 'openai-responses',
      baseUrl: 'https://api.openai.com/v1',
      apiKey,
      modelId: modelId.replace(/^openai\//, ''),
      headers: {},
    };
  }

  // anthropic
  const envName = config.provider.apiKeyEnv ?? 'ANTHROPIC_API_KEY';
  const apiKey = overrides?.apiKey ?? process.env[envName] ?? '';
  if (!apiKey) {
    throw new Error(`Missing Anthropic API key (set ${envName}).`);
  }
  return {
    providerName: 'collision-anthropic',
    api: 'anthropic-messages',
    baseUrl: 'https://api.anthropic.com',
    apiKey,
    modelId: modelId.replace(/^anthropic\//, ''),
    headers: {},
  };
}
