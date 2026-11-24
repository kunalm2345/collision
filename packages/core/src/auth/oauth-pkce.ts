import { execFile } from 'node:child_process';
import crypto from 'node:crypto';
import http from 'node:http';
import type { OAuthPkceConfig } from '../config.js';

export interface PkcePair {
  codeVerifier: string;
  codeChallenge: string;
  state: string;
}

export interface OAuthTokenResult {
  accessToken: string;
  tokenType: string;
  refreshToken?: string;
  expiresIn?: number;
  scope?: string;
  gatewayToken?: string;
}

export interface OAuthPkceLoginOptions {
  openBrowser?: (url: string) => void | Promise<void>;
  onAuthUrl?: (url: string) => void;
  /** Optional fallback for SSH/headless users to paste the callback URL or authorization code */
  promptForCode?: (authorizeUrl: string) => Promise<string | null>;
  signal?: AbortSignal;
  /** Allow http://localhost or http://127.0.0.1 endpoints (intended for local dev & tests) */
  allowInsecureLocalhost?: boolean;
}

function base64Url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function generatePkcePair(): PkcePair {
  const codeVerifier = base64Url(crypto.randomBytes(32));
  const codeChallenge = base64Url(
    crypto.createHash('sha256').update(codeVerifier).digest(),
  );
  const state = base64Url(crypto.randomBytes(16));
  return { codeVerifier, codeChallenge, state };
}

function assertAllowedEndpointUrl(
  rawUrl: string,
  label: string,
  allowInsecureLocalhost = false,
): URL {
  const parsed = new URL(rawUrl);
  if (parsed.protocol === 'https:') return parsed;
  if (
    allowInsecureLocalhost &&
    parsed.protocol === 'http:' &&
    (parsed.hostname === '127.0.0.1' || parsed.hostname === 'localhost')
  ) {
    return parsed;
  }
  throw new Error(`${label} must use HTTPS (got "${parsed.protocol}//${parsed.host}")`);
}

export function buildAuthorizeUrl(
  config: OAuthPkceConfig,
  params: {
    redirectUri: string;
    codeChallenge: string;
    state: string;
    allowInsecureLocalhost?: boolean;
  },
): string {
  const url = assertAllowedEndpointUrl(
    config.authorizeUrl,
    'authorizeUrl',
    params.allowInsecureLocalhost,
  );
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', config.clientId);
  url.searchParams.set('redirect_uri', params.redirectUri);
  url.searchParams.set('code_challenge', params.codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');
  url.searchParams.set('state', params.state);
  if (config.scopes.length > 0) {
    url.searchParams.set('scope', config.scopes.join(' '));
  }
  if (config.audience) {
    url.searchParams.set('audience', config.audience);
  }
  for (const [k, v] of Object.entries(config.extraAuthorizeParams ?? {})) {
    url.searchParams.set(k, v);
  }
  return url.toString();
}

function timingSafeEquals(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function parsePastedCodeOrUrl(
  input: string,
  expectedState: string,
): { code: string } | { error: string } {
  const trimmed = input.trim();
  if (!trimmed) return { error: 'Empty authorization code' };
  if (/^https?:\/\//i.test(trimmed)) {
    try {
      const parsed = new URL(trimmed);
      const err = parsed.searchParams.get('error');
      if (err) return { error: `OAuth error: ${err}` };
      const code = parsed.searchParams.get('code');
      const state = parsed.searchParams.get('state');
      if (!code) return { error: 'Pasted URL does not contain a code parameter' };
      if (!state || !timingSafeEquals(state, expectedState)) {
        return { error: 'OAuth state mismatch' };
      }
      return { code };
    } catch {
      return { error: 'Invalid pasted callback URL' };
    }
  }
  return { code: trimmed };
}

export async function exchangeAuthorizationCode(
  config: OAuthPkceConfig,
  params: {
    code: string;
    redirectUri: string;
    codeVerifier: string;
    allowInsecureLocalhost?: boolean;
  },
): Promise<OAuthTokenResult> {
  const tokenUrl = assertAllowedEndpointUrl(
    config.tokenUrl,
    'tokenUrl',
    params.allowInsecureLocalhost,
  );

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: params.code,
    redirect_uri: params.redirectUri,
    client_id: config.clientId,
    code_verifier: params.codeVerifier,
  });

  const res = await fetch(tokenUrl.toString(), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: body.toString(),
    redirect: 'error',
  });

  if (!res.ok) {
    throw new Error(`OAuth token exchange failed (HTTP ${res.status})`);
  }

  const data = (await res.json()) as {
    access_token?: string;
    token_type?: string;
    refresh_token?: string;
    expires_in?: number;
    scope?: string;
  };
  if (!data.access_token) {
    throw new Error('OAuth token response missing access_token');
  }

  const result: OAuthTokenResult = {
    accessToken: data.access_token,
    tokenType: data.token_type ?? 'Bearer',
    refreshToken: data.refresh_token,
    expiresIn: data.expires_in,
    scope: data.scope,
  };

  if (config.gatewayExchangeUrl) {
    const exchangeUrl = assertAllowedEndpointUrl(
      config.gatewayExchangeUrl,
      'gatewayExchangeUrl',
      params.allowInsecureLocalhost,
    );
    const gwRes = await fetch(exchangeUrl.toString(), {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${result.accessToken}`,
        Accept: 'application/json',
      },
      redirect: 'error',
    });
    if (!gwRes.ok) {
      throw new Error(`Gateway token exchange failed (HTTP ${gwRes.status})`);
    }
    const gwData = (await gwRes.json()) as { token?: string };
    if (!gwData.token) {
      throw new Error('Gateway token exchange response missing token');
    }
    result.gatewayToken = gwData.token;
  }

  return result;
}

function defaultOpenBrowser(url: string): void {
  const platform = process.platform;
  if (platform === 'darwin') {
    execFile('open', [url], () => {});
  } else if (platform === 'win32') {
    execFile('rundll32', ['url.dll,FileProtocolHandler', url], () => {});
  } else {
    execFile('xdg-open', [url], () => {});
  }
}

const CALLBACK_SUCCESS_HTML = `<!doctype html><html><body style="font-family:system-ui,sans-serif;padding:2rem;max-width:480px;margin:auto"><h2>Authentication complete</h2><p>You can close this tab and return to your terminal.</p></body></html>`;
const CALLBACK_ERROR_HTML = `<!doctype html><html><body style="font-family:system-ui,sans-serif;padding:2rem;max-width:480px;margin:auto"><h2>Authentication failed</h2><p>Return to your terminal for details.</p></body></html>`;

export async function runOAuthPkceLogin(
  config: OAuthPkceConfig,
  options: OAuthPkceLoginOptions = {},
): Promise<OAuthTokenResult> {
  const { codeVerifier, codeChallenge, state } = generatePkcePair();
  const callbackPath = config.callbackPath.startsWith('/')
    ? config.callbackPath
    : `/${config.callbackPath}`;

  let resolveCode!: (code: string) => void;
  let rejectCode!: (err: Error) => void;
  let settled = false;

  const finishResolve = (code: string) => {
    if (settled) return;
    settled = true;
    resolveCode(code);
  };
  const finishReject = (err: Error) => {
    if (settled) return;
    settled = true;
    rejectCode(err);
  };

  const codePromise = new Promise<string>((resolve, reject) => {
    resolveCode = resolve;
    rejectCode = reject;
  });
  // Prevent unhandledRejection if the callback rejects before `await codePromise` is reached
  codePromise.catch(() => {});

  const server = http.createServer((req, res) => {
    const reqUrl = new URL(req.url ?? '/', 'http://127.0.0.1');
    if (req.method !== 'GET' || reqUrl.pathname !== callbackPath) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not found');
      return;
    }

    const oauthError = reqUrl.searchParams.get('error');
    const code = reqUrl.searchParams.get('code');
    const returnedState = reqUrl.searchParams.get('state');

    if (!returnedState || !timingSafeEquals(returnedState, state)) {
      res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(CALLBACK_ERROR_HTML);
      return;
    }

    if (oauthError) {
      res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(CALLBACK_ERROR_HTML);
      finishReject(new Error(`OAuth authorization denied: ${oauthError}`));
      return;
    }

    if (!code) {
      res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(CALLBACK_ERROR_HTML);
      return;
    }

    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(CALLBACK_SUCCESS_HTML);
    finishResolve(code);
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(config.redirectPort, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });

  const addr = server.address();
  if (!addr || typeof addr === 'string') {
    server.close();
    throw new Error('Failed to bind local OAuth callback server');
  }

  const redirectUri = `http://127.0.0.1:${addr.port}${callbackPath}`;
  const authorizeUrl = buildAuthorizeUrl(config, {
    redirectUri,
    codeChallenge,
    state,
    allowInsecureLocalhost: options.allowInsecureLocalhost,
  });

  const timer = setTimeout(() => {
    finishReject(new Error(`OAuth login timed out after ${Math.round(config.timeoutMs / 1000)}s`));
  }, config.timeoutMs);

  const onAbort = () => {
    finishReject(new Error('OAuth login aborted'));
  };
  options.signal?.addEventListener('abort', onAbort, { once: true });

  try {
    options.onAuthUrl?.(authorizeUrl);
    const opener = options.openBrowser ?? defaultOpenBrowser;
    await opener(authorizeUrl);

    if (options.promptForCode) {
      void options.promptForCode(authorizeUrl).then(
        (pasted) => {
          if (!pasted || settled) return;
          const parsed = parsePastedCodeOrUrl(pasted, state);
          if ('code' in parsed) {
            finishResolve(parsed.code);
          } else {
            finishReject(new Error(parsed.error));
          }
        },
        () => {
          // Ignore fallback prompt errors if callback finishes
        },
      );
    }

    const code = await codePromise;
    return await exchangeAuthorizationCode(config, {
      code,
      redirectUri,
      codeVerifier,
      allowInsecureLocalhost: options.allowInsecureLocalhost,
    });
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener('abort', onAbort);
    server.close();
  }
}
