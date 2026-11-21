import crypto from 'node:crypto';

const HANDLE_REGEX = /secret:[0-9a-f-]{36}/gi;

/**
 * Keeps sensitive user-provided values in memory on the user's machine.
 * The LLM only ever sees opaque `secret:<uuid>` handles; host-side tools
 * resolve handles only when writing `.env` files or passing auth headers.
 */
export class SecretVault {
  private readonly byHandle = new Map<string, string>();

  store(value: string): string {
    const handle = `secret:${crypto.randomUUID()}`;
    this.byHandle.set(handle, value);
    return handle;
  }

  get(handle: string): string | undefined {
    return this.byHandle.get(handle);
  }

  resolve(input: string): string {
    return input.replace(HANDLE_REGEX, (match) => this.byHandle.get(match) ?? match);
  }

  redact(input: string): string {
    let output = input;
    for (const [handle, secret] of this.byHandle.entries()) {
      if (secret.length >= 6 && output.includes(secret)) {
        output = output.split(secret).join(`[REDACTED:${handle}]`);
      }
    }
    return output;
  }

  clear(): void {
    this.byHandle.clear();
  }
}
