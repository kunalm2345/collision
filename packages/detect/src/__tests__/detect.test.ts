import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { detectProject, installCommandFor } from '../index.js';

const tmpDirs: string[] = [];

function makeTempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'collision-detect-'));
  tmpDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tmpDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe('@collision/detect', () => {
  it('detects Next.js App Router with pnpm and TypeScript', async () => {
    const dir = makeTempDir();
    fs.writeFileSync(
      path.join(dir, 'package.json'),
      JSON.stringify({ dependencies: { next: '15.3.0', react: '19.0.0' } }),
    );
    fs.writeFileSync(path.join(dir, 'pnpm-lock.yaml'), 'lockfileVersion: 9.0\n');
    fs.writeFileSync(path.join(dir, 'tsconfig.json'), '{}');
    fs.mkdirSync(path.join(dir, 'src', 'app'), { recursive: true });
    fs.writeFileSync(path.join(dir, '.env.local'), 'SECRET=1\n');

    const profile = await detectProject(dir);
    expect(profile.framework?.id).toBe('nextjs');
    expect(profile.framework?.variant).toBe('app-router');
    expect(profile.packageManager).toBe('pnpm');
    expect(profile.hasTypeScript).toBe(true);
    expect(profile.envFiles).toEqual(['.env.local']);
    expect(installCommandFor(profile.packageManager, ['acme-sdk'])).toBe(
      'pnpm add acme-sdk',
    );
  });

  it('detects FastAPI with uv', async () => {
    const dir = makeTempDir();
    fs.writeFileSync(
      path.join(dir, 'pyproject.toml'),
      '[project]\ndependencies = ["fastapi>=0.115"]\n',
    );
    fs.writeFileSync(path.join(dir, 'uv.lock'), '');

    const profile = await detectProject(dir);
    expect(profile.framework?.id).toBe('fastapi');
    expect(profile.ecosystem).toBe('python');
    expect(profile.packageManager).toBe('uv');
  });

  it('allows custom vendor detectors to take precedence', async () => {
    const dir = makeTempDir();
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'demo' }));
    fs.writeFileSync(path.join(dir, 'custom.marker'), 'yes');

    const profile = await detectProject(dir, [
      {
        id: 'custom-fw',
        name: 'Custom FW',
        ecosystem: 'node',
        detect: (d) =>
          fs.existsSync(path.join(d, 'custom.marker'))
            ? {
                id: 'custom-fw',
                name: 'Custom FW',
                ecosystem: 'node',
                confidence: 'high',
                evidence: ['custom.marker'],
              }
            : null,
      },
    ]);

    expect(profile.framework?.id).toBe('custom-fw');
  });
});
