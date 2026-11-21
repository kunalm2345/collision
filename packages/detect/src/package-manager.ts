import fs from 'node:fs';
import path from 'node:path';
import type { Ecosystem, PackageManager } from './types.js';

export function detectPackageManager(
  projectDir: string,
  ecosystem: Ecosystem = 'node',
): PackageManager {
  const exists = (rel: string) => fs.existsSync(path.join(projectDir, rel));

  if (ecosystem === 'node' || exists('package.json')) {
    if (exists('pnpm-lock.yaml')) return 'pnpm';
    if (exists('bun.lockb') || exists('bun.lock')) return 'bun';
    if (exists('yarn.lock')) return 'yarn';
    if (exists('package-lock.json')) return 'npm';

    try {
      const pkg = JSON.parse(
        fs.readFileSync(path.join(projectDir, 'package.json'), 'utf8'),
      ) as { packageManager?: string };
      if (pkg.packageManager?.startsWith('pnpm')) return 'pnpm';
      if (pkg.packageManager?.startsWith('yarn')) return 'yarn';
      if (pkg.packageManager?.startsWith('bun')) return 'bun';
      if (pkg.packageManager?.startsWith('npm')) return 'npm';
    } catch {
      // ignore invalid package.json
    }
    if (exists('package.json')) return 'npm';
  }

  if (ecosystem === 'python' || exists('pyproject.toml') || exists('requirements.txt')) {
    if (exists('uv.lock')) return 'uv';
    if (exists('poetry.lock')) return 'poetry';
    return 'pip';
  }

  if (ecosystem === 'go' || exists('go.mod')) return 'go';
  if (ecosystem === 'rust' || exists('Cargo.toml')) return 'cargo';

  return 'unknown';
}

export function installCommandFor(pm: PackageManager, packages: string[]): string {
  const list = packages.join(' ');
  switch (pm) {
    case 'pnpm':
      return `pnpm add ${list}`;
    case 'yarn':
      return `yarn add ${list}`;
    case 'bun':
      return `bun add ${list}`;
    case 'npm':
      return `npm install ${list}`;
    case 'uv':
      return `uv add ${list}`;
    case 'poetry':
      return `poetry add ${list}`;
    case 'pip':
      return `pip install ${list}`;
    case 'go':
      return `go get ${list}`;
    case 'cargo':
      return `cargo add ${list}`;
    default:
      return `npm install ${list}`;
  }
}
