import fs from 'node:fs';
import path from 'node:path';
import { BUILTIN_DETECTORS } from './detectors.js';
import { detectPackageManager, installCommandFor } from './package-manager.js';
import type {
  DetectedFramework,
  Ecosystem,
  FrameworkDetector,
  ProjectProfile,
} from './types.js';

export * from './types.js';
export * from './detectors.js';
export { detectPackageManager, installCommandFor };

const CONFIDENCE_RANK: Record<DetectedFramework['confidence'], number> = {
  high: 3,
  medium: 2,
  low: 1,
};

function detectMonorepo(projectDir: string): boolean {
  if (
    fs.existsSync(path.join(projectDir, 'pnpm-workspace.yaml')) ||
    fs.existsSync(path.join(projectDir, 'turbo.json')) ||
    fs.existsSync(path.join(projectDir, 'nx.json')) ||
    fs.existsSync(path.join(projectDir, 'lerna.json'))
  ) {
    return true;
  }
  const pkgPath = path.join(projectDir, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')) as {
        workspaces?: unknown;
      };
      if (pkg.workspaces) return true;
    } catch {
      // ignore
    }
  }
  return false;
}

function listEnvFiles(projectDir: string): string[] {
  try {
    return fs
      .readdirSync(projectDir)
      .filter((name) => name === '.env' || name.startsWith('.env.'))
      .sort();
  } catch {
    return [];
  }
}

export async function detectProject(
  projectDir: string,
  extraDetectors: FrameworkDetector[] = [],
): Promise<ProjectProfile> {
  const detectors = [...extraDetectors, ...BUILTIN_DETECTORS];
  const matches: DetectedFramework[] = [];

  for (const detector of detectors) {
    const match = await detector.detect(projectDir);
    if (match) matches.push(match);
  }

  matches.sort((a, b) => CONFIDENCE_RANK[b.confidence] - CONFIDENCE_RANK[a.confidence]);
  const primary = matches[0] ?? null;
  const ecosystem: Ecosystem = primary?.ecosystem ?? 'unknown';
  const packageManager = detectPackageManager(projectDir, ecosystem);
  const hasTypeScript = fs.existsSync(path.join(projectDir, 'tsconfig.json'));

  return {
    projectDir,
    framework: primary,
    ecosystem,
    packageManager,
    isMonorepo: detectMonorepo(projectDir),
    hasTypeScript,
    envFiles: listEnvFiles(projectDir),
    allMatches: matches,
  };
}
