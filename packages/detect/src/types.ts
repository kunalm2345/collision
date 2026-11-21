export type Ecosystem = 'node' | 'python' | 'go' | 'rust' | 'unknown';

export type PackageManager =
  | 'pnpm'
  | 'yarn'
  | 'bun'
  | 'npm'
  | 'uv'
  | 'poetry'
  | 'pip'
  | 'go'
  | 'cargo'
  | 'unknown';

export interface DetectedFramework {
  id: string;
  name: string;
  ecosystem: Ecosystem;
  variant?: string;
  version?: string;
  confidence: 'high' | 'medium' | 'low';
  evidence: string[];
}

export interface FrameworkDetector {
  id: string;
  name: string;
  ecosystem: Ecosystem;
  detect(projectDir: string): Promise<DetectedFramework | null> | DetectedFramework | null;
}

export interface ProjectProfile {
  projectDir: string;
  framework: DetectedFramework | null;
  ecosystem: Ecosystem;
  packageManager: PackageManager;
  isMonorepo: boolean;
  hasTypeScript: boolean;
  envFiles: string[];
  allMatches: DetectedFramework[];
}
