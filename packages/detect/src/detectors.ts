import fs from 'node:fs';
import path from 'node:path';
import type { DetectedFramework, FrameworkDetector } from './types.js';

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  workspaces?: unknown;
}

function readPackageJson(dir: string): PackageJson | null {
  const pkgPath = path.join(dir, 'package.json');
  if (!fs.existsSync(pkgPath)) return null;
  try {
    return JSON.parse(fs.readFileSync(pkgPath, 'utf8')) as PackageJson;
  } catch {
    return null;
  }
}

function depVersion(pkg: PackageJson | null, name: string): string | undefined {
  if (!pkg) return undefined;
  return pkg.dependencies?.[name] ?? pkg.devDependencies?.[name];
}

function readTextIfExists(filePath: string): string {
  try {
    return fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf8') : '';
  } catch {
    return '';
  }
}

export const nextjsDetector: FrameworkDetector = {
  id: 'nextjs',
  name: 'Next.js',
  ecosystem: 'node',
  detect(dir): DetectedFramework | null {
    const pkg = readPackageJson(dir);
    const version = depVersion(pkg, 'next');
    if (!version) return null;

    const hasAppDir =
      fs.existsSync(path.join(dir, 'app')) ||
      fs.existsSync(path.join(dir, 'src', 'app'));
    const hasPagesDir =
      fs.existsSync(path.join(dir, 'pages')) ||
      fs.existsSync(path.join(dir, 'src', 'pages'));

    const variant = hasAppDir ? 'app-router' : hasPagesDir ? 'pages-router' : 'app-router';
    return {
      id: 'nextjs',
      name: 'Next.js',
      ecosystem: 'node',
      variant,
      version,
      confidence: 'high',
      evidence: [`package.json next@${version}`, `variant:${variant}`],
    };
  },
};

export const viteDetector: FrameworkDetector = {
  id: 'vite',
  name: 'Vite',
  ecosystem: 'node',
  detect(dir): DetectedFramework | null {
    const pkg = readPackageJson(dir);
    const version = depVersion(pkg, 'vite');
    if (!version) return null;

    const variant = depVersion(pkg, 'react')
      ? 'react'
      : depVersion(pkg, 'vue')
        ? 'vue'
        : depVersion(pkg, 'svelte')
          ? 'svelte'
          : 'vanilla';

    return {
      id: 'vite',
      name: 'Vite',
      ecosystem: 'node',
      variant,
      version,
      confidence: 'high',
      evidence: [`package.json vite@${version}`, `variant:${variant}`],
    };
  },
};

export const astroDetector: FrameworkDetector = {
  id: 'astro',
  name: 'Astro',
  ecosystem: 'node',
  detect(dir): DetectedFramework | null {
    const pkg = readPackageJson(dir);
    const version = depVersion(pkg, 'astro');
    if (!version) return null;
    return {
      id: 'astro',
      name: 'Astro',
      ecosystem: 'node',
      version,
      confidence: 'high',
      evidence: [`package.json astro@${version}`],
    };
  },
};

export const sveltekitDetector: FrameworkDetector = {
  id: 'sveltekit',
  name: 'SvelteKit',
  ecosystem: 'node',
  detect(dir): DetectedFramework | null {
    const pkg = readPackageJson(dir);
    const version = depVersion(pkg, '@sveltejs/kit');
    if (!version) return null;
    return {
      id: 'sveltekit',
      name: 'SvelteKit',
      ecosystem: 'node',
      version,
      confidence: 'high',
      evidence: [`package.json @sveltejs/kit@${version}`],
    };
  },
};

export const nuxtDetector: FrameworkDetector = {
  id: 'nuxt',
  name: 'Nuxt',
  ecosystem: 'node',
  detect(dir): DetectedFramework | null {
    const pkg = readPackageJson(dir);
    const version = depVersion(pkg, 'nuxt');
    if (!version) return null;
    return {
      id: 'nuxt',
      name: 'Nuxt',
      ecosystem: 'node',
      version,
      confidence: 'high',
      evidence: [`package.json nuxt@${version}`],
    };
  },
};

export const reactNativeDetector: FrameworkDetector = {
  id: 'react-native',
  name: 'React Native',
  ecosystem: 'node',
  detect(dir): DetectedFramework | null {
    const pkg = readPackageJson(dir);
    const expo = depVersion(pkg, 'expo');
    const rn = depVersion(pkg, 'react-native');
    if (!expo && !rn) return null;
    return {
      id: 'react-native',
      name: expo ? 'Expo (React Native)' : 'React Native',
      ecosystem: 'node',
      variant: expo ? 'expo' : 'bare',
      version: expo ?? rn,
      confidence: 'high',
      evidence: [expo ? `package.json expo@${expo}` : `package.json react-native@${rn}`],
    };
  },
};

export const expressDetector: FrameworkDetector = {
  id: 'express',
  name: 'Express',
  ecosystem: 'node',
  detect(dir): DetectedFramework | null {
    const pkg = readPackageJson(dir);
    const version = depVersion(pkg, 'express');
    if (!version) return null;
    return {
      id: 'express',
      name: 'Express',
      ecosystem: 'node',
      version,
      confidence: 'medium',
      evidence: [`package.json express@${version}`],
    };
  },
};

export const pythonFrameworkDetector: FrameworkDetector = {
  id: 'python',
  name: 'Python',
  ecosystem: 'python',
  detect(dir): DetectedFramework | null {
    const pyproject = readTextIfExists(path.join(dir, 'pyproject.toml'));
    const reqs = readTextIfExists(path.join(dir, 'requirements.txt'));
    const combined = `${pyproject}\n${reqs}`.toLowerCase();
    if (!combined.trim()) return null;

    if (combined.includes('fastapi')) {
      return {
        id: 'fastapi',
        name: 'FastAPI',
        ecosystem: 'python',
        confidence: 'high',
        evidence: ['fastapi dependency detected'],
      };
    }
    if (combined.includes('django')) {
      return {
        id: 'django',
        name: 'Django',
        ecosystem: 'python',
        confidence: 'high',
        evidence: ['django dependency detected'],
      };
    }
    if (combined.includes('flask')) {
      return {
        id: 'flask',
        name: 'Flask',
        ecosystem: 'python',
        confidence: 'high',
        evidence: ['flask dependency detected'],
      };
    }
    return {
      id: 'python',
      name: 'Python',
      ecosystem: 'python',
      confidence: 'low',
      evidence: ['pyproject.toml or requirements.txt present'],
    };
  },
};

export const goDetector: FrameworkDetector = {
  id: 'go',
  name: 'Go',
  ecosystem: 'go',
  detect(dir): DetectedFramework | null {
    if (!fs.existsSync(path.join(dir, 'go.mod'))) return null;
    return {
      id: 'go',
      name: 'Go',
      ecosystem: 'go',
      confidence: 'high',
      evidence: ['go.mod present'],
    };
  },
};

export const rustDetector: FrameworkDetector = {
  id: 'rust',
  name: 'Rust',
  ecosystem: 'rust',
  detect(dir): DetectedFramework | null {
    if (!fs.existsSync(path.join(dir, 'Cargo.toml'))) return null;
    return {
      id: 'rust',
      name: 'Rust',
      ecosystem: 'rust',
      confidence: 'high',
      evidence: ['Cargo.toml present'],
    };
  },
};

export const nodeFallbackDetector: FrameworkDetector = {
  id: 'node',
  name: 'Node.js',
  ecosystem: 'node',
  detect(dir): DetectedFramework | null {
    const pkg = readPackageJson(dir);
    if (!pkg) return null;
    return {
      id: 'node',
      name: 'Node.js',
      ecosystem: 'node',
      confidence: 'low',
      evidence: ['package.json present'],
    };
  },
};

export const BUILTIN_DETECTORS: FrameworkDetector[] = [
  nextjsDetector,
  sveltekitDetector,
  nuxtDetector,
  astroDetector,
  reactNativeDetector,
  viteDetector,
  expressDetector,
  pythonFrameworkDetector,
  goDetector,
  rustDetector,
  nodeFallbackDetector,
];
