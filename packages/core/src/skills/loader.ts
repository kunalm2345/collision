import fs from 'node:fs';
import path from 'node:path';
import type { ProjectProfile } from '@collision/detect';
import type { SkillSource } from '../config.js';

export interface LoadedSkill {
  id: string;
  description: string;
  content: string;
  source: string;
  match?: Record<string, string>;
}

export interface SkillMenuEntry {
  id: string;
  description: string;
  url: string;
  match?: Record<string, string>;
}

export function parseFrontmatter(raw: string): {
  meta: Record<string, string>;
  body: string;
} {
  const match = raw.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/);
  if (!match) return { meta: {}, body: raw };

  const meta: Record<string, string> = {};
  for (const line of match[1].split(/\r?\n/)) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    const key = line.slice(0, idx).trim();
    const val = line.slice(idx + 1).trim().replace(/^["']|["']$/g, '');
    if (key) meta[key] = val;
  }

  return { meta, body: match[2].trim() };
}

function matchesProfile(
  match: Record<string, string> | undefined,
  profile: ProjectProfile,
): boolean {
  if (!match || Object.keys(match).length === 0) return true;
  if (match.framework && profile.framework?.id !== match.framework) return false;
  if (match.variant && profile.framework?.variant !== match.variant) return false;
  if (match.ecosystem && profile.ecosystem !== match.ecosystem) return false;
  return true;
}

export class SkillRegistry {
  private readonly skills = new Map<string, LoadedSkill>();
  private readonly remoteMenu = new Map<string, SkillMenuEntry>();

  async loadSources(sources: SkillSource[], profile: ProjectProfile): Promise<void> {
    for (const source of sources) {
      if (source.type === 'local') {
        this.loadLocalDirectory(source.dir, profile);
      } else if (source.type === 'url') {
        if (matchesProfile(source.match, profile)) {
          this.remoteMenu.set(source.id, {
            id: source.id,
            description: source.description,
            url: source.url,
            match: source.match,
          });
        }
      } else if (source.type === 'menu') {
        const res = await fetch(source.menuUrl);
        if (!res.ok) continue;
        const json = (await res.json()) as { skills?: SkillMenuEntry[] };
        for (const entry of json.skills ?? []) {
          if (matchesProfile(entry.match, profile)) {
            this.remoteMenu.set(entry.id, entry);
          }
        }
      }
    }
  }

  private loadLocalDirectory(dir: string, profile: ProjectProfile): void {
    if (!fs.existsSync(dir)) return;
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isFile() && entry.name.endsWith('.md')) {
        const raw = fs.readFileSync(full, 'utf8');
        const { meta, body } = parseFrontmatter(raw);
        const id = meta.id || path.basename(entry.name, '.md');
        const match: Record<string, string> = {};
        if (meta.framework) match.framework = meta.framework;
        if (meta.variant) match.variant = meta.variant;
        if (meta.ecosystem) match.ecosystem = meta.ecosystem;
        if (!matchesProfile(match, profile)) continue;

        this.skills.set(id, {
          id,
          description: meta.description || id,
          content: body,
          source: full,
          match: Object.keys(match).length ? match : undefined,
        });
      }
    }
  }

  listAvailable(): Array<{ id: string; description: string }> {
    const out = new Map<string, string>();
    for (const s of this.skills.values()) out.set(s.id, s.description);
    for (const m of this.remoteMenu.values()) {
      if (!out.has(m.id)) out.set(m.id, m.description);
    }
    return [...out.entries()].map(([id, description]) => ({ id, description }));
  }

  async get(id: string): Promise<LoadedSkill | null> {
    const cached = this.skills.get(id);
    if (cached) return cached;

    const remote = this.remoteMenu.get(id);
    if (!remote) return null;

    const res = await fetch(remote.url);
    if (!res.ok) {
      throw new Error(`Failed to fetch skill "${id}" from ${remote.url}: ${res.status}`);
    }
    const raw = await res.text();
    const { body } = parseFrontmatter(raw);
    const loaded: LoadedSkill = {
      id: remote.id,
      description: remote.description,
      content: body,
      source: remote.url,
      match: remote.match,
    };
    this.skills.set(id, loaded);
    return loaded;
  }
}
