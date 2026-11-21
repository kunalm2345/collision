import type { TaskDefinition } from '../config.js';

export interface TaskResult {
  taskId: string;
  label: string;
  summary: string;
  artifacts?: string[];
}

export function defaultInstallTasks(vendorName: string): TaskDefinition[] {
  return [
    {
      id: 'install',
      label: `Install ${vendorName} SDK`,
      dependsOn: [],
      skills: [],
      prompt: `Inspect the project's package manifest and install the official ${vendorName} SDK using the project's package manager. Verify the dependency is added cleanly without breaking existing scripts.`,
    },
    {
      id: 'configure',
      label: `Configure ${vendorName} initialization`,
      dependsOn: ['install'],
      skills: [],
      prompt: `Wire up ${vendorName} initialization following the project's framework conventions and loaded skills/docs. Use environment variables via the set_env_values tool; never hardcode API keys or secrets.`,
    },
    {
      id: 'verify',
      label: 'Verify build and types',
      dependsOn: ['configure'],
      skills: [],
      prompt: `Run the project's typecheck or build command to confirm there are no syntax or type errors introduced by the ${vendorName} integration. Fix any issues you find.`,
    },
    {
      id: 'report',
      label: 'Write setup summary',
      dependsOn: ['verify'],
      skills: [],
      prompt: `Write a concise markdown summary of all files created/modified, environment variables added, and any manual next steps the user should take.`,
    },
  ];
}

/**
 * Topologically orders tasks into parallelizable waves and validates
 * there are no missing dependencies or cycles.
 */
export function planTaskWaves(tasks: TaskDefinition[]): TaskDefinition[][] {
  const byId = new Map<string, TaskDefinition>();
  for (const task of tasks) {
    if (byId.has(task.id)) {
      throw new Error(`Duplicate task id "${task.id}"`);
    }
    byId.set(task.id, task);
  }

  for (const task of tasks) {
    for (const dep of task.dependsOn) {
      if (!byId.has(dep)) {
        throw new Error(`Task "${task.id}" depends on unknown task "${dep}"`);
      }
    }
  }

  const completed = new Set<string>();
  const remaining = new Map(byId);
  const waves: TaskDefinition[][] = [];

  while (remaining.size > 0) {
    const ready: TaskDefinition[] = [];
    for (const task of remaining.values()) {
      if (task.dependsOn.every((dep) => completed.has(dep))) {
        ready.push(task);
      }
    }

    if (ready.length === 0) {
      const stuck = [...remaining.keys()].join(', ');
      throw new Error(`Circular task dependency detected involving: ${stuck}`);
    }

    waves.push(ready);
    for (const task of ready) {
      completed.add(task.id);
      remaining.delete(task.id);
    }
  }

  return waves;
}
