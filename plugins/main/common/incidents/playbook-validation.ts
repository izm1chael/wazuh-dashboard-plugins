import type { CollaborationPage } from './contracts';

const idValid = (value: unknown) => typeof value === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(value);
const integer = (value: number) => Number.isSafeInteger(value) && value > 0 && value <= 2147483647;
const text = (value: unknown, max: number) => typeof value === 'string' && value.trim().length > 0 && value.length <= max;
const key = (row: { template_id: string; version: number }) => row.template_id + ':' + row.version;
export function validatePlaybooks(body: CollaborationPage, id: string): void {
  // Older experimental servers may omit both fields. Never treat one absent field as empty history.
  if (body.playbooks === undefined && body.playbook_runs === undefined) return;
  const previews = body.playbooks, runs = body.playbook_runs;
  if (!Array.isArray(previews) || previews.length > 100 || !Array.isArray(runs) || runs.length > 100) {
    throw new Error('Invalid playbook projection');
  }
  const tasks = new Map(body.tasks.map(task => [task.id, task]));
  const used = new Set<string>(), runKeys = new Set<string>();
  for (const run of runs) {
    if (!run || !idValid(run.template_id) || !integer(run.version) || !integer(run.applied_revision) ||
        run.applied_revision > body.observed_revision || !text(run.applied_by, 1024) ||
        typeof run.applied_at !== 'string' || !Number.isFinite(Date.parse(run.applied_at)) ||
        !Array.isArray(run.task_ids) || run.task_ids.length < 1 || run.task_ids.length > 20 || runKeys.has(key(run))) {
      throw new Error('Invalid playbook receipt');
    }
    runKeys.add(key(run));
    for (const [n, taskId] of run.task_ids.entries()) {
      const task = tasks.get(taskId);
      if (taskId !== id + ':' + run.applied_revision + ':' + (n + 1) || used.has(taskId) ||
          !task || task.created_by !== run.applied_by || task.created_at !== run.applied_at) {
        throw new Error('Invalid playbook task membership');
      }
      used.add(taskId);
    }
  }
  const previewKeys = new Set<string>();
  for (const preview of previews) {
    if (!preview || !idValid(preview.template_id) || !integer(preview.version) || !text(preview.title, 1024) ||
        !Array.isArray(preview.tasks) || preview.tasks.length < 1 || preview.tasks.length > 20 ||
        !preview.tasks.every(task => text(task, 1024)) ||
        !['available', 'already_applied', 'not_applicable', 'capacity_exceeded'].includes(preview.state) ||
        previewKeys.has(key(preview)) || (preview.state === 'already_applied') !== runKeys.has(key(preview)) ||
        (preview.state === 'available' && body.tasks.length + preview.tasks.length > 100)) {
      throw new Error('Invalid playbook recommendation');
    }
    previewKeys.add(key(preview));
  }
}
