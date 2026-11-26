import { validatePlaybooks } from './playbook-validation';
import type { CollaborationPage } from './contracts';
const id = '00000000-0000-4000-8000-000000000001';
const now = '2026-11-26T12:00:00Z';
const page: CollaborationPage = {
  notes: [], tasks: [{ id: id + ':3:1', title: 'Review', status: 'open', created_by: 'analyst', created_at: now, completed_by: null, completed_at: null }],
  observed_revision: 3, activity_pending: false,
  playbooks: [{ template_id: 'initial_triage', version: 1, title: 'Triage', tasks: ['Review'], state: 'already_applied' }],
  playbook_runs: [{ template_id: 'initial_triage', version: 1, applied_revision: 3, applied_by: 'analyst', applied_at: now, task_ids: [id + ':3:1'] }],
};
describe('playbook receipts', () => {
  test('accepts consistent membership', () => expect(() => validatePlaybooks(page, id)).not.toThrow());
  test('rejects missing or foreign tasks and mismatched applied state', () => {
    expect(() => validatePlaybooks({ ...page, tasks: [] }, id)).toThrow();
    expect(() => validatePlaybooks({ ...page, playbook_runs: [{ ...page.playbook_runs![0], task_ids: ['other:3:1'] }] }, id)).toThrow();
    expect(() => validatePlaybooks({ ...page, playbooks: [{ ...page.playbooks![0], state: 'available' }] }, id)).toThrow();
  });
  test('does not fabricate history when older servers omit both fields', () => {
    expect(() => validatePlaybooks({ ...page, playbooks: undefined, playbook_runs: undefined }, id)).not.toThrow();
    expect(() => validatePlaybooks({ ...page, playbook_runs: undefined }, id)).toThrow();
  });
});
