import { validateResponsePage } from './response-validation';
import type { IncidentResponsePage, IncidentResponseRecord } from './contracts';
const id = '00000000-0000-4000-8000-000000000001';
const now = '2026-11-26T12:00:00Z';
const row: IncidentResponseRecord = { id: id + ':2', type: 'review_containment', scope: 'Host review', reason: 'Evidence',
  state: 'requested', requested_by: 'analyst', requested_at: now, decided_by: null, decided_at: null, decision_reason: null,
  finalized_by: null, finalized_at: null, final_reason: null, execution_verified: false };
const page: IncidentResponsePage = { responses: [row], mode: 'manual_tracking_only', observed_revision: 2, activity_pending: false };
describe('response projection', () => {
  test('accepts attributed requests', () => expect(() => validateResponsePage(page, id)).not.toThrow());
  test('rejects foreign or duplicate identity and unverified-success substitution', () => {
    expect(() => validateResponsePage({ ...page, responses: [{ ...row, id: 'other:2' }] }, id)).toThrow();
    expect(() => validateResponsePage({ ...page, responses: [row, row] }, id)).toThrow();
    expect(() => validateResponsePage({ ...page, responses: [{ ...row, execution_verified: true } as unknown as IncidentResponseRecord] }, id)).toThrow();
  });
  test('rejects self-approval and missing manual outcome attribution', () => {
    expect(() => validateResponsePage({ ...page, responses: [{ ...row, state: 'approved', decided_by: 'analyst', decided_at: now, decision_reason: 'Reviewed' }] }, id)).toThrow();
    expect(() => validateResponsePage({ ...page, responses: [{ ...row, state: 'reported_completed' }] }, id)).toThrow();
  });
});
