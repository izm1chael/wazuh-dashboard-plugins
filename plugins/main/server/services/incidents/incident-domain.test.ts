import { applyIncidentCommand, createIncident, Incident, IncidentCommand } from './incident-domain';

const ID = '00000000-0000-4000-8000-000000000001';
const T0 = '2026-11-26T12:00:00.000Z';
const T1 = '2026-11-26T12:01:00.000Z';
const T2 = '2026-11-26T12:02:00.000Z';
const T3 = '2026-11-26T12:03:00.000Z';
const T4 = '2026-11-26T12:04:00.000Z';
const T5 = '2026-11-26T12:05:00.000Z';

const create = () => createIncident({ title: 'Suspicious activity', severity: 'high' }, ID, 'creator', T0);
// Only the durable activity-delivery adapter may perform this acknowledgement in production.
const delivered = (incident: Incident): Incident => ({ ...incident, pending_activity: null });
const apply = (incident: Incident, command: IncidentCommand, actor: string, at: string) =>
  applyIncidentCommand(delivered(incident), command, actor, at);

describe('first-class incident domain', () => {
  test('creates a standalone unassigned incident and immutable logical activity identity', () => {
    const incident = create();
    expect(incident).toMatchObject({ id: ID, status: 'new', owner: null, created_by: 'creator', revision: 1 });
    expect(incident.pending_activity).toMatchObject({ id: ID + ':1', actor: 'creator', kind: 'created' });
  });

  test('assignment and editing attribution are separate', () => {
    const assigned = apply(create(), { kind: 'assign', owner: 'analyst' }, 'supervisor', T1);
    const triage = apply(assigned, { kind: 'start_triage' }, 'other', T2);
    expect(triage).toMatchObject({ owner: 'analyst', created_by: 'creator', updated_by: 'other', first_assigned_at: T1, triage_started_at: T2 });
    expect(triage.pending_activity?.changes.status).toEqual({ before: 'new', after: 'triaging' });
  });

  test('requires durable activity delivery before another command', () => {
    expect(() => applyIncidentCommand(create(), { kind: 'assign', owner: 'analyst' }, 'creator', T1)).toThrow(/Pending activity/);
  });

  test('blocks invalid transitions and unassigned triage', () => {
    expect(() => apply(create(), { kind: 'activate' }, 'analyst', T1)).toThrow();
    expect(() => apply(create(), { kind: 'start_triage' }, 'analyst', T1)).toThrow(/Assign/);
  });

  test('records classified closure and reopening without erasing first closure or creation', () => {
    const assigned = apply(create(), { kind: 'assign', owner: 'analyst' }, 'analyst', T1);
    const triage = apply(assigned, { kind: 'start_triage' }, 'analyst', T2);
    const active = apply(triage, { kind: 'activate' }, 'analyst', T3);
    const closed = apply(active, { kind: 'close', classification: 'true_positive', reason: 'Verified containment' }, 'analyst', T4);
    const reopened = apply(closed, { kind: 'reopen', reason: 'New evidence' }, 'supervisor', T5);
    expect(reopened).toMatchObject({ status: 'active', closed_at: null, closure: null, first_closed_at: T4, reopened_at: T5, created_at: T0, activated_at: T3, owner: 'analyst', revision: 6 });
    expect(reopened.pending_activity?.changes.closure.before).toEqual(closed.closure);
    expect(closed.status).toBe('closed');
  });

  test('rejects empty closure reasons and backwards clocks', () => {
    const assigned = apply(create(), { kind: 'assign', owner: 'analyst' }, 'analyst', T1);
    const triage = apply(assigned, { kind: 'start_triage' }, 'analyst', T2);
    expect(() => apply(triage, { kind: 'close', classification: 'false_positive', reason: ' ' }, 'analyst', T3)).toThrow();
    expect(() => apply(triage, { kind: 'activate' }, 'analyst', T1)).toThrow(/backwards/);
  });
});
