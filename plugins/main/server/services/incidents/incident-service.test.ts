import { createIncident } from './incident-domain';
import { IncidentService } from './incident-service';

const ID = '00000000-0000-4000-8000-000000000001';
const NOW = '2026-11-26T12:00:00.000Z';
const principal = { username: 'analyst' };
const record = createIncident({ title: 'Test', severity: 'high' }, ID, 'creator', NOW);
const previous = { record: { ...record, pending_activity: null }, seqNo: 2, primaryTerm: 1 };

function setup() {
  const store = {
    list: jest.fn().mockResolvedValue({ incidents: [] }),
    get: jest.fn().mockResolvedValue(previous),
    create: jest.fn().mockImplementation(async incident => ({ record: incident, seqNo: 1, primaryTerm: 1 })),
    commit: jest.fn().mockImplementation(async (_, incident) => ({ record: incident, seqNo: 3, primaryTerm: 1 })),
    deliverPending: jest.fn().mockImplementation(async version => ({ ...version, record: { ...version.record, pending_activity: null } })),
  };
  const authorization = { require: jest.fn().mockResolvedValue(undefined), requireAssignableOwner: jest.fn().mockResolvedValue(undefined) };
  const report = jest.fn();
  return { store, authorization, report, service: new IncidentService(store, authorization, () => ID, () => NOW, report) };
}

describe('incident service', () => {
  test('denies an operation before touching storage', async () => {
    const { service, authorization, store } = setup();
    authorization.require.mockRejectedValueOnce(new Error('denied'));
    await expect(service.get(principal, ID)).rejects.toThrow('denied');
    expect(store.get).not.toHaveBeenCalled();
  });
  test('queue read is authorized and validates pagination before storage', async () => {
    const { service, authorization, store } = setup();
    await expect(service.list(principal, { limit: 101 })).rejects.toThrow();
    expect(store.list).not.toHaveBeenCalled();
    expect(await service.list(principal, { queue: 'open' })).toEqual({ incidents: [] });
    expect(authorization.require).toHaveBeenCalledWith(principal, 'read');
  });
  test('creates using authenticated attribution, never an input actor', async () => {
    const { service, authorization, store } = setup();
    const result = await service.create(principal, { title: 'New', severity: 'low' });
    expect(authorization.require).toHaveBeenCalledWith(principal, 'create');
    expect(store.create.mock.calls[0][0].created_by).toBe('analyst');
    expect(result.incident).not.toHaveProperty('pending_activity');
    expect(result.activityDelivery).toBe('delivered');
  });
  test('uses command-specific grants and validates assignee', async () => {
    const { service, authorization, store } = setup();
    authorization.requireAssignableOwner.mockRejectedValueOnce(new Error('not assignable'));
    await expect(service.command(principal, ID, 1, { kind: 'assign', owner: 'unknown' })).rejects.toThrow('not assignable');
    expect(authorization.require).toHaveBeenCalledWith(principal, 'assign');
    expect(store.commit).not.toHaveBeenCalled();
  });
  test('rejects stale revisions without mutating', async () => {
    const { service, store } = setup();
    await expect(service.command(principal, ID, 2, { kind: 'assign', owner: 'analyst' })).rejects.toMatchObject({ code: 'conflict' });
    expect(store.commit).not.toHaveBeenCalled();
  });
  test('distinguishes committed mutation from failed audit delivery', async () => {
    const { service, store, report } = setup();
    store.deliverPending.mockRejectedValueOnce(new Error('offline'));
    const result = await service.command(principal, ID, 1, { kind: 'assign', owner: 'analyst' });
    expect(result.incident).toMatchObject({ revision: 2, owner: 'analyst' });
    expect(result.activityDelivery).toBe('pending');
    expect(report).toHaveBeenCalledWith(ID, expect.any(Error));
    expect(store.commit).toHaveBeenCalledTimes(1);
  });
});
