import { applyIncidentCommand, createIncident } from './incident-domain';
import { IncidentStore, IncidentTransport, VersionedIncident } from './incident-store';

const ID = '00000000-0000-4000-8000-000000000001';
const create = () => createIncident({ title: 'Test', severity: 'high' }, ID, 'creator', '2026-11-26T12:00:00.000Z');
const writeResult = { body: { _seq_no: 2, _primary_term: 1 } };
const versioned = (): VersionedIncident => ({ record: create(), seqNo: 1, primaryTerm: 1 });
const conflict = { meta: { statusCode: 409 } };

function setup() {
  const request = jest.fn();
  const store = new IncidentStore({ request } as IncidentTransport);
  return { request, store };
}

describe('incident persistence', () => {
  test('returns a bounded queue page and omits internal activity payload', async () => {
    const { request, store } = setup();
    const record = create();
    const cursor = [record.updated_at, record.id];
    request.mockResolvedValueOnce({ body: { hits: { hits: [
      { _source: record, sort: cursor },
      { _source: { ...record, id: '00000000-0000-4000-8000-000000000002' } },
    ] } } });
    const result = await store.list({ limit: 1 });
    expect(result.incidents).toHaveLength(1);
    expect(result.incidents[0]).not.toHaveProperty('pending_activity');
    expect(result.next).toEqual(cursor);
    expect(request).toHaveBeenCalledWith(expect.objectContaining({
      path: '/wazuh-cases-v1/_search',
      querystring: { allow_partial_search_results: 'false' },
    }));
  });
  test('rejects partial queue search', async () => {
    const { request, store } = setup();
    request.mockResolvedValueOnce({ body: { timed_out: true } });
    await expect(store.list({})).rejects.toThrow(/Incomplete/);
  });

  test('creates the aggregate without overwriting an existing incident', async () => {
    const { request, store } = setup();
    request.mockResolvedValueOnce(writeResult);
    const record = create();
    const result = await store.create(record);
    expect(request).toHaveBeenCalledWith(expect.objectContaining({
      method: 'PUT', path: '/wazuh-cases-v1/_create/' + ID, body: record,
    }));
    expect(result.seqNo).toBe(2);
  });

  test('uses sequence number and primary term on every aggregate mutation', async () => {
    const { request, store } = setup();
    const previous = versioned();
    previous.record = { ...previous.record, pending_activity: null };
    const next = applyIncidentCommand(previous.record, { kind: 'assign', owner: 'analyst' }, 'supervisor', '2026-11-26T12:01:00.000Z');
    request.mockResolvedValueOnce(writeResult);
    await store.commit(previous, next);
    expect(request).toHaveBeenCalledWith(expect.objectContaining({
      path: '/wazuh-cases-v1/_doc/' + ID,
      querystring: { if_seq_no: 1, if_primary_term: 1, refresh: 'wait_for' },
      body: next,
    }));
    request.mockRejectedValueOnce(conflict);
    await expect(store.commit(previous, next)).rejects.toMatchObject({ code: 'conflict' });
  });

  test('delivers activity before clearing the outbox and keeps logical revision', async () => {
    const { request, store } = setup();
    request.mockResolvedValue(writeResult);
    const previous = versioned();
    const result = await store.deliverPending(previous);
    expect(request.mock.calls[0][0].path).toBe('/wazuh-case-activity-v1/_create/' + ID + '%3A1');
    expect(request.mock.calls[1][0].body.pending_activity).toBeNull();
    expect(result.record.revision).toBe(1);
    expect(previous.record.pending_activity).not.toBeNull();
  });

  test('recovers an already-delivered identical event', async () => {
    const { request, store } = setup();
    const previous = versioned();
    request.mockRejectedValueOnce(conflict)
      .mockResolvedValueOnce({ body: { _source: previous.record.pending_activity } })
      .mockResolvedValueOnce(writeResult);
    const result = await store.deliverPending(previous);
    expect(result.record.pending_activity).toBeNull();
    expect(request).toHaveBeenCalledTimes(3);
  });

  test('does not acknowledge a conflicting event or failed delivery', async () => {
    const { request, store } = setup();
    const previous = versioned();
    request.mockRejectedValueOnce(conflict).mockResolvedValueOnce({ body: { _source: { actor: 'different' } } });
    await expect(store.deliverPending(previous)).rejects.toThrow(/collision/);
    expect(request).toHaveBeenCalledTimes(2);
    request.mockReset().mockRejectedValueOnce(new Error('network unavailable'));
    await expect(store.deliverPending(previous)).rejects.toThrow(/network/);
    expect(request).toHaveBeenCalledTimes(1);
    expect(previous.record.pending_activity).not.toBeNull();
  });

  test('acknowledgement conflict cannot overwrite a newer aggregate', async () => {
    const { request, store } = setup();
    request.mockResolvedValueOnce(writeResult).mockRejectedValueOnce(conflict);
    await expect(store.deliverPending(versioned())).rejects.toMatchObject({ code: 'conflict' });
    expect(request).toHaveBeenCalledTimes(2);
  });
});
