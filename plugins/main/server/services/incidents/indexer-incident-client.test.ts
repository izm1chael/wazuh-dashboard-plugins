import { IndexerIncidentClient, CurrentUserIncidentTransport } from './indexer-incident-client';

const ID = '00000000-0000-4000-8000-000000000001';

function setup(revision = 1) {
  const request = jest.fn().mockResolvedValue({
    body: { incident: { id: ID, revision, finding_count: 0 }, activity_delivery: 'delivered', replayed: false },
  });
  return { request, client: new IndexerIncidentClient({ request } as CurrentUserIncidentTransport) };
}

describe('dedicated indexer incident adapter', () => {
  test('reads fixed incident detail and queue paths', async () => {
    const { client, request } = setup();
    const incident = { id: ID, revision: 1, finding_count: 0 };
    request.mockResolvedValueOnce({ body: { incident } });
    expect(await client.get(ID)).toEqual(incident);
    expect(request.mock.calls[0][0]).toEqual({ method: 'GET', path: '/_plugins/_setup/incidents/' + ID });
    request.mockResolvedValueOnce({ body: { incidents: [incident], next: { time: 123, id: ID } } });
    await client.list({ queue: 'unassigned', limit: 1, after: { time: 122, id: ID } });
    expect(request.mock.calls[1][0]).toEqual({
      method: 'GET', path: '/_plugins/_setup/incidents',
      querystring: { queue: 'unassigned', limit: 1, after_time: 122, after_id: ID },
    });
  });

  test('personal queue requests do not accept an actor override', async () => {
    const { client, request } = setup();
    request.mockResolvedValueOnce({ body: { incidents: [] } });
    await client.list({ queue: 'handover', limit: 50 });
    expect(request.mock.calls[0][0].querystring).toEqual({ queue: 'handover', limit: 50 });
  });

  test('handover commands forward only target and reason and validate returned ownership', async () => {
    const { client, request } = setup(2);
    const command = { kind: 'offer-handover' as const, target: 'bob', reason: 'Shift change', actor: 'forged' };
    await client.command(ID, 1, command);
    expect(request.mock.calls[0][0].body).toEqual({ target: 'bob', reason: 'Shift change' });
    expect(request.mock.calls[0][0].path).toBe('/_plugins/_setup/incidents/' + ID + '/offer-handover');
    request.mockResolvedValueOnce({ body: { incident: { id: ID, revision: 2, finding_count: 0, owner: 'alice',
      handover: { target: 'bob', offered_by: 'eve', offered_at: '2026-11-26T12:00:00Z' } } } });
    await expect(client.get(ID)).rejects.toThrow(/handover projection/);
  });

  test('rejects invalid queue limits and leaked internal data', async () => {
    const { client, request } = setup();
    await expect(client.list({ limit: 101 })).rejects.toThrow();
    expect(request).not.toHaveBeenCalled();
    request.mockResolvedValueOnce({ body: { incidents: [{ id: ID, revision: 1, finding_count: 0, findings: [] }] } });
    await expect(client.list()).rejects.toThrow(/projection/);
  });

  test('activity reads are incident scoped and reject a mismatched event identity', async () => {
    const { client, request } = setup();
    const event = { id: ID + ':1', incident_id: ID, revision: 1, actor: 'analyst', kind: 'created', at: '2026-11-26T12:00:00.000Z', changes: {} };
    request.mockResolvedValueOnce({ body: { events: [event], observed_revision: 1, activity_pending: false } });
    expect((await client.activity(ID)).events).toEqual([event]);
    expect(request.mock.calls[0][0]).toEqual({
      method: 'GET', path: '/_plugins/_setup/incidents/' + ID + '/activity', querystring: { before: 0, limit: 50 },
    });
    request.mockResolvedValueOnce({ body: { events: [{ ...event, incident_id: 'other' }], observed_revision: 1, activity_pending: false } });
    await expect(client.activity(ID)).rejects.toThrow(/activity response/);
  });

  test('finding reads require a revision for later pages and reject leaked source fields', async () => {
    const { client, request } = setup();
    await expect(client.findings(ID, 25)).rejects.toThrow();
    expect(request).not.toHaveBeenCalled();
    const ref = { index: '.ds-wazuh-findings-v5-security-000001', document_id: 'doc' };
    request.mockResolvedValueOnce({ body: { findings: [ref], unavailable_count: 1, revision: 2 } });
    expect((await client.findings(ID, 0, 2)).findings).toEqual([ref]);
    request.mockResolvedValueOnce({ body: { findings: [{ ...ref, source: { secret: true } }], unavailable_count: 0, revision: 2 } });
    await expect(client.findings(ID, 0, 2)).rejects.toThrow(/finding response/);
  });

  test('create sends only the allowed fields to the fixed API', async () => {
    const { client, request } = setup();
    const input = { title: 'Example', severity: 'high' as const, created_by: 'forged', owner: 'forged' };
    await client.create(input, ID);
    expect(request).toHaveBeenCalledWith({
      method: 'POST', path: '/_plugins/_setup/incidents',
      body: { request_id: ID, title: 'Example', severity: 'high' },
    });
  });

  test('same create key is retained and a replay can return the current revision', async () => {
    const { client, request } = setup();
    request.mockResolvedValueOnce({ body: { incident: { id: ID, revision: 3, finding_count: 0 }, activity_delivery: 'pending', replayed: true } });
    const input = { title: 'Example', severity: 'high' as const };
    const result = await client.create(input, ID);
    expect(result.replayed).toBe(true);
    expect(result.incident.revision).toBe(3);
    expect(request.mock.calls[0][0].body.request_id).toBe(ID);
    await expect(client.create(input, 'invalid')).rejects.toThrow();
    expect(request).toHaveBeenCalledTimes(1);
  });

  test('commands carry the expected revision and fixed command path', async () => {
    const { client, request } = setup(2);
    await client.command(ID, 1, { kind: 'close', classification: 'true_positive', reason: 'Verified' });
    expect(request).toHaveBeenCalledWith({
      method: 'POST', path: '/_plugins/_setup/incidents/' + ID + '/close',
      querystring: { expected_revision: 1 }, body: { classification: 'true_positive', reason: 'Verified' },
    });
  });

  test('passes finding references, never source documents', async () => {
    const { client, request } = setup(2);
    const command = { kind: 'attach-finding' as const, index: '.ds-wazuh-findings-v5-security-000001', document_id: 'opaque', source: { forged: true } };
    await client.command(ID, 1, command);
    expect(request.mock.calls[0][0].body).toEqual({ index: command.index, document_id: 'opaque' });
  });

  test('rejects malformed IDs and revisions without calling transport', async () => {
    const { client, request } = setup();
    await expect(client.command('../admin', 1, { kind: 'assign-self' })).rejects.toThrow();
    await expect(client.command(ID, 0, { kind: 'assign-self' })).rejects.toThrow();
    expect(request).not.toHaveBeenCalled();
  });

  test('rejects mismatched revision or internal fields and never retries failures', async () => {
    const { client, request } = setup();
    await expect(client.command(ID, 1, { kind: 'assign-self' })).rejects.toThrow(/projection/);
    request.mockResolvedValueOnce({ body: { incident: { id: ID, revision: 2, finding_count: 0, pending_activity: {} }, activity_delivery: 'delivered', replayed: false } });
    await expect(client.command(ID, 1, { kind: 'assign-self' })).rejects.toThrow(/projection/);
    request.mockRejectedValueOnce(new Error('network unavailable'));
    await expect(client.create({ title: 'Example', severity: 'high' }, ID)).rejects.toThrow('network unavailable');
    expect(request).toHaveBeenCalledTimes(3);
  });
});
