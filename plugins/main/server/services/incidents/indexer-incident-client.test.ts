import { IndexerIncidentClient, CurrentUserIncidentTransport } from './indexer-incident-client';

const ID = '00000000-0000-4000-8000-000000000001';

function setup(revision = 1) {
  const request = jest.fn().mockResolvedValue({
    body: { incident: { id: ID, revision, finding_count: 0 }, activity_delivery: 'delivered' },
  });
  return { request, client: new IndexerIncidentClient({ request } as CurrentUserIncidentTransport) };
}

describe('dedicated indexer incident adapter', () => {
  test('create sends only the allowed fields to the fixed API', async () => {
    const { client, request } = setup();
    const input = { title: 'Example', severity: 'high' as const, created_by: 'forged', owner: 'forged' };
    await client.create(input);
    expect(request).toHaveBeenCalledWith({
      method: 'POST', path: '/_plugins/_setup/incidents',
      body: { title: 'Example', severity: 'high' },
    });
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
    request.mockResolvedValueOnce({ body: { incident: { id: ID, revision: 2, finding_count: 0, pending_activity: {} }, activity_delivery: 'delivered' } });
    await expect(client.command(ID, 1, { kind: 'assign-self' })).rejects.toThrow(/projection/);
    request.mockRejectedValueOnce(new Error('network unavailable'));
    await expect(client.create({ title: 'Example', severity: 'high' })).rejects.toThrow('network unavailable');
    expect(request).toHaveBeenCalledTimes(3);
  });
});
