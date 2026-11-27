import type { FindingObservation, IncidentActivity, IncidentSummary } from '../../../../common/incidents/contracts';
import { buildTimeline, loadInvestigation } from './investigation-snapshot';

const id = '00000000-0000-4000-8000-000000000001';
const at = '2026-11-26T12:00:00.000Z';
const incident = { id, revision: 3, finding_count: 26 } as IncidentSummary;
const observation = (n: number): FindingObservation => ({
  index: 'findings', document_id: String(n), timestamp: at, rule_id: '1', rule_title: 'Rule',
  entities: [], techniques: [], tactics: [],
});
const event = (revision: number): IncidentActivity => ({
  id: id + ':' + revision, incident_id: id, revision, at, kind: 'edit', actor: 'analyst', changes: {},
});
function reader() {
  return {
    findings: jest.fn(async (_id: string, offset: number, _revision: number) => {
      const observations = Array.from({ length: offset === 0 ? 24 : 1 }, (_, n) => observation(offset + n));
      return { findings: observations.map(({ index, document_id }) => ({ index, document_id })), observations,
        revision: 3, unavailable_count: offset === 0 ? 1 : 0, ...(offset === 0 ? { next_offset: 25 } : {}) };
    }),
    activity: jest.fn(async (_id: string, _before: number) => ({
      events: [event(3), event(1)], observed_revision: 3, activity_pending: true,
    })),
    get: jest.fn(async (_id: string) => incident),
  };
}
describe('bounded investigation snapshot', () => {
  test('conserves visible, unavailable and unscanned positions and discloses missing audit', async () => {
    const api = reader();
    const result = await loadInvestigation(api, incident);
    expect(api.findings.mock.calls).toEqual([[id, 0, 3], [id, 25, 3]]);
    expect(result.positions).toBe(26);
    expect(result.unavailable).toBe(1);
    expect(result.unscanned).toBe(0);
    expect(result.observations).toHaveLength(25);
    expect(result.missingAuditRevisions).toBe(1);
    expect(result.activityPending).toBe(true);
    expect(result.rows).toHaveLength(27);
  });
  test('rejects stale revision after collecting rows', async () => {
    const api = reader();
    api.get.mockResolvedValue({ ...incident, revision: 4 });
    await expect(loadInvestigation(api, incident)).rejects.toThrow();
  });
  test('rejects observation not returned as a visible reference', async () => {
    const api = reader();
    api.findings.mockResolvedValueOnce({ findings: [{ index: 'findings', document_id: 'visible' }],
      observations: [observation(1)], revision: 3, unavailable_count: 24, next_offset: 25 });
    await expect(loadInvestigation(api, incident)).rejects.toThrow();
  });
  test('rejects cursor drift', async () => {
    const api = reader();
    const page = await api.findings(id, 0, 3);
    api.findings.mockResolvedValueOnce({ ...page, next_offset: 24 });
    await expect(loadInvestigation(api, incident)).rejects.toThrow();
  });
  test('stops before further requests when cancelled', async () => {
    const api = reader();
    await expect(loadInvestigation(api, incident, () => true)).rejects.toThrow();
    expect(api.findings).not.toHaveBeenCalled();
  });
  test('unknown timestamps sort after dated observations with stable unique keys', () => {
    const result = buildTimeline([{ ...observation(1), timestamp: null }, observation(2)], [event(3)]);
    expect(result.map(row => row.source)).toEqual(['activity', 'finding', 'finding']);
    expect(result[2].at).toBeNull();
    expect(new Set(result.map(row => row.key)).size).toBe(3);
  });
  test('stops at four finding pages and preserves the remaining count', async () => {
    const api = reader(), large = { ...incident, finding_count: 125 };
    api.get.mockResolvedValue(large);
    api.findings.mockImplementation(async (_id, offset) => {
      const observations = Array.from({ length: 25 }, (_, n) => observation(offset + n));
      return { findings: observations, observations, revision: 3, unavailable_count: 0, next_offset: offset + 25 };
    });
    const result = await loadInvestigation(api, large);
    expect(api.findings).toHaveBeenCalledTimes(4);
    expect(result.positions).toBe(100);
    expect(result.unscanned).toBe(25);
  });
});
