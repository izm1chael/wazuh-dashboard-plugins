import { buildIncidentQuery } from './incident-query';

describe('incident queue query', () => {
  test('defaults to all open incidents without any finding time range', () => {
    const result = buildIncidentQuery({});
    expect(result.query).toEqual({ bool: { filter: [{ terms: { status: ['new', 'triaging', 'active'] } }], must_not: [], must: [] } });
    expect(result.size).toBe(51);
    expect(result._source).toEqual({ excludes: ['pending_activity'] });
  });
  test('unassigned excludes closed records and requires missing owner', () => {
    expect(buildIncidentQuery({ queue: 'unassigned' }).query).toMatchObject({
      bool: { filter: [{ terms: { status: ['new', 'triaging', 'active'] } }], must_not: [{ exists: { field: 'owner' } }] },
    });
  });
  test('bounded input and validated cursor', () => {
    expect(() => buildIncidentQuery({ limit: 101 })).toThrow();
    expect(() => buildIncidentQuery({ after: ['not-a-date', 'invalid'] })).toThrow();
    const after: [string, string] = ['2026-11-26T12:00:00.000Z', '00000000-0000-4000-8000-000000000001'];
    expect(buildIncidentQuery({ after, limit: 10 })).toMatchObject({ size: 11, search_after: after });
  });
  test('search uses a fixed multi_match, not client DSL', () => {
    expect(buildIncidentQuery({ search: 'test', severity: 'high' }).query).toMatchObject({
      bool: { filter: [{ terms: { status: ['new', 'triaging', 'active'] } }, { term: { severity: 'high' } }],
        must: [{ multi_match: { query: 'test', fields: ['title^3', 'description', 'id'] } }] },
    });
  });
});
