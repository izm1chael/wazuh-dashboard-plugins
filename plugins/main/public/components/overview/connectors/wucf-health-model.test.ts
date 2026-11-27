import { assessHealth, SourceIdentity } from './wucf-health-model';

const source: SourceIdentity = {
  environment: 'env', instance: 'source', provider: 'entra',
  dataset: 'signins', revision: 'a'.repeat(64), intervalSeconds: 60,
};
const row = {
  schema_version: 1, environment: 'env', instance: 'source', dataset: 'signins',
  provider: 'entra', revision: 'a'.repeat(64), observed_at: '2026-01-01T00:00:00+00:00',
  state: 'events_acknowledged', execution_status: 'complete', acknowledged_pages: 1,
  acknowledged_events: 2, pending: false, delivery_boundary: 'local_spool',
  coverage: 'unknown', native_delivery_qualified: false,
};
const now = Date.parse('2026-01-01T00:01:00Z');

describe('WUCF health assessment', () => {
  it('distinguishes local acknowledgement and native coverage', () => {
    const result = assessHealth(row, source, now);
    expect(result.state).toBe('local_events_observed');
    expect(result.nativeQualified).toBe(false);
    expect(result.coverage).toBe('unknown');
  });
  it('rejects foreign scope, stale revision and future observation', () => {
    expect(assessHealth(row, { ...source, instance: 'other' }, now).state).toBe('unknown');
    expect(assessHealth(row, { ...source, revision: 'b'.repeat(64) }, now).state).toBe('unknown');
    expect(assessHealth(row, source, now - 120000).state).toBe('unknown');
  });
  it('distinguishes stale, blocked and no-event states', () => {
    expect(assessHealth(row, source, now + 360000).state).toBe('stale');
    const blocked = { ...row, pending: true, state: 'delivery_blocked', execution_status: 'delivery_unknown' };
    expect(assessHealth(blocked, source, now).state).toBe('delivery_blocked');
    const empty = { ...row, acknowledged_events: 0, state: 'no_events_observed' };
    expect(assessHealth(empty, source, now).state).toBe('no_events_observed');
  });
});
