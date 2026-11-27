import { AnalyticsStatus, AnalyticsWindowQuery, healthWindows, latestSettledWindow, validateAnalyticsStatus, validateWindow } from './analytics-contract';

const policy = '00000000-0000-4000-8000-000000000002';
const query: AnalyticsWindowQuery = { policy_id: policy, policy_version: 1, from: '2026-11-26T12:00:00Z', until: '2026-11-26T12:15:00Z' };
const base = { ...query, run_id: 'a'.repeat(64) };
const completed: AnalyticsStatus = { ...base, state: 'completed', finding_count: 3, group_count: 1,
  below_threshold: 1, actor: 'runner', reserved_at: '2026-11-26T12:17:00Z', completed_at: '2026-11-26T12:17:01.123456789Z' };

describe('analytics execution receipt contract', () => {
  it('rejects malformed, overlong or forged windows', () => {
    expect(validateWindow(query)).toEqual(query);
    for (const patch of [{ policy_id: 'bad' }, { policy_version: 0 }, { policy_version: 1.5 },
      { policy_version: 2147483648 }, { from: query.until }, { from: '2026-02-30T12:00:00Z' },
      { from: '2026-11-26T12:00:00.000Z' }, { until: '2026-11-28T12:15:00Z' }, { actor: 'forged' }]) {
      expect(() => validateWindow({ ...query, ...patch })).toThrow();
    }
  });
  it('distinguishes missing, reserved, completed and completed zero-match windows', () => {
    expect(validateAnalyticsStatus(completed, query)).toEqual(completed);
    expect(validateAnalyticsStatus({ ...base, state: 'not_recorded' }, query).state).toBe('not_recorded');
    expect(validateAnalyticsStatus({ ...completed, state: 'reserved', completed_at: null }, query).state).toBe('reserved');
    expect(validateAnalyticsStatus({ ...completed, finding_count: 0, group_count: 0, below_threshold: 0 }, query).state).toBe('completed');
  });
  it('rejects mismatched identity, invalid counts, chronology and unexpected source data', () => {
    for (const patch of [{ run_id: 'bad' }, { policy_id: 'bad' }, { policy_version: 2 }, { from: '2026-11-26T11:00:00Z' },
      { state: 'failed' }, { finding_count: 101 }, { group_count: 21 }, { below_threshold: 4 }, { group_count: 2 },
      { group_count: 0 }, { actor: ' ' }, { actor: 'a\nb' }, { reserved_at: '2026-11-26T12:16:59Z' },
      { completed_at: '2026-11-26T12:16:59Z' }, { completed_at: null }, { state: 'reserved' }, { raw: 'secret' }]) {
      expect(() => validateAnalyticsStatus({ ...completed, ...patch } as AnalyticsStatus, query)).toThrow();
    }
    expect(() => validateAnalyticsStatus({ ...base, state: 'not_recorded', finding_count: 0 } as AnalyticsStatus, query)).toThrow();
  });
  it('constructs bounded aligned health windows and respects the settlement grace', () => {
    expect(healthWindows(policy, 1, 15, query.until, 2)).toEqual([query,
      { ...query, from: '2026-11-26T11:45:00Z', until: query.from }]);
    expect(() => healthWindows(policy, 1, 4, query.until, 1)).toThrow();
    expect(() => healthWindows(policy, 1, 1441, query.until, 1)).toThrow();
    expect(() => healthWindows(policy, 1, 15, query.until, 11)).toThrow();
    expect(() => healthWindows(policy, 1, 15, '2026-11-26T12:14:00Z', 1)).toThrow();
    expect(() => healthWindows(policy, 1, 15, query.until, 0)).toThrow();
    expect(latestSettledWindow(15, Date.parse('2026-11-26T12:16:59Z'))).toBe(query.from);
    expect(latestSettledWindow(15, Date.parse('2026-11-26T12:17:00Z'))).toBe(query.until);
  });
});
