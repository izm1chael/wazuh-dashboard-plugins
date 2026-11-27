import { parseManagementHealth, statusLabel } from './wucf-management-health';

const run = { observed_at: 101, completed_version: 3, outcome: 'complete', acknowledged_pages: 1, acknowledged_events: 5, pending: false };
const source = { instance: 'a', dataset: 'signins', revision: 'a'.repeat(64), interval: 300, state: 'ready', version: 3,
  due: 401, claim_expiry: null, status: 'local_observation', last_run: run };
const snapshot = { schema_version: 1, environment: 'env-a', observed_at: 101, delivery_boundary: 'local_spool',
  coverage: 'unknown', native_delivery_qualified: false, sources: [source] };

describe('WUCF management health snapshot', () => {
  it('accepts scoped local observations and recomputes freshness', () => {
    expect(parseManagementHealth(snapshot, 'env-a')).toEqual(snapshot);
    expect(parseManagementHealth({ ...snapshot, observed_at: 702, sources: [{ ...source, status: 'overdue' }] }, 'env-a')).not.toBeNull();
    expect(statusLabel('local_observation')).toBe('Local run recorded');
  });
  it('rejects scope and native delivery overclaims', () => {
    expect(parseManagementHealth(snapshot, 'env-b')).toBeNull();
    expect(parseManagementHealth({ ...snapshot, native_delivery_qualified: true }, 'env-a')).toBeNull();
    expect(parseManagementHealth({ ...snapshot, coverage: 'complete' }, 'env-a')).toBeNull();
    expect(parseManagementHealth({ ...snapshot, sources: [{ ...source, lease: 'secret' }] }, 'env-a')).toBeNull();
  });
  it('rejects false state, counters and repeated source identities', () => {
    expect(parseManagementHealth({ ...snapshot, sources: [{ ...source, status: 'overdue' }] }, 'env-a')).toBeNull();
    expect(parseManagementHealth({ ...snapshot, sources: [{ ...source, last_run: { ...run, acknowledged_events: 101 } }] }, 'env-a')).toBeNull();
    expect(parseManagementHealth({ ...snapshot, sources: [source, source] }, 'env-a')).toBeNull();
  });
  it('distinguishes stale or expired work from a successful observation', () => {
    expect(parseManagementHealth({ ...snapshot, sources: [{ ...source, version: 4, status: 'not_observed' }] }, 'env-a')).not.toBeNull();
    expect(parseManagementHealth({ ...snapshot, sources: [{ ...source, version: 4, claim_expiry: 100, status: 'expired_claim' }] }, 'env-a')).not.toBeNull();
    expect(parseManagementHealth({ ...snapshot, sources: [{ ...source, version: 4 }] }, 'env-a')).toBeNull();
  });
});
