import { parseSchedulerSnapshot } from './wucf-scheduler-model';

const row = {
  instance: 'source', dataset: 'signins', revision: 'a'.repeat(64), interval: 300,
  state: 'ready', version: 2, due: 401, claim_expiry: null,
  status: 'local_observation', last_run: {
    observed_at: 101, completed_version: 2, outcome: 'complete',
    acknowledged_pages: 1, acknowledged_events: 5, pending: false,
  },
};
const snapshot = {
  schema_version: 1, environment: 'env', observed_at: 101,
  delivery_boundary: 'local_spool', coverage: 'unknown',
  native_delivery_qualified: false, sources: [row],
};

describe('WUCF core scheduler snapshot', () => {
  it('accepts the core v1 local observation contract', () => {
    expect(parseSchedulerSnapshot(snapshot, 'env')).toEqual(snapshot);
  });
  it('rejects leaked lease, foreign environment and impossible counts', () => {
    expect(parseSchedulerSnapshot(snapshot, 'other')).toBeNull();
    expect(parseSchedulerSnapshot({ ...snapshot, sources: [{ ...row, lease: 'secret' }] }, 'env')).toBeNull();
    expect(parseSchedulerSnapshot({ ...snapshot, sources: [{ ...row,
      last_run: { ...row.last_run, acknowledged_events: 101 } }] }, 'env')).toBeNull();
  });
  it('rejects duplicates and false coverage', () => {
    expect(parseSchedulerSnapshot({ ...snapshot, sources: [row, row] }, 'env')).toBeNull();
    expect(parseSchedulerSnapshot({ ...snapshot, coverage: 'complete' }, 'env')).toBeNull();
  });
  it('checks lifecycle status against version and timing', () => {
    expect(parseSchedulerSnapshot({ ...snapshot, observed_at: 702 }, 'env')).toBeNull();
    expect(parseSchedulerSnapshot({ ...snapshot, observed_at: 702, sources: [{ ...row, status: 'overdue' }] }, 'env')).not.toBeNull();
    expect(parseSchedulerSnapshot({ ...snapshot, sources: [{ ...row, version: 3 }] }, 'env')).toBeNull();
    expect(parseSchedulerSnapshot({ ...snapshot, sources: [{ ...row, version: 3, status: 'not_observed' }] }, 'env')).not.toBeNull();
  });
});
