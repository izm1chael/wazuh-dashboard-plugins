import { catalogue, findDatasets, parseHealth, preview } from './wucf-model';

const row = {
  schema_version: 1, environment: 'env', instance: 'source', dataset: 'signins',
  provider: 'entra', revision: 'a'.repeat(64), observed_at: '2026-01-01T00:00:00+00:00',
  state: 'no_events_observed', execution_status: 'idle', acknowledged_pages: 0,
  acknowledged_events: 0, pending: false, delivery_boundary: 'unqualified_adapter', coverage: 'unknown', native_delivery_qualified: false,
};

describe('WUCF onboarding model', () => {
  it('searches the starter catalogue and handles empty results', () => {
    expect(findDatasets(' EnTra ')).toHaveLength(2);
    expect(findDatasets('not-present')).toHaveLength(0);
    expect(findDatasets('')).toHaveLength(6);
  });
  it('validates bounded intervals and prevents activation', () => {
    expect(preview(catalogue[0], '60')).toEqual({
      provider: 'entra', dataset: 'signins', interval_seconds: 60, activation_supported: false,
    });
    for (const interval of ['59', '86401', '1e3', '-1', '60.5', '']) {
      expect(preview(catalogue[0], interval)).toBeNull();
    }
    expect(preview({ ...catalogue[0], provider: 'unknown' }, '300')).toBeNull();
  });
  it('does not treat empty observations as coverage', () => {
    expect(parseHealth(row, 'env')).toEqual(row);
    expect(parseHealth({ ...row, coverage: 'complete' }, 'env')).toBeNull();
  });
  it('rejects unexpected fields and foreign environment', () => {
    expect(parseHealth({ ...row, credential_ref: 'secret' }, 'env')).toBeNull();
    expect(parseHealth(row, 'foreign')).toBeNull();
    expect(parseHealth({ ...row, native_delivery_qualified: true }, 'env')).toBeNull();
    expect(parseHealth({ ...row, delivery_boundary: 'native_wcs' }, 'env')).toBeNull();
    expect(parseHealth({ ...row, delivery_boundary: 'local_spool' }, 'env')).not.toBeNull();
  });
  it('rejects impossible counters, pending and state', () => {
    expect(parseHealth({ ...row, acknowledged_events: 1 }, 'env')).toBeNull();
    expect(parseHealth({ ...row, pending: true }, 'env')).toBeNull();
    expect(parseHealth({ ...row, state: 'events_acknowledged' }, 'env')).toBeNull();
    expect(parseHealth({ ...row, observed_at: 'not-a-date' }, 'env')).toBeNull();
  });
});
