import { HUNT_FIELDS, HuntInput, HuntReport, HuntRow, validateHunt, validateHuntReport, validHuntValue } from './hunt-contract';

const raw: HuntInput = { field: 'source.ip', values: ['192.0.2.2', '192.0.2.1'],
  from: '2026-11-25T00:00:00Z', until: '2026-11-26T00:00:00Z' };
const input = validateHunt(raw);
const row: HuntRow = { index: '.ds-wazuh-findings-v5-security-000001', document_id: 'doc',
  timestamp: '2026-11-25T12:00:00.123456789Z', matched_values: ['192.0.2.1'] };
const report: HuntReport = { ...input, scope: 'caller_visible_findings_exact_terms', rows: [row], match_count: 1 };

describe('bounded exact hunt contract', () => {
  it('canonicalizes valid input without changing source spelling', () => {
    expect(input).toEqual({ ...raw, values: ['192.0.2.1', '192.0.2.2'],
      from: '2026-11-25T00:00:00.000Z', until: '2026-11-26T00:00:00.000Z' });
    expect(HUNT_FIELDS).toHaveLength(15);
  });
  it('rejects malformed and excessive IP lists', () => {
    for (const values of [[], ['192.0.2.1', '192.0.2.1'], ['192.0.2.256'], ['192.00.2.1'],
      ['192.0.2.0/24'], ['::1'], ['192.0.2.1 '], Array.from({ length: 21 }, (_, i) => '192.0.2.' + i)]) {
      expect(() => validateHunt({ ...raw, values })).toThrow();
    }
  });
  it('rejects arbitrary fields and invalid or oversized date ranges', () => {
    for (const patch of [{ field: '_id' }, { until: raw.from }, { until: '2026-12-03T00:00:00Z' },
      { from: '2026-02-30T00:00:00Z' }, { from: '2026-11-25T00:00:00.0001Z' },
      { from: '2026-11-25T00:00:00+00:00' }]) {
      expect(() => validateHunt({ ...raw, ...patch } as HuntInput)).toThrow();
    }
  });
  it('validates exact digest lengths', () => {
    for (const [field, length] of [['file.hash.md5', 32], ['file.hash.sha1', 40], ['file.hash.sha256', 64]] as const) {
      expect(validHuntValue(field, 'a'.repeat(length))).toBe(true);
      expect(validHuntValue(field, 'a'.repeat(length - 1))).toBe(false);
    }
  });
  it('accepts matching projections including zero results', () => {
    expect(validateHuntReport(report, input)).toEqual(report);
    expect(validateHuntReport({ ...report, rows: [], match_count: 0 }, input).match_count).toBe(0);
  });
  it('fails closed on malformed, duplicated, mismatched or excessive result data', () => {
    const patches = [{ scope: 'other' }, { field: 'destination.ip' }, { values: ['192.0.2.1'] },
      { from: '2026-11-24T00:00:00Z' }, { match_count: 2 }, { raw: 'secret' },
      { rows: [row, row], match_count: 2 }, { rows: [{ ...row, matched_values: ['192.0.2.8'] }] },
      { rows: [{ ...row, matched_values: [] }] }, { rows: [{ ...row, matched_values: ['192.0.2.1', '192.0.2.1'] }] },
      { rows: [{ ...row, timestamp: input.until }] }, { rows: [{ ...row, index: 'private-index' }] },
      { rows: [{ ...row, source: { secret: 1 } }] },
      { rows: Array.from({ length: 101 }, (_, i) => ({ ...row, document_id: 'doc' + i })), match_count: 101 }];
    for (const patch of patches) expect(() => validateHuntReport({ ...report, ...patch } as HuntReport, input)).toThrow();
  });
});
