import { evaluateReplay, parseReplay, ReplayRow } from './tuning-evaluation';
const input = (rows: ReplayRow[]) => ({ baseline_version: 'v1', candidate_version: 'v2', split: 'holdout', rows });
const fixtures = (): ReplayRow[] => [
  ...Array.from({ length: 10 }, (_, n) => ({ id: 'm' + n, label: 'malicious' as const, baseline: true, candidate: true })),
  ...Array.from({ length: 10 }, (_, n) => ({ id: 'b' + n, label: 'benign' as const, baseline: true, candidate: n < 2 })),
];
describe('paired tuning replay evaluation', () => {
  test('reports confusion matrices and preserves every prior malicious detection', () => {
    const result = evaluateReplay(input(fixtures()));
    expect(result.baseline).toEqual({ tp: 10, fn: 0, fp: 10, tn: 0 });
    expect(result.candidate).toEqual({ tp: 10, fn: 0, fp: 2, tn: 8 });
    expect(result.benignAlertReduction).toBe(0.8);
    expect(result.gate).toBe('eligible_for_human_review');
  });
  test('blocks a lost malicious sample even if another missed sample is gained', () => {
    const rows = fixtures(); rows[0].candidate = false; rows[1].baseline = false;
    const result = evaluateReplay(input(rows));
    expect(result.baselineRecall).toBe(result.candidateRecall);
    expect(result.lostMalicious).toBe(1);
    expect(result.gainedMalicious).toBe(1);
    expect(result.gate).toBe('blocked');
  });
  test('unknown labels never become benign and empty denominators stay null', () => {
    const result = evaluateReplay(input([{ id: 'u', label: 'unknown', baseline: true, candidate: false }]));
    expect(result.unknownChanged).toBe(1);
    expect(result.benignAlertReduction).toBeNull();
    expect(result.candidateRecall).toBeNull();
    expect(result.reasons).toContain('unknown_labels_present');
  });
  test('rejects duplicates, unpaired outputs, extra fields and non-holdout claims', () => {
    const rows = fixtures();
    expect(() => parseReplay(input([rows[0], rows[0]]))).toThrow();
    expect(() => parseReplay({ ...input(rows), split: 'train' })).toThrow();
    expect(() => parseReplay(input([{ ...rows[0], candidate: 'false' } as unknown as ReplayRow]))).toThrow();
    expect(() => parseReplay(input([{ ...rows[0], raw_log: 'secret' } as ReplayRow]))).toThrow();
  });
  test('blocks new benign alerts even with net reduction', () => {
    const rows = fixtures(); rows[10].baseline = false;
    expect(evaluateReplay(input(rows)).reasons).toContain('new_benign_alerts');
  });
});
