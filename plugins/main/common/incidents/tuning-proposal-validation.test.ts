import { validReplay } from './tuning-proposal-validation';
import type { TuningReplayReceipt } from './contracts';
const row: TuningReplayReceipt = { fixture_sha256: 'a'.repeat(64), total: 20, malicious: 10, benign: 10, unknown: 0,
  unknown_changed: 0, baseline_tp: 10, candidate_tp: 10, baseline_fp: 10, candidate_fp: 2, lost_malicious: 0,
  gained_malicious: 0, removed_benign: 8, added_benign: 0, gate: 'eligible_for_human_review' };
describe('tuning receipt validation', () => {
  test('accepts conserved counts and rejects fabricated gate', () => {
    expect(validReplay(row)).toBe(true);
    expect(validReplay({ ...row, candidate_tp: 9, lost_malicious: 1 })).toBe(false);
    expect(validReplay({ ...row, candidate_tp: 9, lost_malicious: 1, gate: 'blocked' })).toBe(true);
  });
  test('rejects impossible paired transitions', () => {
    expect(validReplay({ ...row, lost_malicious: 1, gained_malicious: 1, gate: 'blocked' })).toBe(false);
    expect(validReplay({ ...row, total: 19 })).toBe(false);
    expect(validReplay({ ...row, removed_benign: 9 })).toBe(false);
  });
});
