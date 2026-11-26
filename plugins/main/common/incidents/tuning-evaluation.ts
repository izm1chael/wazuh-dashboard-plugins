export type Label = 'malicious' | 'benign' | 'unknown';
export interface ReplayRow { id: string; label: Label; baseline: boolean; candidate: boolean }
export interface ReplayInput { baseline_version: string; candidate_version: string; split: 'holdout'; rows: ReplayRow[] }
export const MIN_CLASS_SUPPORT = 10;
export const MAX_ROWS = 5000;

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Expected a JSON object');
  return value as Record<string, unknown>;
}
function exact(value: Record<string, unknown>, keys: string[]) {
  if (Object.keys(value).length !== keys.length || !keys.every(key => Object.prototype.hasOwnProperty.call(value, key))) {
    throw new Error('Unexpected or missing replay fields');
  }
}
function token(value: unknown): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_.:-]{1,128}$/.test(value)) throw new Error('Invalid fixture ID or version');
  return value;
}
export function parseReplay(input: unknown): ReplayInput {
  const source = object(input);
  exact(source, ['baseline_version', 'candidate_version', 'split', 'rows']);
  const baseline_version = token(source.baseline_version), candidate_version = token(source.candidate_version);
  if (baseline_version === candidate_version || source.split !== 'holdout' || !Array.isArray(source.rows) ||
      source.rows.length < 1 || source.rows.length > MAX_ROWS) throw new Error('Distinct versions and a bounded holdout fixture required');
  const seen = new Set<string>();
  const rows = source.rows.map(raw => {
    const row = object(raw);
    exact(row, ['id', 'label', 'baseline', 'candidate']);
    const id = token(row.id);
    if (seen.has(id) || (row.label !== 'malicious' && row.label !== 'benign' && row.label !== 'unknown') ||
        typeof row.baseline !== 'boolean' || typeof row.candidate !== 'boolean') throw new Error('Invalid or duplicate paired sample');
    seen.add(id);
    return { id, label: row.label, baseline: row.baseline, candidate: row.candidate } as ReplayRow;
  });
  return { baseline_version, candidate_version, split: 'holdout', rows };
}

export function evaluateReplay(raw: unknown) {
  const input = parseReplay(raw);
  const baseline = { tp: 0, fp: 0, tn: 0, fn: 0 };
  const candidate = { tp: 0, fp: 0, tn: 0, fn: 0 };
  let malicious = 0, benign = 0, unknown = 0, unknownChanged = 0;
  let lostMalicious = 0, gainedMalicious = 0, removedBenign = 0, addedBenign = 0;
  for (const row of input.rows) {
    if (row.label === 'unknown') { unknown++; if (row.baseline !== row.candidate) unknownChanged++; continue; }
    const positive = row.label === 'malicious';
    if (positive) malicious++; else benign++;
    baseline[positive ? row.baseline ? 'tp' : 'fn' : row.baseline ? 'fp' : 'tn']++;
    candidate[positive ? row.candidate ? 'tp' : 'fn' : row.candidate ? 'fp' : 'tn']++;
    if (positive && row.baseline && !row.candidate) lostMalicious++;
    if (positive && !row.baseline && row.candidate) gainedMalicious++;
    if (!positive && row.baseline && !row.candidate) removedBenign++;
    if (!positive && !row.baseline && row.candidate) addedBenign++;
  }
  const ratio = (numerator: number, denominator: number) => denominator ? numerator / denominator : null;
  const reasons: string[] = [];
  if (malicious < MIN_CLASS_SUPPORT || benign < MIN_CLASS_SUPPORT) reasons.push('insufficient_labelled_support');
  if (unknown > 0) reasons.push('unknown_labels_present');
  if (lostMalicious > 0) reasons.push('previously_detected_malicious_samples_lost');
  if (addedBenign > 0) reasons.push('new_benign_alerts');
  if (baseline.fp === 0 || removedBenign <= addedBenign) reasons.push('no_demonstrated_benign_alert_reduction');
  return {
    baseline_version: input.baseline_version, candidate_version: input.candidate_version,
    total: input.rows.length, malicious, benign, unknown, unknownChanged, baseline, candidate,
    lostMalicious, gainedMalicious, removedBenign, addedBenign,
    baselineRecall: ratio(baseline.tp, malicious), candidateRecall: ratio(candidate.tp, malicious),
    baselineFalsePositiveRate: ratio(baseline.fp, benign), candidateFalsePositiveRate: ratio(candidate.fp, benign),
    benignAlertReduction: ratio(baseline.fp - candidate.fp, baseline.fp),
    gate: reasons.length === 0 ? 'eligible_for_human_review' as const : 'blocked' as const,
    reasons,
  };
}
