// SPDX-License-Identifier: AGPL-3.0-or-later
export type Outcome = 'MATCH' | 'NO_MATCH' | 'UNKNOWN';
export type Label = 'BENIGN' | 'MALICIOUS' | 'UNLABELLED';
export interface ReplayCase { id: string; label: Label; champion: Outcome; challenger: Outcome; protected: boolean }
export interface Cohort {
  format: 'wade-tuning-cohort-v1'; champion_digest: string; challenger_digest: string;
  min_benign: number; min_malicious: number; cases: ReplayCase[];
}
export interface Review {
  status: 'WITHHELD' | 'REVIEW_CANDIDATE'; reasons: string[];
  benign: number; malicious: number; unlabelled: number; unknown: number;
  false_positives_before: number; false_positives_after: number;
  malicious_regressions: string[]; protected_failures: string[];
  requires_human_approval: true;
}
const exact = (value: unknown, keys: string[]): Record<string, unknown> => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Expected object');
  const obj = value as Record<string, unknown>;
  if (Object.keys(obj).length !== keys.length || keys.some(k => !Object.prototype.hasOwnProperty.call(obj, k))) throw new Error('Unexpected or missing fields');
  return obj;
};
const digest = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const minimum = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 1 && value <= 100000;
const outcome = (value: unknown): value is Outcome => value === 'MATCH' || value === 'NO_MATCH' || value === 'UNKNOWN';
const label = (value: unknown): value is Label => value === 'BENIGN' || value === 'MALICIOUS' || value === 'UNLABELLED';
export function parseCohort(text: string): Cohort {
  if (new TextEncoder().encode(text).length > 8 * 1024 * 1024) throw new Error('Import exceeds 8 MiB');
  const obj = exact(JSON.parse(text), ['format','champion_digest','challenger_digest','min_benign','min_malicious','cases']);
  if (obj.format !== 'wade-tuning-cohort-v1' || !digest(obj.champion_digest) || !digest(obj.challenger_digest) || obj.champion_digest === obj.challenger_digest || !minimum(obj.min_benign) || !minimum(obj.min_malicious) || !Array.isArray(obj.cases) || obj.cases.length > 100000) throw new Error('Invalid cohort header');
  const seen = new Set<string>();
  const cases: ReplayCase[] = obj.cases.map(raw => {
    const c = exact(raw, ['id','label','champion','challenger','protected']);
    if (typeof c.id !== 'string' || !c.id.trim() || c.id.length > 1024 || seen.has(c.id) || !label(c.label) || !outcome(c.champion) || !outcome(c.challenger) || typeof c.protected !== 'boolean') throw new Error('Invalid or duplicate paired case');
    seen.add(c.id);
    return {id:c.id,label:c.label,champion:c.champion,challenger:c.challenger,protected:c.protected};
  });
  return {format:obj.format,champion_digest:obj.champion_digest,challenger_digest:obj.challenger_digest,min_benign:obj.min_benign,min_malicious:obj.min_malicious,cases};
}
/** Imported cohort is untrusted; this is a review calculation, never an authorization decision. */
export function reviewCohort(cohort: Cohort): Review {
  const rows = [...cohort.cases].sort((a,b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  const benign = rows.filter(c => c.label === 'BENIGN');
  const malicious = rows.filter(c => c.label === 'MALICIOUS');
  const unknown = [...benign,...malicious].filter(c => c.champion === 'UNKNOWN' || c.challenger === 'UNKNOWN');
  const regressions = malicious.filter(c => c.champion === 'MATCH' && c.challenger !== 'MATCH').map(c => c.id);
  const protectedFailures = rows.filter(c => c.protected && (c.label !== 'MALICIOUS' || c.challenger !== 'MATCH')).map(c => c.id);
  const before = benign.filter(c => c.champion === 'MATCH').length;
  const after = benign.filter(c => c.challenger === 'MATCH').length;
  const reasons: string[] = [];
  if (benign.length < cohort.min_benign || malicious.length < cohort.min_malicious) reasons.push('INSUFFICIENT_LABELLED_COHORT');
  if (unknown.length) reasons.push('INCOMPLETE_PAIRED_EVALUATION');
  if (regressions.length) reasons.push('MALICIOUS_REGRESSION');
  if (protectedFailures.length) reasons.push('PROTECTED_CASE_FAILURE');
  if (after >= before) reasons.push('NO_FALSE_POSITIVE_REDUCTION');
  return {status:reasons.length?'WITHHELD':'REVIEW_CANDIDATE',reasons,benign:benign.length,malicious:malicious.length,unlabelled:rows.length-benign.length-malicious.length,unknown:unknown.length,false_positives_before:before,false_positives_after:after,malicious_regressions:regressions,protected_failures:protectedFailures,requires_human_approval:true};
}
