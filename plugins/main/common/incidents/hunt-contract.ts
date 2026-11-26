/** Fixed historical finding hunt, not arbitrary DSL or a raw event search. */
export const HUNT_FIELDS = ['wazuh.agent.id', 'wazuh.agent.name', 'host.id', 'host.name', 'host.hostname',
  'host.ip', 'source.ip', 'destination.ip', 'user.name', 'user.id', 'user.domain', 'dns.question.name',
  'file.hash.md5', 'file.hash.sha1', 'file.hash.sha256'] as const;
export type HuntField = typeof HUNT_FIELDS[number];
export interface HuntInput { field: HuntField; values: string[]; from: string; until: string }
export interface HuntRow { index: string; document_id: string; timestamp: string; matched_values: string[] }
export interface HuntReport extends HuntInput {
  scope: 'caller_visible_findings_exact_terms'; rows: HuntRow[]; match_count: number;
}
const DAY = 86400000;
const validTime = (s: unknown): s is string => typeof s === 'string' &&
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(s) && Number.isFinite(Date.parse(s));
const safe = (v: unknown, max: number): v is string =>
  typeof v === 'string' && v.length <= max && !!v.trim() && !/[\x00-\x1f\x7f-\x9f]/.test(v);
const exact = (v: object, keys: string[]) => Object.keys(v).length === keys.length &&
  keys.every(k => Object.prototype.hasOwnProperty.call(v, k));
const fail = (): never => { throw new Error('Invalid bounded hunt'); };
export function validHuntValue(field: HuntField, value: unknown): value is string {
  if (!safe(value, 256) || value !== value.trim()) return false;
  if (field === 'file.hash.md5') return /^[a-fA-F0-9]{32}$/.test(value);
  if (field === 'file.hash.sha1') return /^[a-fA-F0-9]{40}$/.test(value);
  if (field === 'file.hash.sha256') return /^[a-fA-F0-9]{64}$/.test(value);
  if (field.endsWith('.ip')) {
    const parts = value.split('.');
    return parts.length === 4 && parts.every(p => /^(0|[1-9][0-9]{0,2})$/.test(p) && Number(p) <= 255);
  }
  return true;
}
export function validateHunt(input: HuntInput): HuntInput {
  if (!input || !HUNT_FIELDS.includes(input.field) || !Array.isArray(input.values) ||
      input.values.length < 1 || input.values.length > 20 ||
      !input.values.every(v => validHuntValue(input.field, v)) || new Set(input.values).size !== input.values.length ||
      !validTime(input.from) || !validTime(input.until)) return fail();
  const start = Date.parse(input.from), end = Date.parse(input.until);
  if (start >= end || end - start > 7 * DAY || start < Date.UTC(2000, 0, 1) || end > Date.UTC(2100, 0, 1)) return fail();
  // Send normalized millisecond UTC timestamps; no sub-millisecond browser ambiguity.
  return { field: input.field, values: [...input.values].sort(), from: new Date(start).toISOString(), until: new Date(end).toISOString() };
}
export function validateHuntReport(report: HuntReport, expected: HuntInput): HuntReport {
  if (!report || !exact(report, ['scope', 'field', 'values', 'from', 'until', 'rows', 'match_count']) ||
      report.scope !== 'caller_visible_findings_exact_terms' || report.field !== expected.field ||
      !Array.isArray(report.values) || JSON.stringify(report.values) !== JSON.stringify(expected.values) ||
      !validTime(report.from) || !validTime(report.until) ||
      Date.parse(report.from) !== Date.parse(expected.from) || Date.parse(report.until) !== Date.parse(expected.until) ||
      !Array.isArray(report.rows) || report.rows.length > 100 || report.match_count !== report.rows.length) return fail();
  const seen = new Set<string>();
  for (const row of report.rows) {
    if (!row || !exact(row, ['index', 'document_id', 'timestamp', 'matched_values']) ||
        !safe(row.index, 255) || !/^(?:\.ds-)?wazuh-findings-v5-[a-z0-9][a-z0-9-]*-[0-9]{6}$/.test(row.index) ||
        !safe(row.document_id, 512) || !validTime(row.timestamp) ||
        Date.parse(row.timestamp) < Date.parse(expected.from) || Date.parse(row.timestamp) >= Date.parse(expected.until) ||
        !Array.isArray(row.matched_values) || !row.matched_values.length ||
        new Set(row.matched_values).size !== row.matched_values.length ||
        !row.matched_values.every(v => expected.values.includes(v))) return fail();
    const key = JSON.stringify([row.index, row.document_id]);
    if (seen.has(key)) return fail();
    seen.add(key);
  }
  return report;
}
