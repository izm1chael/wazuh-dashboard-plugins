import type { DurationMetric, IncidentMetricsQuery, IncidentMetricsReport } from './contracts';

const count = (value: number) => Number.isSafeInteger(value) && value >= 0 && value <= 5000;
const seconds = (value: number | null) => value === null || (typeof value === 'number' && Number.isFinite(value) && value >= 0);
function requireValid(condition: boolean): void { if (!condition) throw new Error('Invalid or inconsistent incident metrics report'); }
export function validateMetricsQuery(input: IncidentMetricsQuery): void {
  const from = Date.parse(input.from), until = Date.parse(input.until);
  const utc = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
  if (!utc.test(input.from) || !utc.test(input.until) || !Number.isFinite(from) || !Number.isFinite(until) ||
      from < Date.UTC(2000, 0, 1) || until > Date.UTC(2100, 0, 1) ||
      until <= from || until - from > 31 * 86400000 ||
      !Number.isSafeInteger(input.triage_target_seconds) || input.triage_target_seconds < 1 || input.triage_target_seconds > 86400 ||
      !Number.isSafeInteger(input.resolution_target_seconds) || input.resolution_target_seconds < 1 || input.resolution_target_seconds > 604800) {
    throw new Error('Enter UTC timestamps covering 31 days or less and valid whole-second SLA targets.');
  }
}

function sumCounts(value: Record<string, number>, keys: string[]): number {
  requireValid(!!value && Object.keys(value).length === keys.length && keys.every(key => count(value[key])));
  return keys.reduce((sum, key) => sum + value[key], 0);
}
function metric(value: DurationMetric, total: number, target?: number): void {
  requireValid(!!value && [value.samples, value.missing, value.invalid].every(count) &&
    value.samples + value.missing + value.invalid === total);
  const stats = [value.mean_seconds, value.p50_seconds, value.p95_seconds];
  requireValid(stats.every(seconds) && (value.samples ? stats.every(v => v !== null) : stats.every(v => v === null)));
  if (target !== undefined) requireValid(value.target_seconds === target && count(value.met!) && count(value.breached!) &&
    value.met! + value.breached! === value.samples);
}

export function validateMetricsReport(body: IncidentMetricsReport, input: IncidentMetricsQuery): void {
  requireValid(!!body && body.scope === 'current_state_creation_cohort_and_open_backlog' && body.mtti_available === false &&
    Date.parse(body.from) === Date.parse(input.from) && Date.parse(body.until) === Date.parse(input.until) &&
    Number.isFinite(Date.parse(body.observed_at)) && Date.parse(body.observed_at) >= Date.parse(input.until));
  const numeric = [body.scanned, body.cohort_count, body.reopened_incidents, body.cohort_pending_audit,
    body.invalid_created_records, body.unknown_classification, body.open_backlog, body.unassigned,
    body.unknown_severity, body.open_resolution_breached, body.open_resolution_unknown,
    body.open_triage_breached, body.open_triage_unknown];
  requireValid(numeric.every(count) && body.cohort_count <= body.scanned && body.open_backlog <= body.scanned &&
    body.reopened_incidents <= body.cohort_count && body.cohort_pending_audit <= body.cohort_count &&
    body.invalid_created_records <= body.scanned && body.open_resolution_breached + body.open_resolution_unknown <= body.open_backlog &&
    body.open_triage_breached + body.open_triage_unknown <= body.open_backlog);
  requireValid(sumCounts(body.cohort_statuses, ['new', 'triaging', 'active', 'closed']) === body.cohort_count);
  requireValid(body.open_backlog + body.cohort_statuses.closed === body.scanned);
  requireValid(sumCounts(body.classifications, ['true_positive', 'benign_positive', 'false_positive', 'undetermined', 'duplicate']) +
    body.unknown_classification === body.cohort_statuses.closed);
  requireValid(sumCounts(body.backlog_severities, ['informational', 'low', 'medium', 'high', 'critical']) +
    body.unknown_severity === body.open_backlog);
  requireValid(sumCounts(body.backlog_age_buckets, ['lt_1h', '1h_to_24h', '1d_to_7d', 'gte_7d', 'unknown']) === body.open_backlog);
  requireValid(Array.isArray(body.owner_workload) && body.owner_workload.length <= body.open_backlog &&
    body.owner_workload.every(row => typeof row.owner === 'string' && row.owner.length > 0 && count(row.open) && row.open > 0) &&
    new Set(body.owner_workload.map(row => row.owner)).size === body.owner_workload.length &&
    body.owner_workload.reduce((sum, row) => sum + row.open, 0) + body.unassigned === body.open_backlog);
  metric(body.creation_to_first_assignment, body.cohort_count);
  metric(body.mttt, body.cohort_count, input.triage_target_seconds);
  metric(body.mttr, body.cohort_statuses.closed, input.resolution_target_seconds);
  metric(body.creation_to_first_close, body.cohort_count);
}
