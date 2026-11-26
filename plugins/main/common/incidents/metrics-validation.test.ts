import { validateMetricsQuery, validateMetricsReport } from './metrics-validation';
import type { IncidentMetricsReport } from './contracts';
const query = { from: '2026-11-26T12:00:00Z', until: '2026-11-26T13:00:00Z', triage_target_seconds: 600, resolution_target_seconds: 1200 };
const empty = { samples: 0, missing: 0, invalid: 0, mean_seconds: null, p50_seconds: null, p95_seconds: null };
const report: IncidentMetricsReport = { ...query, observed_at: query.until, scope: 'current_state_creation_cohort_and_open_backlog',
  scanned: 0, cohort_count: 0, cohort_statuses: { new: 0, triaging: 0, active: 0, closed: 0 }, reopened_incidents: 0,
  cohort_pending_audit: 0, invalid_created_records: 0, classifications: { true_positive: 0, benign_positive: 0, false_positive: 0, undetermined: 0, duplicate: 0 },
  unknown_classification: 0, open_backlog: 0, unassigned: 0, backlog_severities: { informational: 0, low: 0, medium: 0, high: 0, critical: 0 },
  unknown_severity: 0, backlog_age_buckets: { lt_1h: 0, '1h_to_24h': 0, '1d_to_7d': 0, gte_7d: 0, unknown: 0 }, owner_workload: [],
  open_resolution_breached: 0, open_resolution_unknown: 0, open_triage_breached: 0, open_triage_unknown: 0,
  creation_to_first_assignment: empty, mttt: { ...empty, target_seconds: 600, met: 0, breached: 0 },
  mttr: { ...empty, target_seconds: 1200, met: 0, breached: 0 }, creation_to_first_close: empty, mtti_available: false };
describe('SOC report validation', () => {
  test('accepts an empty report without inventing durations', () => {
    expect(() => validateMetricsQuery(query)).not.toThrow();
    expect(() => validateMetricsReport(report, query)).not.toThrow();
  });
  test('rejects inconsistent cohort and workload counts', () => {
    expect(() => validateMetricsReport({ ...report, cohort_count: 1 }, query)).toThrow();
    expect(() => validateMetricsReport({ ...report, unassigned: 1 }, query)).toThrow();
  });
  test('rejects zero substituted for missing durations and mismatched SLA targets', () => {
    expect(() => validateMetricsReport({ ...report, mttt: { ...report.mttt, mean_seconds: 0 } }, query)).toThrow();
    expect(() => validateMetricsReport({ ...report, mttr: { ...report.mttr, target_seconds: 1 } }, query)).toThrow();
  });
});
