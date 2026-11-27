import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import type { IncidentMetricsReport } from '../../../../common/incidents/contracts';
import { IncidentMetricsPanel } from './incident-metrics-panel';

const missing = { samples: 0, missing: 1, invalid: 0, mean_seconds: null, p50_seconds: null, p95_seconds: null };
const report: IncidentMetricsReport = {
  scope: 'current_state_creation_cohort_and_open_backlog', from: '2026-11-26T12:00:00Z',
  until: '2026-11-26T13:00:00Z', observed_at: '2026-11-26T13:00:01Z',
  scanned: 2, cohort_count: 1, cohort_statuses: { new: 0, triaging: 0, active: 0, closed: 1 },
  reopened_incidents: 0, cohort_pending_audit: 0, invalid_created_records: 0,
  classifications: { true_positive: 0, benign_positive: 0, false_positive: 1, undetermined: 0, duplicate: 0 },
  unknown_classification: 0, open_backlog: 1, unassigned: 1,
  backlog_severities: { informational: 0, low: 0, medium: 0, high: 1, critical: 0 }, unknown_severity: 0,
  backlog_age_buckets: { lt_1h: 0, '1h_to_24h': 1, '1d_to_7d': 0, gte_7d: 0, unknown: 0 },
  owner_workload: [], open_resolution_breached: 1, open_resolution_unknown: 0, open_triage_breached: 0, open_triage_unknown: 1,
  creation_to_first_assignment: missing, mttt: { ...missing, target_seconds: 600, met: 0, breached: 0 },
  mttr: { samples: 1, missing: 0, invalid: 0, mean_seconds: 1200, p50_seconds: 1200, p95_seconds: 1200, target_seconds: 1200, met: 0, breached: 1 },
  creation_to_first_close: { samples: 1, missing: 0, invalid: 0, mean_seconds: 1200, p50_seconds: 1200, p95_seconds: 1200 },
  mtti_available: false,
};

describe('SOC reporting panel', () => {
  test('requests the chosen creation cohort and displays explicit denominators and missing samples', async () => {
    const request = jest.fn().mockResolvedValue(report);
    render(<IncidentMetricsPanel back={jest.fn()} report={request} />);
    fireEvent.change(screen.getByLabelText('From (UTC)'), { target: { value: report.from } });
    fireEvent.change(screen.getByLabelText('Until (UTC, exclusive)'), { target: { value: report.until } });
    fireEvent.click(screen.getByRole('button', { name: 'Run SOC report' }));
    await screen.findByText('Creation cohort (1 incidents)');
    expect(request).toHaveBeenCalledWith({ from: report.from, until: report.until, triage_target_seconds: 600, resolution_target_seconds: 1200 });
    expect(screen.getByText('Current open backlog (1 incidents)')).toBeInTheDocument();
    expect(screen.getByText(/False-positive share: 100.0%/)).toBeInTheDocument();
    expect(screen.getByText(/MTTI unavailable/)).toBeInTheDocument();
    expect(screen.getAllByText('Not available').length).toBeGreaterThan(0);
    expect(screen.getByText(/0 met · 1 breached/)).toBeInTheDocument();
  });
  test('does not show stale results after a failed refresh', async () => {
    const request = jest.fn().mockResolvedValueOnce(report).mockRejectedValueOnce(new Error('incomplete'));
    render(<IncidentMetricsPanel back={jest.fn()} report={request} />);
    fireEvent.click(screen.getByRole('button', { name: 'Run SOC report' }));
    await screen.findByText('Creation cohort (1 incidents)');
    fireEvent.click(screen.getByRole('button', { name: 'Run SOC report' }));
    await waitFor(() => expect(screen.getByText(/Report unavailable/)).toBeInTheDocument());
    expect(screen.queryByText('Creation cohort (1 incidents)')).not.toBeInTheDocument();
  });
});
