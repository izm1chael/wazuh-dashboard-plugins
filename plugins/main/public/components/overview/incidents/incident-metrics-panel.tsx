import React, { useRef, useState } from 'react';
import { EuiBasicTable, EuiButton, EuiButtonEmpty, EuiCallOut, EuiFieldText, EuiFlexGroup, EuiFlexItem,
  EuiFormRow, EuiPanel, EuiSpacer, EuiText, EuiTitle } from '@elastic/eui';
import { getHttp } from '../../../kibana-services';
import type { DurationMetric, IncidentMetricsQuery, IncidentMetricsReport } from '../../../../common/incidents/contracts';
import { validateMetricsQuery } from '../../../../common/incidents/metrics-validation';

const request = (query: IncidentMetricsQuery) => getHttp().post<IncidentMetricsReport>('/indexer/incident-metrics/report', { body: JSON.stringify(query) });
const display = (seconds: number | null) => seconds === null ? 'Not available' : (seconds / 60).toFixed(2) + ' min';
const label = (value: string) => value.replace(/_/g, ' ');

function Metric({ title, value }: { title: string; value: DurationMetric }) {
  return <EuiPanel hasShadow={false} hasBorder paddingSize='m'>
    <EuiTitle size='xs'><h3>{title}</h3></EuiTitle>
    <EuiTitle size='l'><h4>{display(value.mean_seconds)}</h4></EuiTitle>
    <EuiText size='s'><p>P50: {display(value.p50_seconds)} · P95: {display(value.p95_seconds)}</p>
      <p>{value.samples} measured · {value.missing} missing · {value.invalid} invalid</p>
      {value.target_seconds !== undefined && <p>Target: less than {display(value.target_seconds)} · {value.met} met · {value.breached} breached
        {value.samples > 0 ? ' · ' + ((value.met ?? 0) / value.samples * 100).toFixed(1) + '% met' : ''}</p>}
    </EuiText>
  </EuiPanel>;
}

function Counts({ title, values }: { title: string; values: Record<string, number> }) {
  return <EuiPanel paddingSize='m' hasShadow={false} hasBorder>
    <EuiTitle size='xs'><h3>{title}</h3></EuiTitle>
    <EuiText size='s'><dl>{Object.entries(values).map(([key, value]) =>
      <React.Fragment key={key}><dt>{label(key)}</dt><dd>{value}</dd></React.Fragment>)}</dl></EuiText>
  </EuiPanel>;
}

export function IncidentMetricsPanel({ back, report = request }: {
  back: () => void; report?: (query: IncidentMetricsQuery) => Promise<IncidentMetricsReport>;
}) {
  const [from, setFrom] = useState(() => new Date(Date.now() - 7 * 86400000).toISOString());
  const [until, setUntil] = useState(() => new Date().toISOString());
  const [triage, setTriage] = useState('600');
  const [resolution, setResolution] = useState('1200');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<IncidentMetricsReport>();
  const inFlight = useRef(false);

  async function run(event: React.FormEvent) {
    event.preventDefault();
    if (inFlight.current) return;
    setError(''); setResult(undefined);
    const input = { from: from.trim(), until: until.trim(), triage_target_seconds: Number(triage), resolution_target_seconds: Number(resolution) };
    try { validateMetricsQuery(input); }
    catch (e) { setError(e instanceof Error ? e.message : 'Invalid report input'); return; }
    inFlight.current = true; setBusy(true);
    try { setResult(await report(input)); }
    catch (_) { setError('Report unavailable. Check metrics permission, period and the 5,000-record cohort/backlog limit.'); }
    finally { setBusy(false); inFlight.current = false; }
  }

  return <>
    <EuiButtonEmpty onClick={back} disabled={busy}>Back to incidents</EuiButtonEmpty>
    <EuiTitle size='l'><h1>SOC operational reporting</h1></EuiTitle>
    <EuiSpacer size='s' />
    <EuiCallOut title='Current-state metrics'>Lifecycle durations use incidents created in the selected period. Open backlog includes all currently open incidents, regardless of creation date. This is not historical as-of reporting.</EuiCallOut>
    <EuiSpacer size='m' />
    {error && <EuiCallOut color='danger' title={error} />}
    <form onSubmit={run}>
      <EuiFlexGroup wrap>
        <EuiFlexItem><EuiFormRow label='From (UTC)'><EuiFieldText value={from} disabled={busy} onChange={e => setFrom(e.target.value)} /></EuiFormRow></EuiFlexItem>
        <EuiFlexItem><EuiFormRow label='Until (UTC, exclusive)'><EuiFieldText value={until} disabled={busy} onChange={e => setUntil(e.target.value)} /></EuiFormRow></EuiFlexItem>
        <EuiFlexItem><EuiFormRow label='Triage SLA (seconds)'><EuiFieldText value={triage} disabled={busy} onChange={e => setTriage(e.target.value)} /></EuiFormRow></EuiFlexItem>
        <EuiFlexItem><EuiFormRow label='Resolution SLA (seconds)'><EuiFieldText value={resolution} disabled={busy} onChange={e => setResolution(e.target.value)} /></EuiFormRow></EuiFlexItem>
      </EuiFlexGroup>
      <EuiButton type='submit' fill isLoading={busy} disabled={busy}>Run SOC report</EuiButton>
    </form>
    {result && <>
      <EuiSpacer size='l' />
      <EuiText size='s'><p>Observed {result.observed_at} · {result.from} to {result.until} · {result.scanned} records scanned.</p></EuiText>
      <EuiTitle size='s'><h2>Creation cohort ({result.cohort_count} incidents)</h2></EuiTitle>
      <EuiSpacer size='s' />
      <EuiFlexGroup wrap>
        <EuiFlexItem><Metric title='MTTT · Triage to active' value={result.mttt} /></EuiFlexItem>
        <EuiFlexItem><Metric title='MTTR · Creation to current closure' value={result.mttr} /></EuiFlexItem>
        <EuiFlexItem><Metric title='Creation to first assignment (not MTTI)' value={result.creation_to_first_assignment} /></EuiFlexItem>
        <EuiFlexItem><Metric title='Creation to first closure' value={result.creation_to_first_close} /></EuiFlexItem>
      </EuiFlexGroup>
      <EuiText size='s'><p>MTTI unavailable: trusted originating detection and identification timestamps are not captured.</p>
        <p>Reopened incidents: {result.reopened_incidents}. Cohort pending audit: {result.cohort_pending_audit}. Invalid creation timestamps among scanned records: {result.invalid_created_records}.</p></EuiText>
      <EuiFlexGroup wrap>
        <EuiFlexItem><Counts title='Current cohort status' values={result.cohort_statuses} /></EuiFlexItem>
        <EuiFlexItem><Counts title='Current closed cohort classification' values={{ ...result.classifications, unknown: result.unknown_classification }} /></EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer size='l' />
      <EuiTitle size='s'><h2>Current open backlog ({result.open_backlog} incidents)</h2></EuiTitle>
      <EuiText size='s'><p>Unassigned: {result.unassigned} · Open resolution breaches: {result.open_resolution_breached} · Unknown resolution age: {result.open_resolution_unknown}</p>
        <p>Open triage breaches: {result.open_triage_breached} · Triage start or activation unavailable: {result.open_triage_unknown}</p></EuiText>
      <EuiFlexGroup wrap>
        <EuiFlexItem><Counts title='Open severity' values={{ ...result.backlog_severities, unknown: result.unknown_severity }} /></EuiFlexItem>
        <EuiFlexItem><Counts title='Backlog age' values={result.backlog_age_buckets} /></EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer size='m' />
      <EuiTitle size='xs'><h3>Current analyst workloads</h3></EuiTitle>
      <EuiBasicTable items={[...result.owner_workload].sort((a, b) => b.open - a.open || a.owner.localeCompare(b.owner))}
        columns={[{ field: 'owner', name: 'Owner' }, { field: 'open', name: 'Open incidents' }]} noItemsMessage='No assigned open incidents' />
    </>}
  </>;
}
