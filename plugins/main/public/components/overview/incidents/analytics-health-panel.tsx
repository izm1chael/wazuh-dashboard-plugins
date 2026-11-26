import React, { useEffect, useRef, useState } from 'react';
import { EuiBasicTable, EuiBasicTableColumn, EuiButton, EuiButtonEmpty, EuiCallOut, EuiFieldText, EuiFormRow, EuiSpacer, EuiText, EuiTitle } from '@elastic/eui';
import { getHttp } from '../../../kibana-services';
import { AnalyticsStatus, AnalyticsWindowQuery, healthWindows, latestSettledWindow, validateAnalyticsStatus } from '../../../../common/incidents/analytics-contract';

type Row = { query: AnalyticsWindowQuery; status: AnalyticsStatus | null };
const request = (query: AnalyticsWindowQuery) => getHttp().post<AnalyticsStatus>('/indexer/incident-analytics/status', { body: JSON.stringify(query) });

export function AnalyticsHealthPanel({ back, read = request }: { back: () => void; read?: (query: AnalyticsWindowQuery) => Promise<AnalyticsStatus> }) {
  const [policy, setPolicy] = useState('');
  const [version, setVersion] = useState('1');
  const [minutes, setMinutes] = useState('15');
  const [until, setUntil] = useState(() => latestSettledWindow(15, Date.now()));
  const [count, setCount] = useState('5');
  const [rows, setRows] = useState<Row[]>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const generation = useRef(0);
  const active = useRef(false);
  useEffect(() => () => { generation.current++; }, []);
  function reset() { setRows(undefined); setError(''); }
  let windows: AnalyticsWindowQuery[] | undefined;
  try {
    if ([version, minutes, count].every(value => /^[1-9][0-9]*$/.test(value)))
      windows = healthWindows(policy, Number(version), Number(minutes), until, Number(count));
  } catch (_) { /* invalid form */ }
  async function inspect() {
    if (!windows || active.current) return;
    const run = ++generation.current; active.current = true; setBusy(true); reset();
    const result: Row[] = [];
    try {
      for (const query of windows) {
        if (generation.current !== run) return;
        try { result.push({ query, status: validateAnalyticsStatus(await read(query), query) }); }
        catch (_) { result.push({ query, status: null }); }
      }
      if (generation.current === run) setRows(result);
    } finally {
      active.current = false;
      if (generation.current === run) setBusy(false);
    }
  }
  const columns: Array<EuiBasicTableColumn<Row>> = [
    { name: 'Window start (UTC)', render: row => row.query.from },
    { name: 'Window end (UTC)', render: row => row.query.until },
    { name: 'Receipt status', render: row => row.status?.state ?? 'unavailable' },
    { name: 'Findings', render: row => row.status && row.status.state !== 'not_recorded' ? row.status.finding_count : '—' },
    { name: 'Groups', render: row => row.status && row.status.state !== 'not_recorded' ? row.status.group_count : '—' },
    { name: 'Below threshold', render: row => row.status && row.status.state !== 'not_recorded' ? row.status.below_threshold : '—' },
    { name: 'Completed (UTC)', render: row => row.status && row.status.state !== 'not_recorded' ? row.status.completed_at ?? '—' : '—' },
  ];
  return <>
    <EuiButtonEmpty onClick={back} disabled={busy}>Back to incidents</EuiButtonEmpty>
    <EuiTitle size='l'><h1>Analytics execution health</h1></EuiTitle>
    <EuiCallOut title='Read-only execution receipt inspection'>
      Native finding correlation runs are activated separately by an operator and executed by the approved service account.
      Inspect up to ten aligned windows for an exact saved policy version. Missing receipts do not establish that the policy was scheduled; reserved means completion was not verified, not necessarily that execution failed.
    </EuiCallOut>
    <EuiSpacer size='m' />
    <EuiFormRow label='Policy UUID'><EuiFieldText value={policy} maxLength={36} disabled={busy} onChange={e => { reset(); setPolicy(e.target.value); }} /></EuiFormRow>
    <EuiFormRow label='Policy version'><EuiFieldText value={version} maxLength={10} disabled={busy} onChange={e => { reset(); setVersion(e.target.value); }} /></EuiFormRow>
    <EuiFormRow label='Saved policy window (minutes)'><EuiFieldText value={minutes} maxLength={4} disabled={busy} onChange={e => { reset(); setMinutes(e.target.value); }} /></EuiFormRow>
    <EuiFormRow label='Last window end (UTC)' helpText='Aligned UTC timestamp with seconds, no fractions.'><EuiFieldText value={until} maxLength={20} disabled={busy} onChange={e => { reset(); setUntil(e.target.value); }} /></EuiFormRow>
    <EuiButtonEmpty disabled={busy} onClick={() => {
      reset(); try { setUntil(latestSettledWindow(Number(minutes), Date.now())); } catch (_) { setError('Invalid window duration.'); }
    }}>Use latest settled boundary</EuiButtonEmpty>
    <EuiFormRow label='Number of windows (1–10)'><EuiFieldText value={count} maxLength={2} disabled={busy} onChange={e => { reset(); setCount(e.target.value); }} /></EuiFormRow>
    <EuiButton disabled={busy || !windows} isLoading={busy} onClick={() => void inspect()}>Inspect window receipts</EuiButton>
    {error && <EuiCallOut color='warning' title={error} />}
    {rows && <>
      <EuiSpacer size='m' />
      <EuiText size='s'>{rows.length} requested windows · {rows.filter(row => row.status?.state === 'completed').length} completed ·
        {' '}{rows.filter(row => row.status?.state === 'reserved').length} reserved · {rows.filter(row => row.status?.state === 'not_recorded').length} not recorded ·
        {' '}{rows.filter(row => row.status === null).length} unavailable.</EuiText>
      <EuiBasicTable<Row> items={rows} columns={columns} noItemsMessage='No receipt requests' />
      <EuiText size='s'>Completed group counts represent verified incident creation audit receipts, including replayed groups, not necessarily newly created incidents. A completed zero-match window is not proof of ingestion completeness. No source findings are returned.</EuiText>
    </>}
  </>;
}
