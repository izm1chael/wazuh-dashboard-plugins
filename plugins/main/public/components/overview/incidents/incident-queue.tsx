import React, { useEffect, useState } from 'react';
import {
  EuiBasicTable, EuiBasicTableColumn, EuiButton, EuiButtonEmpty, EuiCallOut, EuiFieldText, EuiFlexGroup, EuiFlexItem,
  EuiFormRow, EuiSelect, EuiSpacer, EuiText, EuiTitle,
} from '@elastic/eui';
import type { IncidentSummary, Queue, QueueCursor, QueuePage, QueueQuery, Severity } from '../../../../common/incidents/contracts';
import type { IncidentApi } from './incident-api';

const QUEUES: Queue[] = ['open', 'mine', 'handover', 'new', 'triaging', 'active', 'unassigned', 'closed', 'all'];
const SEVERITIES: Severity[] = ['informational', 'low', 'medium', 'high', 'critical'];
const label = (value: string) => value === 'mine' ? 'My open incidents' : value === 'handover' ? 'Incoming handovers' : value.charAt(0).toUpperCase() + value.slice(1);

export function IncidentQueue({ api, open, create }: {
  api: IncidentApi;
  open: (id: string) => void;
  create: () => void;
}) {
  const [queue, setQueue] = useState<Queue>('open');
  const [severity, setSeverity] = useState<Severity | ''>('');
  const [search, setSearch] = useState('');
  const [owner, setOwner] = useState('');
  const [filter, setFilter] = useState<QueueQuery>({ queue: 'open', limit: 50 });
  const [cursors, setCursors] = useState<Array<QueueCursor | undefined>>([undefined]);
  const [page, setPage] = useState<QueuePage>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const after = cursors[cursors.length - 1];

  useEffect(() => {
    let current = true;
    setLoading(true);
    setError(false);
    setPage(undefined);
    api.list({ ...filter, after }).then(result => {
      if (current) setPage(result);
    }, () => {
      if (current) setError(true);
    }).finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [api, filter, after, refresh]);

  function apply(event: React.FormEvent) {
    event.preventDefault();
    setCursors([undefined]);
    setFilter({ queue, limit: 50, ...(severity ? { severity } : {}),
      ...(search.trim() ? { search: search.trim() } : {}),
      ...(owner.trim() ? { owner: owner.trim() } : {}) });
  }

  const columns: Array<EuiBasicTableColumn<IncidentSummary>> = [
    { field: 'title', name: 'Incident', render: (_: string, item: IncidentSummary) => (
      <EuiButtonEmpty onClick={() => open(item.id)}>{item.title}</EuiButtonEmpty>
    ) },
    { field: 'severity', name: 'Severity' },
    { field: 'status', name: 'Status' },
    { field: 'owner', name: 'Owner', render: (value: string | null) => value || 'Unassigned' },
    { name: 'Handover', render: (item: IncidentSummary) => item.handover?.target || '—' },
    { name: 'Tags', render: (item: IncidentSummary) => (item.tags ?? []).join(', ') || '—' },
    { field: 'finding_count', name: 'Findings' },
    { field: 'updated_at', name: 'Updated (UTC)' },
  ];

  return <>
    <EuiFlexGroup alignItems='center'>
      <EuiFlexItem><EuiTitle size='l'><h1>Incidents</h1></EuiTitle>
        <EuiText size='s'>Open incidents remain in the queue regardless of finding age.</EuiText>
      </EuiFlexItem>
      <EuiFlexItem grow={false}><EuiButton fill onClick={create}>Create incident</EuiButton></EuiFlexItem>
    </EuiFlexGroup>
    <EuiSpacer size='m' />
    <form onSubmit={apply}>
      <EuiFlexGroup wrap alignItems='flexEnd'>
        <EuiFlexItem><EuiFormRow label='Queue'><EuiSelect value={queue} options={QUEUES.map(value => ({ value, text: label(value) }))} onChange={e => setQueue(e.target.value as Queue)} /></EuiFormRow></EuiFlexItem>
        <EuiFlexItem><EuiFormRow label='Severity'><EuiSelect value={severity} options={[{ value: '', text: 'All severities' }, ...SEVERITIES.map(value => ({ value, text: label(value) }))]} onChange={e => setSeverity(e.target.value as Severity | '')} /></EuiFormRow></EuiFlexItem>
        <EuiFlexItem><EuiFormRow label='Owner'><EuiFieldText value={owner} maxLength={1024} onChange={e => setOwner(e.target.value)} /></EuiFormRow></EuiFlexItem>
        <EuiFlexItem><EuiFormRow label='Search incidents' helpText='Use tag:example for an exact tag match.'><EuiFieldText value={search} maxLength={1024} onChange={e => setSearch(e.target.value)} /></EuiFormRow></EuiFlexItem>
        <EuiFlexItem grow={false}><EuiButton type='submit'>Apply filters</EuiButton></EuiFlexItem>
      </EuiFlexGroup>
    </form>
    <EuiSpacer size='m' />
    {error && <EuiCallOut color='danger' title='Incident queue unavailable' iconType='alert'>Check incident read permissions and experimental indexer activation.</EuiCallOut>}
    <EuiBasicTable<IncidentSummary> items={page?.incidents ?? []} columns={columns} itemId='id' loading={loading}
      noItemsMessage={error ? 'Queue could not be loaded' : 'No incidents match this queue'} />
    <EuiSpacer size='m' />
    <EuiFlexGroup alignItems='center'>
      <EuiFlexItem><EuiText size='s'>Page {cursors.length} · Live results can change between pages</EuiText></EuiFlexItem>
      <EuiFlexItem grow={false}><EuiButtonEmpty disabled={loading} onClick={() => { setCursors([undefined]); setRefresh(value => value + 1); }}>Refresh</EuiButtonEmpty></EuiFlexItem>
      <EuiFlexItem grow={false}><EuiButtonEmpty disabled={loading || cursors.length === 1} onClick={() => setCursors(items => items.slice(0, -1))}>Previous</EuiButtonEmpty></EuiFlexItem>
      <EuiFlexItem grow={false}><EuiButtonEmpty disabled={loading || !page?.next} onClick={() => { const next = page?.next; if (next) setCursors(items => [...items, next]); }}>Next</EuiButtonEmpty></EuiFlexItem>
    </EuiFlexGroup>
  </>;
}
