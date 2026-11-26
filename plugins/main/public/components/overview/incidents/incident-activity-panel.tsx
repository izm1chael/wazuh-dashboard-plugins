import React, { useEffect, useState } from 'react';
import { EuiBasicTable, EuiBasicTableColumn, EuiButtonEmpty, EuiCallOut, EuiFlexGroup, EuiFlexItem, EuiSpacer, EuiText, EuiTitle } from '@elastic/eui';
import type { ActivityPage, IncidentActivity } from '../../../../common/incidents/contracts';
import type { IncidentApi } from './incident-api';

const LABELS: Record<string, string> = {
  created: 'Incident created', assign: 'Assignment changed', start_triage: 'Triage started',
  activate: 'Investigation started', close: 'Incident closed', reopen: 'Incident reopened',
  response_requested: 'Response requested', response_approved: 'Response approved', response_rejected: 'Response rejected',
  response_cancelled: 'Response cancelled', response_outcome_reported: 'Manual response outcome reported',
  playbook_applied: 'Investigation playbook applied',
  note_added: 'Note added', task_created: 'Task created', task_completed: 'Task completed', task_reopened: 'Task reopened',
  edit: 'Metadata changed', attach_finding: 'Finding attached', detach_finding: 'Finding detached',
};
const display = (value: string | number | boolean | null) => value === null ? '—' : String(value);

export function IncidentActivityPanel({ api, id }: { api: IncidentApi; id: string }) {
  const [page, setPage] = useState<ActivityPage>();
  const [cursors, setCursors] = useState([0]);
  const [reload, setReload] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const before = cursors[cursors.length - 1];
  useEffect(() => {
    let current = true;
    setPage(undefined); setError(false); setLoading(true);
    api.activity(id, before).then(result => { if (current) setPage(result); },
      () => { if (current) setError(true); }).finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [api, id, before, reload]);

  const columns: Array<EuiBasicTableColumn<IncidentActivity>> = [
    { field: 'at', name: 'Time (UTC)' },
    { field: 'revision', name: 'Revision' },
    { field: 'kind', name: 'Activity', render: (kind: string) => LABELS[kind] || kind },
    { field: 'actor', name: 'Analyst' },
    { name: 'Changes', render: (event: IncidentActivity) => <EuiText size='s'>
      {Object.entries(event.changes).map(([field, change]) => <div key={field}>{field.replace(/_/g, ' ')}: {display(change.before)} → {display(change.after)}</div>)}
    </EuiText> },
  ];
  return <>
    <EuiTitle size='s'><h2>Activity history</h2></EuiTitle>
    <EuiSpacer size='s' />
    {error && <EuiCallOut color='danger' title='Activity history unavailable' />}
    {page?.activity_pending && <EuiCallOut color='warning' title='Audit delivery pending'>The latest incident update may not yet appear in this history.</EuiCallOut>}
    <EuiBasicTable<IncidentActivity> items={page?.events ?? []} columns={columns} itemId='id' loading={loading} noItemsMessage='No delivered activity on this page' />
    <EuiFlexGroup alignItems='center'>
      <EuiFlexItem><EuiText size='s'>Page {cursors.length} · Finding identifiers and sensitive change fields are omitted.</EuiText></EuiFlexItem>
      <EuiFlexItem grow={false}><EuiButtonEmpty disabled={loading} onClick={() => { setCursors([0]); setReload(value => value + 1); }}>Refresh activity</EuiButtonEmpty></EuiFlexItem>
      <EuiFlexItem grow={false}><EuiButtonEmpty disabled={loading || cursors.length === 1} onClick={() => setCursors(items => items.slice(0, -1))}>Previous activity</EuiButtonEmpty></EuiFlexItem>
      <EuiFlexItem grow={false}><EuiButtonEmpty disabled={loading || !page?.next_before} onClick={() => { const next = page?.next_before; if (next) setCursors(items => [...items, next]); }}>Older activity</EuiButtonEmpty></EuiFlexItem>
    </EuiFlexGroup>
  </>;
}
