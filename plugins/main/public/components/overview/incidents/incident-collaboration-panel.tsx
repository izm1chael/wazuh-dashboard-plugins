import React, { useEffect, useState } from 'react';
import { EuiBasicTable, EuiBasicTableColumn, EuiButton, EuiButtonEmpty, EuiCallOut, EuiFieldText, EuiFormRow, EuiPanel, EuiSpacer, EuiText, EuiTextArea, EuiTitle } from '@elastic/eui';
import type { CollaborationPage, IncidentSummary, IncidentTask, IndexerIncidentCommand } from '../../../../common/incidents/contracts';
import type { IncidentApi } from './incident-api';

export function IncidentCollaborationPanel({ api, incident, disabled, command }: {
  api: IncidentApi; incident: IncidentSummary; disabled: boolean;
  command: (value: IndexerIncidentCommand) => Promise<void>;
}) {
  const [page, setPage] = useState<CollaborationPage>();
  const [before, setBefore] = useState(0);
  const [reload, setReload] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [body, setBody] = useState('');
  const [title, setTitle] = useState('');
  useEffect(() => {
    let current = true;
    setPage(undefined); setError(false); setLoading(true);
    api.collaboration(incident.id, before).then(result => { if (current) setPage(result); },
      () => { if (current) setError(true); }).finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [api, incident.id, before, reload]);

  const stale = !!page && page.observed_revision !== incident.revision;
  const blocked = disabled || loading || error || stale;
  const tasksBlocked = blocked || !incident.owner;
  const tasks = page?.tasks ?? [];
  const completed = tasks.filter(task => task.status === 'completed').length;
  const columns: Array<EuiBasicTableColumn<IncidentTask>> = [
    { field: 'title', name: 'Task' }, { field: 'status', name: 'Status' },
    { field: 'created_by', name: 'Created by' }, { field: 'completed_by', name: 'Completed by' },
    { name: 'Action', render: (task: IncidentTask) => <EuiButtonEmpty disabled={tasksBlocked} onClick={() =>
      command({ kind: task.status === 'open' ? 'complete-task' : 'reopen-task', task_id: task.id })}>
      {task.status === 'open' ? 'Complete task' : 'Reopen task'}
    </EuiButtonEmpty> },
  ];
  return <>
    <EuiTitle size='s'><h2>Investigation tasks</h2></EuiTitle>
    <EuiSpacer size='s' />
    {error && <EuiCallOut color='danger' title='Collaboration unavailable' />}
    {stale && <EuiCallOut color='warning' title='Incident changed'>Reload the incident before making changes.</EuiCallOut>}
    {page?.activity_pending && <EuiCallOut color='warning' title='Note or activity delivery pending' />}
    {page && <EuiText size='s'>{completed} of {tasks.length} tasks complete</EuiText>}
    <EuiBasicTable<IncidentTask> items={tasks} columns={columns} itemId='id' loading={loading} noItemsMessage='No investigation tasks' />
    <form onSubmit={event => { event.preventDefault(); if (!tasksBlocked && title.trim()) void command({ kind: 'create-task', title }); }}>
      <EuiFormRow label='New task'><EuiFieldText value={title} maxLength={1024} disabled={tasksBlocked} onChange={e => setTitle(e.target.value)} /></EuiFormRow>
      <EuiButton type='submit' disabled={tasksBlocked || !title.trim() || tasks.length >= 100}>Create task</EuiButton>
    </form>
    <EuiSpacer size='l' />
    <EuiTitle size='s'><h2>Analyst notes</h2></EuiTitle>
    <EuiSpacer size='s' />
    <EuiText size='s'>Notes are append-only and visible to authorized incident readers. Do not include restricted finding data or secrets.</EuiText>
    <EuiSpacer size='s' />
    {page?.notes.map(note => <React.Fragment key={note.id}>
      <EuiPanel paddingSize='m' hasShadow={false} hasBorder>
        <EuiText size='s'><strong>{note.actor}</strong> · {note.at} · Revision {note.revision}</EuiText>
        <EuiText><p style={{ whiteSpace: 'pre-wrap' }}>{note.body}</p></EuiText>
      </EuiPanel><EuiSpacer size='s' />
    </React.Fragment>)}
    {page && page.notes.length === 0 && <EuiText size='s'>No delivered notes on this page.</EuiText>}
    <EuiButtonEmpty disabled={loading} onClick={() => { setBefore(0); setReload(value => value + 1); }}>Refresh notes</EuiButtonEmpty>
    <EuiButtonEmpty disabled={loading || !page?.next_before} onClick={() => { if (page?.next_before) setBefore(page.next_before); }}>Older notes</EuiButtonEmpty>
    <form onSubmit={event => { event.preventDefault(); if (!blocked && body.trim()) void command({ kind: 'add-note', body }); }}>
      <EuiFormRow label='Investigation note'><EuiTextArea value={body} maxLength={8192} disabled={blocked} onChange={e => setBody(e.target.value)} /></EuiFormRow>
      <EuiButton type='submit' disabled={blocked || !body.trim()}>Add note</EuiButton>
    </form>
  </>;
}
